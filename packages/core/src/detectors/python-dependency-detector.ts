// ─────────────────────────────────────────────────────────────────────────────
// Python Dependency Detector
//
// Offline checks of Python manifests (requirements*.txt, requirements/*.txt,
// pyproject.toml, Pipfile):
//  - dependency/python-unpinned: Django and other security-critical packages
//    without an exact pin or an upper bound (pyproject.toml / Pipfile are skipped
//    when a lock file sits next to them).
//  - dependency/python-insecure-version: versions on a small static list of
//    end-of-life or known-vulnerable releases.
// No network access and no vulnerability database: the list below is static.
// Line based (no TOML parser, by design); tables and arrays are tracked by hand.
// ─────────────────────────────────────────────────────────────────────────────

import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { CATEGORY_PREFIX, createFindingId, isPythonRequirementsFile } from "@talaljaber/vibesafe-shared";
import { sanitizeEvidence } from "./utils/sanitize-evidence.js";

const UNPINNED_RULE = "dependency/python-unpinned";
const INSECURE_RULE = "dependency/python-insecure-version";

/** Packages whose silent upgrades or downgrades matter most for security. */
const CRITICAL_PACKAGES = new Set([
  "django",
  "djangorestframework",
  "djangorestframework-simplejwt",
  "django-allauth",
  "django-cors-headers",
  "pyjwt",
  "cryptography",
]);

interface InsecureEntry {
  name: string;
  /** Versions strictly below this are flagged; undefined flags every version. */
  below?: number[] | undefined;
  reason: string;
}

/**
 * Known end-of-life or insecure versions.
 *
 * Written 2026-10-29. Kept deliberately short and conservative: only releases that
 * are clearly unsupported or have a well-known fixed vulnerability. Django 4.2, 5.0
 * and 5.1 had also reached end of life by that date but are left out to avoid noise;
 * extend the list when reviewing it against the Django and DRF support timelines.
 */
export const PYTHON_INSECURE_VERSIONS: readonly InsecureEntry[] = [
  {
    name: "django",
    below: [4, 2],
    reason:
      "Django releases before 4.2 are end of life and no longer get security fixes (3.2 LTS support ended in April 2024, 4.1 in December 2023).",
  },
  {
    name: "djangorestframework",
    below: [3, 15],
    reason:
      "Django REST Framework releases before 3.15 are no longer maintained and miss later security fixes.",
  },
  {
    name: "pyjwt",
    below: [2, 4],
    reason: "PyJWT before 2.4.0 is vulnerable to algorithm confusion attacks (CVE-2022-29217).",
  },
  {
    name: "pycrypto",
    reason:
      "PyCrypto has been unmaintained since 2013 and has known vulnerabilities (for example CVE-2013-7459). Use pycryptodome or cryptography instead.",
  },
];

const LOCK_FILES = ["poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock"];

type SpecStyle = "pep440" | "poetry" | "pipfile";

interface Requirement {
  name: string;
  specs: string;
  style: SpecStyle;
  line: number;
  evidence: string;
}

interface Bounds {
  /** True when the spec has an exact pin or an upper bound. */
  bounded: boolean;
  /** Highest allowed version (exclusive) when known. */
  upperExclusive?: number[] | undefined;
  /** Highest allowed version (inclusive) when known. */
  upperInclusive?: number[] | undefined;
}

function normalizeName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, "-");
}

function parseVersion(v: string): number[] | undefined {
  const m = /^v?(\d+(?:\.\d+)*)/.exec(v.trim());
  return m?.[1] ? m[1].split(".").map(Number) : undefined;
}

function compareVersions(a: number[], b: number[]): number {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

/** Increments component `index` and drops everything after it: bump([4,2,1], 1) = [4,3]. */
function bump(v: number[], index: number): number[] {
  const out = v.slice(0, index + 1);
  while (out.length <= index) out.push(0);
  out[index] = (out[index] ?? 0) + 1;
  return out;
}

function minVersion(a: number[] | undefined, b: number[]): number[] {
  return a && compareVersions(a, b) <= 0 ? a : b;
}

/** Works out whether a version spec is pinned/bounded and its highest allowed version. */
export function analyzeSpecs(specs: string, style: SpecStyle): Bounds {
  const bounds: Bounds = { bounded: false };
  const text = specs.trim().replace(/^\(|\)$/g, "");
  if (!text || text === "*") return bounds;
  // Poetry "or" constraints are not analysed: assume bounded, check nothing.
  if (text.includes("||")) return { bounded: true };

  for (const raw of text.split(",")) {
    const part = raw.trim();
    if (!part) continue;
    const op = /^(===|==|~=|!=|<=|>=|<|>|\^|~|=)?\s*(.+)$/.exec(part);
    if (!op) continue;
    const operator = op[1] ?? (style === "poetry" ? "==" : "");
    const versionText = op[2] ?? "";
    const version = parseVersion(versionText);
    if (!version) continue;
    const parts = versionText.split(".");

    switch (operator) {
      case "==":
      case "===":
      case "=": {
        bounds.bounded = true;
        const wildcard = parts.indexOf("*");
        if (wildcard > 0) {
          bounds.upperExclusive = minVersion(bounds.upperExclusive, bump(version, wildcard - 1));
        } else {
          bounds.upperInclusive = minVersion(bounds.upperInclusive, version);
        }
        break;
      }
      case "~=":
        bounds.bounded = true;
        bounds.upperExclusive = minVersion(
          bounds.upperExclusive,
          bump(version, Math.max(0, version.length - 2)),
        );
        break;
      case "<":
        bounds.bounded = true;
        bounds.upperExclusive = minVersion(bounds.upperExclusive, version);
        break;
      case "<=":
        bounds.bounded = true;
        bounds.upperInclusive = minVersion(bounds.upperInclusive, version);
        break;
      case "^": {
        bounds.bounded = true;
        const firstNonZero = version.findIndex((n) => n !== 0);
        const index = firstNonZero === -1 ? version.length - 1 : firstNonZero;
        bounds.upperExclusive = minVersion(bounds.upperExclusive, bump(version, index));
        break;
      }
      case "~":
        bounds.bounded = true;
        bounds.upperExclusive = minVersion(
          bounds.upperExclusive,
          bump(version, version.length > 1 ? 1 : 0),
        );
        break;
      default:
        // >=, >, != (and a bare version outside Poetry) leave the top open.
        break;
    }
  }
  return bounds;
}

/** True when every version the spec allows is below `limit`. */
function allBelow(bounds: Bounds, limit: number[]): boolean {
  if (bounds.upperExclusive && compareVersions(bounds.upperExclusive, limit) <= 0) return true;
  if (bounds.upperInclusive && compareVersions(bounds.upperInclusive, limit) < 0) return true;
  return false;
}

/** Parses a PEP 508 requirement string ("Django[argon2]>=4.2,<5; python_version>'3.8'"). */
function parsePep508(text: string): { name: string; specs: string } | null {
  const req = text.split(";")[0]!.trim();
  if (!req || req.includes("://") || /\s@\s/.test(req)) return null;
  const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$/.exec(req);
  if (!m?.[1]) return null;
  return { name: normalizeName(m[1]), specs: (m[2] ?? "").trim() };
}

function parseRequirementsTxt(content: string): Requirement[] {
  const out: Requirement[] = [];
  const lines = content.split("\n").map((l) => l.replace(/\r$/, ""));
  for (let i = 0; i < lines.length; i++) {
    const start = i;
    let text = lines[i]!;
    while (text.endsWith("\\") && i + 1 < lines.length) {
      text = text.slice(0, -1) + " " + lines[++i]!;
    }
    const code = text
      .replace(/(^|\s)#.*$/, "")
      .replace(/\s--?[\w-]+(?:[= ]\S+)?/g, "")
      .trim();
    if (!code || code.startsWith("-")) continue;
    const req = parsePep508(code);
    if (req) {
      out.push({ ...req, style: "pep440", line: start + 1, evidence: lines[start]!.trim() });
    }
  }
  return out;
}

/** String literals in a TOML line, with what remains outside them. */
function tomlStrings(line: string): { strings: string[]; rest: string } {
  const strings: string[] = [];
  const rest = line.replace(/"((?:[^"\\]|\\.)*)"|'([^']*)'/g, (_m, dq?: string, sq?: string) => {
    strings.push(dq ?? sq ?? "");
    return '""';
  });
  return { strings, rest: rest.replace(/#.*$/, "") };
}

/** Tables whose arrays hold PEP 508 strings, and which keys inside them do. */
function isPep508ArrayKey(section: string, key: string): boolean {
  if (section === "project") return key === "dependencies";
  if (section === "project.optional-dependencies" || section === "dependency-groups") return true;
  if (section === "tool.uv") return key === "dev-dependencies";
  return section === "tool.pdm.dev-dependencies";
}

/** Tables of `name = "spec"` / `name = { version = "spec" }` entries. */
function tableStyle(section: string, file: "pyproject" | "pipfile"): SpecStyle | null {
  if (file === "pipfile") {
    return section === "packages" || section === "dev-packages" ? "pipfile" : null;
  }
  return /^tool\.poetry\.(?:dependencies|dev-dependencies|group\.[^.]+\.dependencies)$/.test(
    section,
  )
    ? "poetry"
    : null;
}

function parseToml(content: string, file: "pyproject" | "pipfile"): Requirement[] {
  const out: Requirement[] = [];
  const lines = content.split("\n").map((l) => l.replace(/\r$/, ""));
  let section = "";
  let inArray = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const { strings, rest } = tomlStrings(line);

    if (inArray) {
      for (const s of strings) {
        const req = parsePep508(s);
        if (req) out.push({ ...req, style: "pep440", line: i + 1, evidence: line.trim() });
      }
      if (rest.includes("]")) inArray = false;
      continue;
    }

    const header = /^\s*\[\[?\s*([^\]]+?)\s*\]\]?\s*$/.exec(rest);
    if (header) {
      section = header[1]!.replace(/["']/g, "");
      continue;
    }

    // Bare key (`django = ...`) or quoted key (`"django-cors-headers" = ...`, now `""` in rest).
    const kv = /^\s*(?:("")|([\w.-]+))\s*=\s*(.*)$/.exec(rest);
    if (!kv) continue;
    const offset = kv[1] ? 1 : 0;
    const key = kv[1] ? (strings[0] ?? "") : (kv[2] ?? "");
    const value = kv[3] ?? "";

    if (file === "pyproject" && value.startsWith("[") && isPep508ArrayKey(section, key)) {
      for (const s of strings.slice(offset)) {
        const req = parsePep508(s);
        if (req) out.push({ ...req, style: "pep440", line: i + 1, evidence: line.trim() });
      }
      if (!value.includes("]")) inArray = true;
      continue;
    }

    const style = tableStyle(section, file);
    if (!style || !key || normalizeName(key) === "python") continue;
    // `name = "spec"` or `name = { version = "spec", ... }`; git/path/url sources have no version.
    let spec: string | undefined;
    if (value.startsWith('""')) spec = strings[offset];
    else if (value.startsWith("{")) {
      const inline = /\bversion\s*=\s*""/.exec(value);
      if (inline) {
        const before = value.slice(0, inline.index).match(/""/g)?.length ?? 0;
        spec = strings[offset + before];
      }
    }
    if (spec === undefined) continue;
    out.push({ name: normalizeName(key), specs: spec, style, line: i + 1, evidence: line.trim() });
  }
  return out;
}

function dirOf(filePath: string): string {
  const normalized = filePath.replace(/\\/g, "/");
  const slash = normalized.lastIndexOf("/");
  return slash === -1 ? "" : normalized.slice(0, slash + 1);
}

export class PythonDependencyDetector implements Detector {
  id = "python-dependency-detector";
  name = "Python Dependency Detection";
  category = "dependency" as const;
  description =
    "Detects unpinned security-critical Python packages and end-of-life or insecure versions in requirements files, pyproject.toml and Pipfile (offline).";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const filePath of context.files) {
      const base = filePath.replace(/\\/g, "/").split("/").pop() ?? "";
      const kind = isPythonRequirementsFile(filePath)
        ? "requirements"
        : base === "pyproject.toml"
          ? "pyproject"
          : base === "Pipfile"
            ? "pipfile"
            : null;
      if (!kind) continue;

      let content: string;
      try {
        content = await context.readFile(filePath);
      } catch {
        continue;
      }
      if (!content) continue;

      const requirements =
        kind === "requirements" ? parseRequirementsTxt(content) : parseToml(content, kind);
      const locked = kind !== "requirements" && (await this.hasLockFile(context, filePath));

      for (const req of requirements) {
        const bounds = analyzeSpecs(req.specs, req.style);
        const insecure = PYTHON_INSECURE_VERSIONS.find(
          (e) => e.name === req.name && (!e.below || allBelow(bounds, e.below)),
        );
        if (insecure) {
          findings.push(this.insecureFinding(filePath, req, insecure));
        } else if (!locked && !bounds.bounded && CRITICAL_PACKAGES.has(req.name)) {
          findings.push(this.unpinnedFinding(filePath, req));
        }
      }
    }
    return findings;
  }

  private async hasLockFile(context: ScanContext, filePath: string): Promise<boolean> {
    const dir = dirOf(filePath);
    for (const lock of LOCK_FILES) {
      const lockPath = dir + lock;
      if (context.files.includes(lockPath)) return true;
      try {
        if ((await context.readFile(lockPath)).trim()) return true;
      } catch {
        // missing lock file
      }
    }
    return false;
  }

  private unpinnedFinding(filePath: string, req: Requirement): Finding {
    return {
      id: createFindingId(CATEGORY_PREFIX.dependency, UNPINNED_RULE, filePath, req.line, req.name),
      ruleId: UNPINNED_RULE,
      title: `Unpinned security-critical package: ${req.name}`,
      severity: "low",
      category: "dependency",
      deployBlocking: false,
      confidence: "medium",
      file: filePath,
      line: req.line,
      evidence: sanitizeEvidence(req.evidence),
      plainEnglishProblem: `${req.name} has no exact version or upper limit, so every install can pull a different (possibly brand new or breaking) release.`,
      whyItMatters:
        "Deploys stop being reproducible: a new major release can change security defaults or break login and permissions, and a compromised release would be installed automatically.",
      fixSteps: [
        `Pin ${req.name} to the version you tested, for example ${req.name}==X.Y.Z, or at least add an upper bound (${req.name}>=X.Y,<X+1).`,
        "Use pip-tools, Poetry or uv to generate a lock file and update it on purpose.",
      ],
      autoFixAvailable: false,
      aiFixPrompt: `Please pin ${req.name} in my Python requirements to the version currently installed (or a safe range with an upper bound) and suggest a lock-file workflow for future updates.`,
    };
  }

  private insecureFinding(filePath: string, req: Requirement, entry: InsecureEntry): Finding {
    return {
      id: createFindingId(CATEGORY_PREFIX.dependency, INSECURE_RULE, filePath, req.line, req.name),
      ruleId: INSECURE_RULE,
      title: `End-of-life or insecure version of ${req.name}`,
      severity: "medium",
      category: "dependency",
      deployBlocking: false,
      confidence: "medium",
      file: filePath,
      line: req.line,
      evidence: sanitizeEvidence(req.evidence),
      plainEnglishProblem: entry.reason,
      whyItMatters:
        "Security fixes are no longer released for these versions, so known vulnerabilities stay open in your deployed app.",
      fixSteps: entry.below
        ? [
            `Upgrade ${req.name} to ${entry.below.join(".")} or newer (preferably the latest supported release).`,
            "Run your tests after the upgrade and read the release notes for breaking changes.",
          ]
        : [
            `Replace ${req.name} with a maintained alternative.`,
            "Run your tests after the change.",
          ],
      autoFixAvailable: false,
      aiFixPrompt: entry.below
        ? `Please upgrade ${req.name} in my Python dependencies to a supported release (${entry.below.join(".")} or newer) and fix any breaking changes in my code.`
        : `Please replace ${req.name} in my Python project with a maintained alternative and update the code that uses it.`,
    };
  }
}
