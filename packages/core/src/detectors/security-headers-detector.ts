import type { Detector, Finding, ScanContext, Severity } from "@talaljaber/vibesafe-shared";
import { CATEGORY_PREFIX, createFindingId, isInfraFile } from "@talaljaber/vibesafe-shared";
import { sanitizeEvidence } from "./utils/sanitize-evidence.js";

const EXPRESS_SOURCE_RE = /\.(?:[cm]?[jt]s|[jt]sx)$/;
const NEXT_CONFIG_RE = /^next\.config\.(?:js|mjs|cjs|ts)$/;
const MIDDLEWARE_RE = /^(?:middleware|proxy)\.(?:js|mjs|cjs|ts)$/;
// Header sources we cannot follow statically: local modules and header helper packages.
const NEXT_INDIRECT_RE =
  /(?:from\s+|require\(\s*|import\(\s*)["'](?:\.{1,2}\/|@\/|~\/|next-secure-headers|next-safe|@next-safe\/)/;
const NEXT_HEADERS_REF_RE =
  /\bheaders\s*:\s*[A-Za-z_$][\w$.]*\s*[,}\n]|\.\.\.\s*[A-Za-z_$][\w$.]*[Hh]eaders/;
const NEXT_HEADERS_LINE_RE = /\basync\s+headers\s*\(|\bheaders\s*[:(]/;

const EXPRESS_IMPORT_RE = /(?:from\s+["']express["']|require\(\s*["']express["']\s*\))/;
const HELMET_IMPORT_RE =
  /(?:from\s+["']helmet["']|require\(\s*["']helmet["']\s*\)|import\(\s*["']helmet["']\s*\))/;
const HELMET_USE_RE = /\.use\(\s*(?:[^()]*,\s*)?(?:helmet|[\w$.]*helmet\w*)\s*(?:\(|\))/i;

interface HeaderCheck {
  label: string;
  patterns: RegExp[];
}

const NEXT_HEADERS: HeaderCheck[] = [
  { label: "Content-Security-Policy", patterns: [/content-security-policy(?!-report-only)/i] },
  {
    label: "X-Frame-Options (or CSP frame-ancestors)",
    patterns: [/x-frame-options/i, /frame-ancestors/i],
  },
  { label: "X-Content-Type-Options", patterns: [/x-content-type-options/i] },
  { label: "Strict-Transport-Security", patterns: [/strict-transport-security/i] },
  { label: "Referrer-Policy", patterns: [/referrer-policy/i] },
];

function normalize(filePath: string): string {
  return filePath.replace(/\\/g, "/");
}

function baseName(filePath: string): string {
  return normalize(filePath).split("/").pop() ?? filePath;
}

function dirName(filePath: string): string {
  const parts = normalize(filePath).split("/");
  parts.pop();
  return parts.join("/");
}

function isTestFile(filePath: string): boolean {
  const normalized = normalize(filePath);
  const name = baseName(normalized);
  return (
    normalized.split("/").includes("__tests__") ||
    normalized.split("/").includes("node_modules") ||
    name.includes(".test.") ||
    name.includes(".spec.")
  );
}

// Blanks out line and block comments while keeping line numbers and string contents.
// Quote characters are tokenized first so a string such as "/api/*" or "https://x" is
// never mistaken for a comment. Known limitation: regex literals are not tokenized.
function stripComments(content: string): string {
  let out = "";
  let i = 0;
  const n = content.length;
  while (i < n) {
    const ch = content[i] as string;
    const next = content[i + 1];
    if (ch === '"' || ch === "'" || ch === "`") {
      let j = i + 1;
      while (j < n && content[j] !== ch) {
        if (content[j] === "\\") j++;
        else if (ch !== "`" && content[j] === "\n") break;
        j++;
      }
      out += content.slice(i, j + 1);
      i = j + 1;
    } else if (ch === "/" && next === "/") {
      let j = i;
      while (j < n && content[j] !== "\n") j++;
      out += " ".repeat(j - i);
      i = j;
    } else if (ch === "/" && next === "*") {
      const close = content.indexOf("*/", i + 2);
      const j = close === -1 ? n : close + 2;
      out += content.slice(i, j).replace(/[^\n]/g, " ");
      i = j;
    } else {
      out += ch;
      i++;
    }
  }
  return out;
}

function packageRoot(filePath: string, packageDirs: Set<string>): string {
  let dir = dirName(filePath);
  for (;;) {
    if (packageDirs.has(dir)) return dir;
    if (dir === "") return "";
    const idx = dir.lastIndexOf("/");
    dir = idx === -1 ? "" : dir.slice(0, idx);
  }
}
export class SecurityHeadersDetector implements Detector {
  id = "security-headers-detector";
  name = "Security Headers Detection";
  category = "security_config" as const;
  description = "Detects Express and Next.js apps that do not set standard HTTP security headers.";

  async detect(context: ScanContext): Promise<Finding[]> {
    return [...(await this.detectExpress(context)), ...(await this.detectNext(context))];
  }

  private async detectExpress(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const apps: { filePath: string; line: number; text: string }[] = [];
    const packageDirs = new Set(
      context.files.filter((f) => baseName(f) === "package.json").map(dirName),
    );
    const helmetRoots = new Set<string>();

    for (const filePath of context.files) {
      // next.config.mts is admitted as an infra file and matches the extension regex,
      // but it is build config, never an Express app.
      if (!EXPRESS_SOURCE_RE.test(filePath) || isTestFile(filePath) || isInfraFile(filePath)) {
        continue;
      }
      const raw = await context.readFile(filePath);
      if (!raw) continue;
      const hasHelmet = raw.includes("helmet");
      if (!hasHelmet && !raw.includes("express")) continue;

      const content = stripComments(raw);
      if (HELMET_IMPORT_RE.test(content) && HELMET_USE_RE.test(content)) {
        helmetRoots.add(packageRoot(filePath, packageDirs));
      }

      if (!EXPRESS_IMPORT_RE.test(content)) continue;
      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i] ?? "";
        if (/(?<![\w.])express\s*\(\s*\)/.test(line)) {
          apps.push({ filePath, line: i + 1, text: line });
          break;
        }
      }
    }

    // Helmet is often applied in a shared bootstrap file, so a helmet use protects every
    // Express app in the same package (nearest package.json), but not other packages.
    for (const app of apps) {
      if (helmetRoots.has(packageRoot(app.filePath, packageDirs))) continue;
      findings.push({
        id: createFindingId(
          CATEGORY_PREFIX.security_config,
          "security_config/missing-helmet",
          app.filePath,
          app.line,
          "express()",
        ),
        ruleId: "security_config/missing-helmet",
        title: "Express app without helmet security headers",
        severity: "medium",
        category: "security_config",
        deployBlocking: false,
        confidence: "medium",
        file: app.filePath,
        line: app.line,
        evidence: sanitizeEvidence(app.text),
        plainEnglishProblem:
          "This Express app does not use helmet, so it sends no standard security headers and advertises itself with the X-Powered-By: Express header.",
        whyItMatters:
          "Without headers like Content-Security-Policy, X-Content-Type-Options and Strict-Transport-Security, browsers do less to protect your users from clickjacking, MIME sniffing and downgrade attacks, and X-Powered-By tells attackers which framework you run.",
        fixSteps: [
          "Install helmet: npm install helmet.",
          'Import it ("import helmet from \\"helmet\\"") and register it early with app.use(helmet()).',
          'Optionally also call app.disable("x-powered-by") (helmet already removes the header).',
        ],
        autoFixAvailable: false,
        aiFixPrompt:
          "Please add the helmet package to this Express app and register app.use(helmet()) before any routes, configuring Content-Security-Policy for the assets this app serves.",
      });
    }

    return findings;
  }

  private async detectNext(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const configs = context.files.filter((f) => NEXT_CONFIG_RE.test(baseName(f)) && !isTestFile(f));

    for (const configPath of configs) {
      const configRaw = await context.readFile(configPath);
      const configDir = dirName(configPath);
      const strippedConfig = stripComments(configRaw);
      const sources: string[] = [strippedConfig];

      // Headers may also be set by middleware or by hosting config next to the app.
      for (const other of context.files) {
        const otherDir = dirName(other);
        const sameApp =
          otherDir === configDir || otherDir === (configDir ? `${configDir}/src` : "src");
        if (!sameApp) continue;
        const name = baseName(other);
        if (MIDDLEWARE_RE.test(name)) {
          sources.push(stripComments(await context.readFile(other)));
        }
      }

      // vercel.json may live at the repo root while next.config is in a sub-app.
      for (const other of context.files) {
        if (baseName(other) !== "vercel.json") continue;
        const otherDir = dirName(other);
        if (otherDir === "" || configDir === otherDir || configDir.startsWith(`${otherDir}/`)) {
          sources.push(stripComments(await context.readFile(other)));
        }
      }

      const combined = sources.join("\n");
      const missing = NEXT_HEADERS.filter((h) => !h.patterns.some((p) => p.test(combined)));
      if (missing.length === 0) continue;

      const noneSet = missing.length === NEXT_HEADERS.length;
      const severity: Severity =
        noneSet || missing.some((h) => h.label === "Content-Security-Policy") ? "medium" : "low";
      const lines = configRaw.split("\n");
      const headersLineIdx = strippedConfig
        .split("\n")
        .findIndex((l) => NEXT_HEADERS_LINE_RE.test(l));
      // Headers may come from an imported module or helper package we cannot inspect.
      const indirect =
        NEXT_INDIRECT_RE.test(strippedConfig) || NEXT_HEADERS_REF_RE.test(strippedConfig);
      const line = headersLineIdx >= 0 ? headersLineIdx + 1 : 1;
      const missingList = missing.map((h) => h.label).join(", ");

      findings.push({
        id: createFindingId(
          CATEGORY_PREFIX.security_config,
          "security_config/missing-security-headers",
          configPath,
          line,
          missingList,
        ),
        ruleId: "security_config/missing-security-headers",
        title: "Next.js app is missing security headers",
        severity,
        category: "security_config",
        deployBlocking: false,
        confidence: indirect ? "low" : "medium",
        file: configPath,
        line,
        evidence: sanitizeEvidence(lines[line - 1] ?? ""),
        plainEnglishProblem: `This Next.js app does not set these security headers in next.config or middleware: ${missingList}.`,
        whyItMatters:
          "Security headers tell browsers to block clickjacking, MIME sniffing, insecure transport and leaky referrers. Next.js does not add them by default, and it also sends X-Powered-By: Next.js unless disabled.",
        fixSteps: [
          'Add an async headers() function to next.config that returns these headers for source "/(.*)".',
          `Add the missing headers: ${missingList}.`,
          "Set poweredByHeader: false in next.config.",
        ],
        autoFixAvailable: false,
        aiFixPrompt: `Please add an async headers() function to this next.config that sets the missing security headers (${missingList}) on all routes, with a sensible Content-Security-Policy for this app.`,
      });
    }

    return findings;
  }
}
