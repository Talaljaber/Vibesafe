// ─────────────────────────────────────────────────────────────────────────────
// Package Existence Detector (opt-in, online)
//
// Runs only when the caller explicitly sets `config.online === true` (CLI
// `scan --online`, MCP `online: true`, API); config files can never enable it.
//
// AI assistants invent plausible package names and attackers register them
// ("slopsquatting"). For each direct npm and PyPI dependency this asks the public
// registries whether the package exists and how old and used it is. Only package NAMES
// are sent (never versions, paths or contents), and never for popular, workspace,
// private-scope, private-registry, typosquat-flagged or non-registry dependencies.
// Any failure degrades to a scan warning; the offline results stand on their own.
// ─────────────────────────────────────────────────────────────────────────────

import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { isPythonRequirementsFile } from "@talaljaber/vibesafe-shared";
import { makeFinding } from "./utils/finding.js";
import { capFindingsPerRule } from "./utils/infra-common.js";
import { classifySpec } from "./utils/semver.js";
import {
  dirOf,
  findLockfile,
  isValidPackageName,
  manifestFiles,
  parseManifest,
  type LockfileInfo,
} from "./utils/deps-manifest.js";
import {
  isDownloadsShape,
  mapLimit,
  mergeRegistryConfig,
  nonDefaultRegistryNames,
  normalizePypiName,
  npmDownloadsUrl,
  npmLatestUrl,
  npmPackumentUrl,
  parseDownloads,
  parseLatest,
  parseNpmrc,
  parsePackument,
  parsePypi,
  parseYarnrc,
  pypiUrl,
  type FetchLike,
  type RegistryConfig,
} from "./utils/package-registry.js";
import { KNOWN_TYPOSQUATS, POPULAR_PACKAGES } from "./patterns/npm-typosquats.js";
import { lookAlikeTarget, topLookAlikeTarget } from "./typosquat-detector.js";
import { parseRequirementsTxt, parseToml } from "./python-dependency-detector.js";

export const NEW_PACKAGE_DAYS = 30;
export const LOW_WEEKLY_DOWNLOADS = 500;
export const REQUEST_TIMEOUT_MS = 4000;
export const OVERALL_DEADLINE_MS = 10_000;
export const CONCURRENCY = 6;
export const MAX_NPM_NAMES = 250;
export const MAX_PYPI_NAMES = 100;
export const BULK_DOWNLOADS = 128;
export const MAX_LATEST_CHECKS = 150;

const DAY_MS = 86_400_000;
const POPULAR = new Set(POPULAR_PACKAGES);
const TYPOSQUATS = new Set(Object.keys(KNOWN_TYPOSQUATS));
const PYPI_NAME_RE = /^[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?$/;
const ALIAS_RE = /^npm:((?:@[^/@\s]+\/)?[^@\s]+)(?:@.*)?$/;

const NOT_FOUND_PROMPT =
  "One of my dependencies does not exist on the registry, which usually means the name was made up " +
  "or mistyped. Find the correct, established package that provides the functionality my code " +
  "imports from it, replace the dependency and its imports, reinstall to update the lockfile, and " +
  "list what you changed. Do not publish or install any package you cannot verify.";

const VERY_NEW_PROMPT =
  "One of my dependencies was published on the registry very recently and has almost no users, " +
  "which is where typosquats and made-up AI package names end up. Check its publisher and " +
  "repository, replace it with the established package that does the same job if it is not the " +
  "one I meant, pin an exact version, reinstall to update the lockfile, and list what you " +
  "changed. Do not install any package you cannot verify.";

type Ecosystem = "npm" | "PyPI";

interface Candidate {
  ecosystem: Ecosystem;
  /** npm package name, or the PEP 503 normalised PyPI name. */
  name: string;
  /** The name as the finding title shows it. */
  display: string;
  file: string;
  line: number | undefined;
  evidence: string;
  inLockfile: boolean;
}

type Verdict =
  | { kind: "not-found"; removed: boolean }
  | { kind: "new"; created: number; downloads: number | null; releases: number }
  | { kind: "fine" };

type Reply =
  | { kind: "ok"; status: number; json: unknown }
  | { kind: "status"; status: number }
  | { kind: "error"; reason: string };

export class PackageExistenceDetector implements Detector {
  id = "package-existence-detector";
  name = "Online Package Existence Check";
  category = "dependency" as const;
  description =
    "Opt-in (--online): checks that each direct npm and PyPI dependency exists and is not a brand-new, barely used package. This check sends only package names.";

  private readonly fetchImpl: FetchLike | undefined;
  private readonly now: () => number;

  constructor(fetchImpl?: FetchLike, now: () => number = Date.now) {
    this.fetchImpl = fetchImpl;
    this.now = now;
  }

  async detect(context: ScanContext): Promise<Finding[]> {
    if (context.config?.online !== true) return [];
    try {
      return await this.run(context);
    } catch {
      return [];
    }
  }

  private async run(context: ScanContext): Promise<Finding[]> {
    const warn = (message: string): void => context.addWarning?.(message);
    let npm = await this.collectNpm(context, warn);
    let py = await this.collectPyPi(context, warn);
    if (npm.length > MAX_NPM_NAMES) {
      warn(
        `Online package check: only the first ${MAX_NPM_NAMES} npm package names were checked; ${npm.length - MAX_NPM_NAMES} were left out.`,
      );
      npm = npm.slice(0, MAX_NPM_NAMES);
    }
    if (py.length > MAX_PYPI_NAMES) {
      warn(
        `Online package check: only the first ${MAX_PYPI_NAMES} PyPI package names were checked; ${py.length - MAX_PYPI_NAMES} were left out.`,
      );
      py = py.slice(0, MAX_PYPI_NAMES);
    }
    if (npm.length === 0 && py.length === 0) return [];

    const doFetch =
      this.fetchImpl ?? (globalThis.fetch as unknown as FetchLike | undefined) ?? undefined;
    if (!doFetch) {
      warn("Online package check skipped: fetch is not available in this runtime.");
      return [];
    }

    const overall = new AbortController();
    const deadline = setTimeout(() => overall.abort(), OVERALL_DEADLINE_MS);
    const state = { requests: 0, failed: 0 };
    const get = (url: string): Promise<Reply> => this.request(doFetch, url, overall, state);
    const verdicts = new Map<Candidate, Verdict>();
    try {
      await this.checkNpm(npm, get, overall.signal, verdicts, state, warn);
      await this.checkPypi(py, get, overall.signal, verdicts, state);
    } finally {
      clearTimeout(deadline);
    }

    if (state.requests === 0) return [];
    warn(
      `Online package check: looked up ${npm.length} npm and ${py.length} PyPI package name(s) on registry.npmjs.org, api.npmjs.org and pypi.org (the existence check sends names only; the OSV check enabled by the same flag sends names and versions; popular, private-scope and workspace packages were not sent by the existence check).`,
    );
    if (state.failed > 0) {
      warn(
        `Online package check: ${state.failed} lookup(s) failed (timeouts, rate limits or registry errors) and were skipped.`,
      );
    }
    if (overall.signal.aborted) {
      const unchecked = [...npm, ...py].filter((c) => !verdicts.has(c)).length;
      warn(
        `Online package check stopped after ${OVERALL_DEADLINE_MS / 1000}s; ${unchecked} package(s) were not checked.`,
      );
    }

    const findings: Finding[] = [];
    for (const c of [...npm, ...py]) {
      const verdict = verdicts.get(c);
      if (!verdict || verdict.kind === "fine") continue;
      const f = this.finding(c, verdict);
      if (f) findings.push(f);
    }
    return capFindingsPerRule(findings);
  }

  // ── Candidates ─────────────────────────────────────────────────────────────

  private async collectNpm(context: ScanContext, warn: (m: string) => void): Promise<Candidate[]> {
    const out = new Map<string, Candidate>();
    const parsed = [];
    const workspaceNames = new Set<string>();
    for (const file of manifestFiles(context)) {
      try {
        const manifest = parseManifest(file, await context.readFile(file));
        if (!manifest) continue;
        parsed.push(manifest);
        if (typeof manifest.json.name === "string") workspaceNames.add(manifest.json.name);
      } catch {
        continue;
      }
    }

    const configCache = new Map<string, RegistryConfig>();
    const registryConfig = async (dir: string): Promise<RegistryConfig> => {
      const cached = configCache.get(dir);
      if (cached) return cached;
      const at = (name: string): string => (dir ? `${dir}/${name}` : name);
      const read = async (rel: string): Promise<string> => {
        try {
          return await context.readFile(rel);
        } catch {
          return "";
        }
      };
      let config = mergeRegistryConfig(
        parseNpmrc(await read(at(".npmrc"))),
        parseYarnrc(await read(at(".yarnrc.yml"))),
      );
      if (dir !== "") config = mergeRegistryConfig(config, await registryConfig(dirOf(dir)));
      configCache.set(dir, config);
      return config;
    };

    const lockCache = new Map<string, LockfileInfo>();
    const privateNames = new Map<string, Set<string>>();
    const nonDefaultFor = async (lock: LockfileInfo): Promise<Set<string>> => {
      if (!lock.file || lock.state !== "ok") return new Set();
      const cached = privateNames.get(lock.file);
      if (cached) return cached;
      let content = "";
      try {
        content = await context.readFile(lock.file);
      } catch {
        content = "";
      }
      const names = nonDefaultRegistryNames(lock.file, content);
      privateNames.set(lock.file, names);
      return names;
    };

    for (const manifest of parsed) {
      const config = await registryConfig(manifest.dir);
      if (config.defaultIsPrivate) {
        warn(
          `Online package check skipped \`${manifest.file}\`: it installs from a private registry.`,
        );
        continue;
      }
      const lock = await findLockfile(context, manifest.file, lockCache);
      const nonDefault = await nonDefaultFor(lock);
      for (const dep of manifest.deps) {
        const kind = classifySpec(dep.spec);
        let name = dep.name;
        if (kind === "alias") {
          const target = ALIAS_RE.exec(dep.spec.trim());
          if (!target?.[1]) continue;
          name = target[1];
        } else if (kind !== "exact" && kind !== "range" && kind !== "tag") {
          continue;
        }
        if (!isValidPackageName(name)) continue;
        if (workspaceNames.has(name)) continue;
        if (name.startsWith("@") && config.privateScopes.has(name.split("/")[0]!.toLowerCase())) {
          continue;
        }
        if (nonDefault.has(name) || POPULAR.has(name) || TYPOSQUATS.has(name)) continue;
        if (lookAlikeTarget(name) !== undefined || topLookAlikeTarget(name) !== undefined) continue;
        const inLockfile = lock.versions.has(name);
        const existing = out.get(name);
        if (existing) {
          existing.inLockfile = existing.inLockfile || inLockfile;
          continue;
        }
        out.set(name, {
          ecosystem: "npm",
          name,
          display: name,
          file: manifest.file,
          line: dep.line,
          evidence: dep.text ?? `"${dep.name}"`,
          inLockfile,
        });
      }
    }
    return [...out.values()];
  }

  private async collectPyPi(context: ScanContext, warn: (m: string) => void): Promise<Candidate[]> {
    const out = new Map<string, Candidate>();
    for (const file of context.files) {
      const base = file.replace(/\\/g, "/").split("/").pop() ?? "";
      const kind = isPythonRequirementsFile(file)
        ? "requirements"
        : base === "pyproject.toml"
          ? "pyproject"
          : base === "Pipfile"
            ? "pipfile"
            : null;
      if (!kind) continue;
      try {
        const content = await context.readFile(file);
        if (typeof content !== "string" || content === "") continue;
        if (hasCustomPythonIndex(content, kind)) {
          warn(
            `Online package check skipped \`${file}\`: it installs from a custom package index.`,
          );
          continue;
        }
        const reqs =
          kind === "requirements" ? parseRequirementsTxt(content) : parseToml(content, kind);
        for (const req of reqs) {
          const name = normalizePypiName(req.name);
          if (name === "python" || !PYPI_NAME_RE.test(name) || out.has(name)) continue;
          out.set(name, {
            ecosystem: "PyPI",
            name,
            display: writtenName(req.evidence, name),
            file,
            line: req.line,
            evidence: req.evidence,
            inLockfile: false,
          });
        }
      } catch {
        continue;
      }
    }
    return [...out.values()];
  }

  // ── Network ────────────────────────────────────────────────────────────────

  private async request(
    doFetch: FetchLike,
    url: string,
    overall: AbortController,
    state: { requests: number; failed: number },
  ): Promise<Reply> {
    if (overall.signal.aborted) return { kind: "error", reason: "deadline" };
    const controller = new AbortController();
    const onOverall = (): void => controller.abort();
    overall.signal.addEventListener("abort", onOverall, { once: true });
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    const aborted = new Promise<never>((_, reject) => {
      controller.signal.addEventListener("abort", () => reject(new Error("timed out")), {
        once: true,
      });
    });
    aborted.catch(() => undefined);
    state.requests++;
    try {
      const res = await Promise.race([
        doFetch(url, {
          method: "GET",
          headers: { accept: "application/json" },
          signal: controller.signal,
        }),
        aborted,
      ]);
      if (!res.ok) return { kind: "status", status: res.status };
      const json = await Promise.race([res.json(), aborted]);
      return { kind: "ok", status: res.status, json };
    } catch (error) {
      const reason = overall.signal.aborted
        ? "deadline"
        : controller.signal.aborted
          ? "timed out"
          : error instanceof Error
            ? error.message.slice(0, 80)
            : "request failed";
      return { kind: "error", reason };
    } finally {
      clearTimeout(timer);
      overall.signal.removeEventListener("abort", onOverall);
    }
  }

  private async checkNpm(
    npm: Candidate[],
    get: (url: string) => Promise<Reply>,
    signal: AbortSignal,
    verdicts: Map<Candidate, Verdict>,
    state: { requests: number; failed: number },
    warn: (m: string) => void,
  ): Promise<void> {
    if (npm.length === 0) return;
    // Phase A: weekly downloads (unscoped names in bulk, scoped names one by one).
    const unscoped = npm.filter((c) => !c.name.startsWith("@")).map((c) => c.name);
    const tasks: string[][] = [];
    for (let i = 0; i < unscoped.length; i += BULK_DOWNLOADS) {
      tasks.push(unscoped.slice(i, i + BULK_DOWNLOADS));
    }
    for (const c of npm) if (c.name.startsWith("@")) tasks.push([c.name]);
    const downloads = new Map<string, number | null>();
    let phaseFailure: string | undefined;
    const replies = await mapLimit(tasks, CONCURRENCY, signal, async (names) => {
      const reply = await get(npmDownloadsUrl(names));
      return { names, reply };
    });
    for (const r of replies) {
      if (!r) continue;
      const { names, reply } = r;
      if (reply.kind === "ok" && isDownloadsShape(names, reply.json)) {
        for (const [n, d] of parseDownloads(names, reply.json)) downloads.set(n, d);
      } else if (reply.kind === "status" && reply.status === 404) {
        // The downloads API alone never proves a package missing.
        for (const n of names) downloads.set(n, null);
      } else if (!(reply.kind === "error" && reply.reason === "deadline")) {
        phaseFailure ??=
          reply.kind === "ok"
            ? "unexpected response"
            : reply.kind === "status"
              ? `HTTP ${reply.status}`
              : reply.reason;
      }
    }
    if (phaseFailure !== undefined) {
      warn(
        `Online package check (npm) failed: ${phaseFailure}. No existence findings were reported.`,
      );
      return;
    }
    if (signal.aborted) return;

    // Phase B: packument for names with few or unknown downloads.
    const low = npm.filter((c) => {
      const d = downloads.get(c.name);
      return d === null || (d !== undefined && d < LOW_WEEKLY_DOWNLOADS);
    });
    const packument = async (c: Candidate): Promise<void> => {
      const reply = await get(npmPackumentUrl(c.name));
      if (reply.kind === "status" && reply.status === 404) {
        verdicts.set(c, { kind: "not-found", removed: c.inLockfile });
      } else if (reply.kind === "ok") {
        const p = parsePackument(reply.json);
        if (p.unpublished || p.securityHolder)
          verdicts.set(c, { kind: "not-found", removed: true });
        else if (p.created !== undefined) {
          verdicts.set(c, {
            kind: "new",
            created: p.created,
            downloads: downloads.get(c.name) ?? null,
            releases: 0,
          });
        } else verdicts.set(c, { kind: "fine" });
      } else if (!(reply.kind === "error" && reply.reason === "deadline")) {
        state.failed++;
      }
    };
    await mapLimit(low, CONCURRENCY, signal, packument);
    for (const c of npm) {
      const d = downloads.get(c.name);
      if (d !== undefined && d !== null && d >= LOW_WEEKLY_DOWNLOADS && c.name.startsWith("@")) {
        verdicts.set(c, { kind: "fine" });
      }
    }
    if (signal.aborted) return;

    // Phase C: security placeholders keep their traffic, so check /latest for busy unscoped names.
    const busy = npm
      .filter((c) => {
        const d = downloads.get(c.name);
        return (
          !c.name.startsWith("@") && d !== undefined && d !== null && d >= LOW_WEEKLY_DOWNLOADS
        );
      })
      .sort((a, b) => Number(b.inLockfile) - Number(a.inLockfile));
    const checked = busy.slice(0, MAX_LATEST_CHECKS);
    if (busy.length > checked.length) {
      warn(
        `Online package check: ${busy.length - checked.length} busy npm package(s) were not checked for npm security placeholders (limit ${MAX_LATEST_CHECKS}).`,
      );
      for (const c of busy.slice(MAX_LATEST_CHECKS)) verdicts.set(c, { kind: "fine" });
    }
    await mapLimit(checked, CONCURRENCY, signal, async (c) => {
      const reply = await get(npmLatestUrl(c.name));
      if (reply.kind === "ok") {
        verdicts.set(
          c,
          parseLatest(reply.json).securityHolder
            ? { kind: "not-found", removed: true }
            : { kind: "fine" },
        );
      } else if (reply.kind === "status" && reply.status === 404) {
        await packument(c);
      } else if (!(reply.kind === "error" && reply.reason === "deadline")) {
        state.failed++;
      }
    });
  }

  private async checkPypi(
    py: Candidate[],
    get: (url: string) => Promise<Reply>,
    signal: AbortSignal,
    verdicts: Map<Candidate, Verdict>,
    state: { requests: number; failed: number },
  ): Promise<void> {
    await mapLimit(py, CONCURRENCY, signal, async (c) => {
      const reply = await get(pypiUrl(c.name));
      if (reply.kind === "status" && reply.status === 404) {
        verdicts.set(c, { kind: "not-found", removed: false });
      } else if (reply.kind === "ok") {
        const info = parsePypi(reply.json);
        if (!info) state.failed++;
        else if (info.releases === 0) verdicts.set(c, { kind: "not-found", removed: false });
        else if (info.created !== undefined) {
          verdicts.set(c, {
            kind: "new",
            created: info.created,
            downloads: null,
            releases: info.releases,
          });
        } else verdicts.set(c, { kind: "fine" });
      } else if (!(reply.kind === "error" && reply.reason === "deadline")) {
        state.failed++;
      }
    });
  }

  // ── Findings ───────────────────────────────────────────────────────────────

  private finding(c: Candidate, verdict: Exclude<Verdict, { kind: "fine" }>): Finding | undefined {
    const registry = c.ecosystem === "npm" ? "npm" : "PyPI";
    const discriminator = `${c.ecosystem}:${c.name}`;
    const label = `\`${c.display}\``;
    if (verdict.kind === "not-found") {
      const removed = verdict.removed;
      return makeFinding({
        category: "dependency",
        ruleId: "dependency/package-not-found",
        title: removed ? `${label} was removed from npm` : `${label} does not exist on ${registry}`,
        severity: "high",
        confidence: "high",
        file: c.file,
        line: c.line,
        evidence: c.evidence,
        discriminator,
        plainEnglishProblem: removed
          ? `${label} was installed before but is no longer on npm. npm removes packages after malware reports; check your lockfile's version against security advisories and rotate secrets if it ran install scripts.`
          : `${label} is listed in \`${c.file}\` but the ${registry} registry has no package with that name. AI assistants often invent plausible package names; attackers register those names ("slopsquatting") so the next install runs their code.`,
        whyItMatters:
          "The install fails today, and anyone can publish a package under that name tomorrow, after which your next install would run their code on your machine and your CI.",
        fixSteps: [
          "Check the package's real name in the library's own documentation.",
          "Replace or remove the dependency and fix the imports that used it.",
          "Reinstall to refresh the lockfile, and never install a package name you have not verified.",
        ],
        aiFixPrompt: NOT_FOUND_PROMPT,
      });
    }
    const age = this.now() - verdict.created;
    if (age >= NEW_PACKAGE_DAYS * DAY_MS) return undefined;
    if (
      c.ecosystem === "npm"
        ? (verdict.downloads ?? 0) >= LOW_WEEKLY_DOWNLOADS
        : verdict.releases > 3
    ) {
      return undefined;
    }
    const days = Math.max(0, Math.floor(age / DAY_MS));
    const usage =
      c.ecosystem === "npm"
        ? `${verdict.downloads ?? 0} weekly downloads`
        : `${verdict.releases} release${verdict.releases === 1 ? "" : "s"}`;
    return makeFinding({
      category: "dependency",
      ruleId: "dependency/package-very-new",
      title: `${label} is brand new and barely used on ${registry}`,
      severity: "medium",
      confidence: c.ecosystem === "npm" ? "medium" : "low",
      file: c.file,
      line: c.line,
      evidence: c.evidence,
      discriminator,
      plainEnglishProblem: `${label} was first published ${days} day${days === 1 ? "" : "s"} ago and has ${usage}.`,
      whyItMatters:
        "New, unused packages are where typosquats and made-up AI package names end up. A package like this has no track record, so you cannot tell yet whether it is what you meant to install.",
      fixSteps: [
        "Confirm the publisher and the repository link on the registry page.",
        "Prefer the established package that does the same job if this is not the one you meant.",
        "Pin an exact version and review its install scripts before trusting it.",
      ],
      aiFixPrompt: VERY_NEW_PROMPT,
    });
  }
}

/** The name as written on the manifest line (PEP 503 normalisation lowercases it). */
function writtenName(evidence: string, normalized: string): string {
  for (const token of evidence.match(/[A-Za-z0-9][A-Za-z0-9._-]*/g) ?? []) {
    if (normalizePypiName(token) === normalized) return token;
  }
  return normalized;
}

/** A requirements / pyproject / Pipfile that installs from somewhere other than public PyPI. */
function hasCustomPythonIndex(
  content: string,
  kind: "requirements" | "pyproject" | "pipfile",
): boolean {
  if (kind === "requirements") return /^\s*(?:-i|--index-url|--extra-index-url)\b/m.test(content);
  if (
    /^\s*\[\[?\s*(?:tool\.poetry\.source|tool\.uv\.index|tool\.pdm\.source)\s*\]\]?\s*$/m.test(
      content,
    )
  ) {
    return true;
  }
  if (kind !== "pipfile") return false;
  let inSource = false;
  for (const line of content.split(/\r?\n/)) {
    const header = /^\s*\[\[?\s*([^\]]+?)\s*\]\]?\s*(?:#.*)?$/.exec(line);
    if (header) {
      inSource = /^\[\[\s*source\s*\]\]/.test(line.trim());
      continue;
    }
    const url = inSource ? /^\s*url\s*=\s*["']([^"']+)["']/.exec(line) : null;
    if (url && !/^https:\/\/pypi\.org\/simple\/?$/i.test(url[1]!)) return true;
  }
  return false;
}
