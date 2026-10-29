// ─────────────────────────────────────────────────────────────────────────────
// OSV Detector (opt-in, online)
//
// Runs only when the caller explicitly sets `config.online === true` (CLI
// `scan --online`, MCP `online: true`, API). Config files can never enable it.
//
// It sends package names and versions, and nothing else, to the public OSV API
// (POST https://api.osv.dev/v1/querybatch): exact pins from package.json and every
// version the lockfile resolves. One overall 5 s timeout. Any failure becomes a scan
// warning, never an error, and the offline results stand on their own. Versions the
// offline advisory list already reports are skipped to avoid double reporting.
// ─────────────────────────────────────────────────────────────────────────────

import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { makeFinding } from "./utils/finding.js";
import { classifySpec, formatVersion, parseVersion, satisfies } from "./utils/semver.js";
import {
  findLockfile,
  isValidPackageName,
  manifestFiles,
  parseManifest,
  type LockfileInfo,
} from "./utils/deps-manifest.js";
import { NPM_ADVISORIES } from "./patterns/npm-advisories.js";

export const OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch";
const TIMEOUT_MS = 5_000;
/** OSV accepts up to 1000 queries per batch. */
const BATCH_SIZE = 1000;
const MAX_QUERIES = 3000;
const MAX_IDS_SHOWN = 5;
const OSV_ID_RE = /^[A-Za-z][A-Za-z0-9._:-]{2,63}$/;

type FetchLike = (
  url: string,
  init: { method: string; headers: Record<string, string>; body: string; signal: AbortSignal },
) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

interface Query {
  name: string;
  version: string;
  /** Where to report: the manifest line (direct) or the lockfile entry (transitive). */
  file: string;
  line?: number | undefined;
  evidence: string;
  direct: boolean;
}

const AI_FIX_PROMPT =
  "An online advisory lookup (OSV) reports known vulnerabilities for one of my npm dependencies " +
  "at the version my project installs. Look up the listed advisory ids, upgrade the package to a " +
  "release that fixes them (prefer the same major version), reinstall so the lockfile records it, " +
  "and adapt any code the upgrade breaks. If it is a transitive dependency, upgrade the parent " +
  "package or add an npm `overrides` / `pnpm.overrides` / yarn `resolutions` entry. Run the tests " +
  "afterwards.";

function coveredOffline(name: string, version: string): boolean {
  return NPM_ADVISORIES.some((a) => a.name === name && satisfies(version, a.affected));
}

export class OsvDetector implements Detector {
  id = "osv-detector";
  name = "Online Advisory Lookup (OSV)";
  category = "dependency" as const;
  description =
    "Opt-in (--online): looks up installed npm package versions in the OSV database. Sends only package names and versions.";

  private readonly fetchImpl: FetchLike | undefined;

  constructor(fetchImpl?: FetchLike) {
    this.fetchImpl = fetchImpl;
  }

  async detect(context: ScanContext): Promise<Finding[]> {
    if (context.config?.online !== true) return [];
    let queries: Query[];
    try {
      queries = await this.collect(context);
    } catch {
      return [];
    }
    if (queries.length === 0) return [];

    const doFetch =
      this.fetchImpl ?? (globalThis.fetch as unknown as FetchLike | undefined) ?? undefined;
    if (!doFetch) {
      context.addWarning?.(
        "Online advisory lookup skipped: fetch is not available in this runtime.",
      );
      return [];
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
    const vulnsByQuery: string[][] = [];
    try {
      for (let start = 0; start < queries.length; start += BATCH_SIZE) {
        const batch = queries.slice(start, start + BATCH_SIZE);
        const body = JSON.stringify({
          queries: batch.map((q) => ({
            package: { name: q.name, ecosystem: "npm" },
            version: q.version,
          })),
        });
        const res = await doFetch(OSV_QUERYBATCH_URL, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body,
          signal: controller.signal,
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = (await res.json()) as { results?: unknown };
        if (!json || !Array.isArray(json.results) || json.results.length !== batch.length) {
          throw new Error("unexpected response shape");
        }
        for (const r of json.results as unknown[]) vulnsByQuery.push(idsOf(r));
      }
    } catch (error) {
      const reason = controller.signal.aborted
        ? `timed out after ${TIMEOUT_MS / 1000}s`
        : error instanceof Error
          ? error.message.slice(0, 120)
          : "request failed";
      context.addWarning?.(
        `Online advisory lookup (OSV) failed: ${reason}. Only the offline advisory list was used.`,
      );
      return [];
    } finally {
      clearTimeout(timer);
    }

    context.addWarning?.(
      `Online advisory lookup: sent ${queries.length} package name/version pair(s) to api.osv.dev (no source code or file contents).`,
    );
    const findings: Finding[] = [];
    const seen = new Set<string>();
    queries.forEach((q, i) => {
      const ids = vulnsByQuery[i] ?? [];
      if (ids.length === 0) return;
      const key = `${q.file}\u0000${q.name}\u0000${q.version}`;
      if (seen.has(key)) return;
      seen.add(key);
      findings.push(this.finding(q, ids));
    });
    return findings;
  }

  private async collect(context: ScanContext): Promise<Query[]> {
    const queries: Query[] = [];
    const seen = new Set<string>();
    const lockCache = new Map<string, LockfileInfo>();
    const push = (q: Query): void => {
      const key = `${q.name}@${q.version}`;
      if (seen.has(key) || queries.length >= MAX_QUERIES) return;
      if (!isValidPackageName(q.name) || !parseVersion(q.version)) return;
      if (coveredOffline(q.name, q.version)) return;
      seen.add(key);
      queries.push(q);
    };

    const directNames = new Map<string, Set<string>>();
    for (const file of manifestFiles(context)) {
      const manifest = parseManifest(file, await context.readFile(file));
      if (!manifest) continue;
      const lock = await findLockfile(context, file, lockCache);
      const names = directNames.get(lock.file ?? "") ?? new Set<string>();
      for (const dep of manifest.deps) {
        names.add(dep.name);
        const kind = classifySpec(dep.spec);
        if (kind !== "exact" && kind !== "range") continue;
        const entries = lock.versions.get(dep.name) ?? [];
        const resolved = (entries.find((e) => satisfies(e.version, dep.spec)) ?? entries[0])
          ?.version;
        const pinned = kind === "exact" ? parseVersion(dep.spec) : null;
        const version = resolved ?? (pinned ? formatVersion(pinned) : undefined);
        if (!version) continue;
        push({
          name: dep.name,
          version,
          file,
          line: dep.line,
          evidence: dep.text ?? `"${dep.name}"`,
          direct: true,
        });
      }
      directNames.set(lock.file ?? "", names);
    }
    for (const [lockFile, info] of lockCache) {
      if (info.state !== "ok") continue;
      const direct = directNames.get(lockFile) ?? new Set<string>();
      for (const [name, entries] of info.versions) {
        if (direct.has(name)) continue;
        for (const e of entries)
          push({
            name,
            version: e.version,
            file: lockFile,
            line: e.line,
            evidence: `${name}@${e.version}`,
            direct: false,
          });
      }
    }
    return queries;
  }

  private finding(q: Query, ids: string[]): Finding {
    const shown = ids.slice(0, MAX_IDS_SHOWN).join(", ");
    const more = ids.length > MAX_IDS_SHOWN ? ` and ${ids.length - MAX_IDS_SHOWN} more` : "";
    return makeFinding({
      category: "dependency",
      ruleId: "dependency/osv-advisory",
      title: `${q.name} ${q.version} has ${ids.length} known advisor${ids.length === 1 ? "y" : "ies"} (OSV)`,
      severity: q.direct ? "medium" : "low",
      confidence: "medium",
      file: q.file,
      line: q.line,
      evidence: `${q.evidence} -> ${shown}${more}`,
      discriminator: `${q.name}@${q.version}`,
      plainEnglishProblem: `The OSV database lists ${ids.length} advisor${ids.length === 1 ? "y" : "ies"} (${shown}${more}) for ${q.name} ${q.version}, the version your project ${q.direct ? "uses directly" : "installs as an indirect dependency"}.`,
      whyItMatters:
        "Published advisories are what automated attack tooling targets first. OSV does not say here how severe each one is or whether your code reaches the affected function, so read the advisories and prioritise accordingly.",
      fixSteps: [
        `Open each id on https://osv.dev to see the affected and fixed versions.`,
        q.direct
          ? `Upgrade ${q.name} to a fixed release and reinstall to update the lockfile.`
          : `Find which dependency pulls in ${q.name} (\`npm ls ${q.name}\`) and upgrade it, or force a fixed version with overrides/resolutions.`,
        "Re-run vibesafe scan --online to confirm.",
      ],
      aiFixPrompt: AI_FIX_PROMPT,
    });
  }
}

/** Advisory ids from one querybatch result (`{ vulns: [{ id }] }`), validated. */
function idsOf(result: unknown): string[] {
  if (typeof result !== "object" || result === null) return [];
  const vulns = (result as { vulns?: unknown }).vulns;
  if (!Array.isArray(vulns)) return [];
  const ids: string[] = [];
  for (const v of vulns) {
    const id = typeof v === "object" && v !== null ? (v as { id?: unknown }).id : undefined;
    if (typeof id === "string" && OSV_ID_RE.test(id) && !ids.includes(id)) ids.push(id);
  }
  return ids;
}
