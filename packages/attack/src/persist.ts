import fs from "node:fs";
import path from "node:path";
import type { AttackRun } from "./types.js";

const SENSITIVE_HEADER =
  /^(cookie|set-cookie|authorization|proxy-authorization|apikey)$|token|secret|key/i;

/** Copy of the run with sensitive request header values redacted (names kept). */
function redactRun(run: AttackRun): AttackRun {
  return {
    ...run,
    groups: run.groups.map((g) => ({
      ...g,
      requests: g.requests.map((r) => {
        if (!r.headers) return r;
        const headers: Record<string, string> = {};
        for (const [k, v] of Object.entries(r.headers)) {
          headers[k] = SENSITIVE_HEADER.test(k) ? "[redacted]" : v;
        }
        return { ...r, headers };
      }),
    })),
  };
}

const RETRY_CODES = new Set(["EPERM", "EBUSY", "EACCES"]);

function renameWithRetry(from: string, to: string): void {
  for (let attempt = 0; ; attempt++) {
    try {
      fs.renameSync(from, to);
      return;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code ?? "";
      if (attempt >= 4 || !RETRY_CODES.has(code)) throw err;
      const until = Date.now() + 25 * (attempt + 1);
      while (Date.now() < until) {
        // short bounded busy wait (sync API)
      }
    }
  }
}

export const VIBESAFE_DIR = ".vibesafe";
export const BASELINE_FILE = "attack-baseline.json";
export const LAST_FILE = "attack-last.json";
export const REPORT_MD_FILE = "attack-report.md";
export const REPORT_HTML_FILE = "attack-report.html";

/** Thrown for problems the CLI must report with exit code 2. */
export class AttackPersistError extends Error {
  readonly exitCode = 2 as const;
  constructor(message: string) {
    super(message);
    this.name = "AttackPersistError";
  }
}

export const BASELINE_EXISTS_MESSAGE =
  "A baseline exists. Use `--retest` to compare against it, or `--new-baseline` to replace it.";
export const NO_BASELINE_MESSAGE = "No baseline found: run `vibesafe attack` first.";

export function vibesafeDir(projectPath: string): string {
  return path.join(projectPath, VIBESAFE_DIR);
}

/** Writes `content` to a temp file next to `file`, then renames it over the target. */
export function atomicWrite(file: string, content: string): void {
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  try {
    fs.writeFileSync(tmp, content, "utf8");
    renameWithRetry(tmp, file);
  } catch (err) {
    try {
      fs.rmSync(tmp, { force: true });
    } catch {
      // best effort cleanup
    }
    throw err;
  }
}

/** Creates `.vibesafe/` and writes its `.gitignore` (containing `*`) first, only if absent. */
export function ensureVibesafeDir(projectPath: string): string {
  const dir = vibesafeDir(projectPath);
  fs.mkdirSync(dir, { recursive: true });
  const ignore = path.join(dir, ".gitignore");
  if (!fs.existsSync(ignore)) atomicWrite(ignore, "*\n");
  return dir;
}

export function baselineExists(projectPath: string): boolean {
  return fs.existsSync(path.join(vibesafeDir(projectPath), BASELINE_FILE));
}

/**
 * Pre-run guard. A plain baseline run refuses when a baseline exists (unless newBaseline), and a
 * retest refuses when there is none. Dry runs are never refused. Throws AttackPersistError.
 */
export function assertCanRun(
  projectPath: string,
  mode: AttackRun["mode"],
  newBaseline?: boolean | undefined,
): void {
  if (mode === "dry-run") return;
  const exists = baselineExists(projectPath);
  if (mode === "baseline" && exists && !newBaseline) {
    throw new AttackPersistError(BASELINE_EXISTS_MESSAGE);
  }
  if (mode === "retest" && !exists) throw new AttackPersistError(NO_BASELINE_MESSAGE);
}

function archiveName(now: Date): string {
  const stamp = now.toISOString().replace(/:/g, "-");
  return `attack-baseline.${stamp}.json`;
}

export interface SaveResult {
  written: string[];
  archived?: string | undefined;
}

/**
 * Persists a finished run. Dry runs write nothing. A baseline run writes the baseline (archiving
 * the previous one when `newBaseline`) and attack-last.json; a retest writes attack-last.json only.
 */
export function saveRun(
  projectPath: string,
  run: AttackRun,
  options: { newBaseline?: boolean | undefined; now?: Date | undefined } = {},
): SaveResult {
  if (run.mode === "dry-run") return { written: [] };
  assertCanRun(projectPath, run.mode, options.newBaseline);
  try {
    return writeRun(projectPath, run, options);
  } catch (err) {
    if (err instanceof AttackPersistError) throw err;
    throw new AttackPersistError(`Cannot write .vibesafe files: ${(err as Error).message}`);
  }
}

function writeRun(
  projectPath: string,
  run: AttackRun,
  options: { newBaseline?: boolean | undefined; now?: Date | undefined },
): SaveResult {
  const dir = ensureVibesafeDir(projectPath);
  const json = `${JSON.stringify(redactRun(run), null, 2)}\n`;
  const written: string[] = [];
  let archived: string | undefined;
  if (run.mode === "baseline") {
    const baseline = path.join(dir, BASELINE_FILE);
    if (fs.existsSync(baseline)) {
      archived = path.join(dir, archiveName(options.now ?? new Date()));
      fs.copyFileSync(baseline, archived);
    }
    atomicWrite(baseline, json);
    written.push(baseline);
  }
  const last = path.join(dir, LAST_FILE);
  atomicWrite(last, json);
  written.push(last);
  return { written, archived };
}

/** Writes the agent (md) or human (html) report atomically and returns its path. */
export function saveReport(projectPath: string, kind: "md" | "html", content: string): string {
  let dir: string;
  try {
    dir = ensureVibesafeDir(projectPath);
  } catch (err) {
    throw new AttackPersistError(`Cannot write .vibesafe files: ${(err as Error).message}`);
  }
  const file = path.join(dir, kind === "md" ? REPORT_MD_FILE : REPORT_HTML_FILE);
  try {
    atomicWrite(file, content);
  } catch (err) {
    throw new AttackPersistError(`Cannot write ${path.basename(file)}: ${(err as Error).message}`);
  }
  return file;
}

/** Loads a saved run, or undefined when the file is absent. Throws AttackPersistError if invalid. */
export function loadSavedRun(
  projectPath: string,
  which: "baseline" | "last" = "last",
): AttackRun | undefined {
  const name = which === "baseline" ? BASELINE_FILE : LAST_FILE;
  const file = path.join(vibesafeDir(projectPath), name);
  let text: string;
  try {
    text = fs.readFileSync(file, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw new AttackPersistError(`Cannot read ${name}: ${(err as Error).message}`);
  }
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    throw new AttackPersistError(`${name} is not valid JSON.`);
  }
  const run = data as Partial<AttackRun> | null;
  if (!run || typeof run !== "object" || run.schemaVersion !== 1) {
    throw new AttackPersistError(`${name} has an unsupported schemaVersion.`);
  }
  if (!Array.isArray(run.results) || !Array.isArray(run.groups)) {
    throw new AttackPersistError(`${name} is malformed (missing results or groups).`);
  }
  for (const g of run.groups) {
    for (const r of g?.requests ?? []) {
      const ok =
        r.method === "GET" &&
        (r.host === "target" || r.host === "supabase") &&
        typeof r.path === "string" &&
        /^\/(?!\/)/.test(r.path);
      if (!ok) throw new AttackPersistError(`${name} contains an invalid request and was refused.`);
    }
  }
  return run as AttackRun;
}
