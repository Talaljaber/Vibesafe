import { execFile, spawn } from "node:child_process";
import { StringDecoder } from "node:string_decoder";

/** A single line added in a commit's diff, with enough context to trace it back. */
export interface HistoricalHunk {
  sha: string;
  author: string;
  date: string;
  subject: string;
  file: string;
  addedLines: { line: string; index: number }[];
}

const DEFAULT_MAX_COMMITS = 500;
const MAX_STDERR_CHARS = 4000;

// Node's child_process refuses to pass argv containing an embedded NUL byte
// (git's usual %x00 trick), so we use the ASCII "record separator" and
// "unit separator" control characters instead. Neither can appear in diff
// content for text files, and they're distinctive enough not to collide
// with commit message text.
const HEADER_MARKER = "\x1eVIBESAFE-COMMIT\x1e";
const FIELD_SEP = "\x1f";

/** Config overrides applied to every git invocation so repo-local config can't run helpers. */
const HARDENED_CONFIG_ARGS = [
  "-c",
  "core.fsmonitor=false",
  "-c",
  "core.pager=cat",
  "-c",
  "diff.external=",
];

/** Builds the environment for git child processes (inherits the current env). */
export function buildGitEnv(base: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  return { ...base, GIT_CONFIG_NOSYSTEM: "1", GIT_TERMINAL_PROMPT: "0" };
}

/** Builds the argument list for the history scan (`git log -p` with hardened config). */
export function buildGitLogArgs(maxCommits: number = DEFAULT_MAX_COMMITS): string[] {
  return [
    ...HARDENED_CONFIG_ARGS,
    "log",
    "-p",
    "--no-textconv",
    "--no-ext-diff",
    "--all",
    "--no-color",
    "--no-merges",
    // Paths relative to cwd, and only changes under cwd (matters in subdirectories).
    "--relative",
    `--max-count=${maxCommits}`,
    `--format=${HEADER_MARKER}%H${FIELD_SEP}%an${FIELD_SEP}%aI${FIELD_SEP}%s`,
    "--diff-filter=AM",
  ];
}

/**
 * Timeout for the quick git probes below. Spawning git can take several seconds on a
 * loaded machine (CI runners, antivirus scanning on Windows); a short timeout made a
 * deep scan silently skip history there.
 */
const GIT_PROBE_TIMEOUT_MS = 30_000;

/**
 * Confirms the `git` binary is actually runnable on this machine.
 * Never throws, resolves false on any failure (missing binary, PATH issues, etc).
 */
export function isGitAvailable(): Promise<boolean> {
  return new Promise((resolve) => {
    execFile(
      "git",
      ["--version"],
      { timeout: GIT_PROBE_TIMEOUT_MS, windowsHide: true },
      (error) => {
        resolve(!error);
      },
    );
  });
}

/**
 * Returns the repository top-level directory containing `cwd` (works from any
 * subdirectory), or null if `cwd` is not inside a git work tree.
 */
export function resolveGitRoot(cwd: string): Promise<string | null> {
  return new Promise((resolve) => {
    execFile(
      "git",
      [...HARDENED_CONFIG_ARGS, "rev-parse", "--show-toplevel"],
      { cwd, timeout: GIT_PROBE_TIMEOUT_MS, windowsHide: true, env: buildGitEnv() },
      (error, stdout) => {
        const root = stdout.trim();
        resolve(error || !root ? null : root);
      },
    );
  });
}

/**
 * Streams `git log -p` for the repo containing `cwd` and parses it incrementally
 * into per-file, per-commit hunks of added lines only. Output is never buffered
 * in full, so large histories cannot overflow.
 *
 * We only look at added ("+") lines: a secret that appears on a "-" line was
 * necessarily added in some earlier commit's "+" line, so scanning additions
 * alone gives full history coverage without double-counting.
 *
 * Rejects if git fails; callers decide how to surface the error.
 */
export function getHistoricalAddedLines(
  cwd: string,
  maxCommits: number = DEFAULT_MAX_COMMITS,
): Promise<HistoricalHunk[]> {
  return new Promise((resolve, reject) => {
    const parser = new GitLogParser();
    const decoder = new StringDecoder("utf8");
    let pending = "";
    let stderr = "";

    const child = spawn("git", buildGitLogArgs(maxCommits), {
      cwd,
      env: buildGitEnv(),
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });

    const feed = (text: string) => {
      pending += text;
      let nl = pending.indexOf("\n");
      while (nl !== -1) {
        parser.pushLine(pending.slice(0, nl));
        pending = pending.slice(nl + 1);
        nl = pending.indexOf("\n");
      }
    };

    child.stdout.on("data", (chunk: Buffer) => feed(decoder.write(chunk)));
    child.stderr.on("data", (chunk: Buffer) => {
      if (stderr.length < MAX_STDERR_CHARS) stderr += chunk.toString("utf8");
    });
    child.on("error", (error) => reject(error));
    child.on("close", (code) => {
      feed(decoder.end());
      if (pending) parser.pushLine(pending);
      if (code !== 0) {
        reject(new Error(`git log exited with code ${code}: ${stderr.trim().slice(0, 500)}`));
        return;
      }
      resolve(parser.finish());
    });
  });
}

/** Unquotes a git C-style quoted path (`"a\tb\303\251"`), or returns the input if unquoted. */
export function unquoteGitPath(raw: string): string {
  if (!(raw.length >= 2 && raw.startsWith('"') && raw.endsWith('"'))) return raw;
  const inner = raw.slice(1, -1);
  const bytes: number[] = [];
  const simple: Record<string, number> = { n: 10, t: 9, r: 13, a: 7, b: 8, f: 12, v: 11 };
  for (let i = 0; i < inner.length; i++) {
    const ch = inner[i] as string;
    if (ch !== "\\") {
      bytes.push(...Buffer.from(ch, "utf8"));
      continue;
    }
    const next = inner[i + 1] ?? "";
    const octal = /^[0-7]{3}/.exec(inner.slice(i + 1, i + 4));
    if (octal) {
      bytes.push(parseInt(octal[0], 8));
      i += 3;
    } else if (next in simple) {
      bytes.push(simple[next] as number);
      i += 1;
    } else {
      bytes.push(...Buffer.from(next, "utf8"));
      i += 1;
    }
  }
  return Buffer.from(bytes).toString("utf8");
}

/** Extracts the post-change path from a `+++ ` header body, or "" for /dev/null. */
function pathFromPlusHeader(body: string): string {
  // Git may append a tab after paths containing spaces.
  const trimmed = body.replace(/\t.*$/, "");
  if (trimmed === "/dev/null" || trimmed === '"/dev/null"') return "";
  const unquoted = unquoteGitPath(trimmed);
  return unquoted.startsWith("b/") ? unquoted.slice(2) : unquoted;
}

/** Incremental parser for `git log -p` output produced with `buildGitLogArgs`. */
export class GitLogParser {
  private hunks: HistoricalHunk[] = [];
  private sha = "";
  private author = "";
  private date = "";
  private subject = "";
  private file = "";
  private added: { line: string; index: number }[] = [];
  private addedCounter = 0;
  // Remaining old/new line counts of the current "@@" hunk. While either is
  // positive, lines are hunk content and must not be treated as headers.
  private oldRemaining = 0;
  private newRemaining = 0;

  private flushFile(): void {
    if (this.file && this.added.length > 0) {
      this.hunks.push({
        sha: this.sha,
        author: this.author,
        date: this.date,
        subject: this.subject,
        file: this.file,
        addedLines: this.added,
      });
    }
    this.added = [];
  }

  pushLine(rawLine: string): void {
    const line = rawLine.replace(/\r$/, "");
    // Inside a hunk keep the raw content (a trailing \r is part of the line).
    const hunkLine = rawLine;

    if (this.inHunk()) {
      const first = hunkLine[0];
      if (first === "+") {
        this.newRemaining--;
        this.addedCounter++;
        this.added.push({ line: hunkLine.slice(1), index: this.addedCounter });
        return;
      }
      if (first === "-") {
        this.oldRemaining--;
        return;
      }
      if (first === " ") {
        this.oldRemaining--;
        this.newRemaining--;
        return;
      }
      if (first === "\\") return; // "\ No newline at end of file"
      // Anything else means the counts were off; fall through to header parsing.
      this.oldRemaining = 0;
      this.newRemaining = 0;
    }

    if (line.startsWith(HEADER_MARKER)) {
      this.flushFile();
      this.file = "";
      this.addedCounter = 0;
      const parts = line.slice(HEADER_MARKER.length).split(FIELD_SEP);
      this.sha = parts[0] ?? "";
      this.author = parts[1] ?? "";
      this.date = parts[2] ?? "";
      this.subject = parts[3] ?? "";
      return;
    }

    if (line.startsWith("diff --git ")) {
      this.flushFile();
      this.file = "";
      this.addedCounter = 0;
      return;
    }

    if (line.startsWith("+++ ")) {
      this.file = pathFromPlusHeader(line.slice(4));
      return;
    }

    const hunk = /^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@/.exec(line);
    if (hunk) {
      this.oldRemaining = hunk[1] === undefined ? 1 : parseInt(hunk[1], 10);
      this.newRemaining = hunk[2] === undefined ? 1 : parseInt(hunk[2], 10);
    }
  }

  private inHunk(): boolean {
    return this.oldRemaining > 0 || this.newRemaining > 0;
  }

  finish(): HistoricalHunk[] {
    this.flushFile();
    const result = this.hunks;
    this.hunks = [];
    return result;
  }
}

/**
 * Parses raw `git log -p` output (as produced by `buildGitLogArgs`) into a flat
 * list of hunks, one per (commit, file) pair that had added lines.
 */
export function parseGitLogOutput(output: string): HistoricalHunk[] {
  if (!output) return [];
  const parser = new GitLogParser();
  for (const line of output.split("\n")) {
    parser.pushLine(line);
  }
  return parser.finish();
}
