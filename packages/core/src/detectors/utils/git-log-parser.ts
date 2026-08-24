import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

/** A single line added in a commit's diff, with enough context to trace it back. */
export interface HistoricalHunk {
  sha: string;
  author: string;
  date: string;
  subject: string;
  file: string;
  addedLines: { line: string; index: number }[];
}

const MAX_BUFFER_BYTES = 64 * 1024 * 1024; // 64MB, history diffs can get large
const DEFAULT_MAX_COMMITS = 500;

// Node's child_process refuses to pass argv containing an embedded NUL byte
// (git's usual %x00 trick), so we use the ASCII "record separator" and
// "unit separator" control characters instead. Neither can appear in diff
// content for text files, and they're distinctive enough not to collide
// with commit message text.
const HEADER_MARKER = "\x1eVIBESAFE-COMMIT\x1e";
const FIELD_SEP = "\x1f";

/**
 * Returns true if `rootPath` looks like a git repository (has a .git directory).
 * Doesn't shell out, just checks the filesystem so we can no-op cheaply.
 */
export function looksLikeGitRepo(rootPath: string): boolean {
  try {
    return fs.existsSync(path.join(rootPath, ".git"));
  } catch {
    return false;
  }
}

/**
 * Confirms the `git` binary is actually runnable on this machine.
 * Never throws, resolves false on any failure (missing binary, PATH issues, etc).
 */
export function isGitAvailable(): Promise<boolean> {
  return new Promise((resolve) => {
    execFile("git", ["--version"], { timeout: 5000 }, (error) => {
      resolve(!error);
    });
  });
}

/**
 * Runs `git log -p` over the repo at `cwd` and parses it into per-file,
 * per-commit hunks of added lines only.
 *
 * We only look at added ("+") lines: a secret that appears on a "-" line was
 * necessarily added in some earlier commit's "+" line, so scanning additions
 * alone gives full history coverage without double-counting.
 *
 * Resolves to [] (never rejects) if git fails for any reason, a forensics
 * detector must never crash a scan.
 */
export async function getHistoricalAddedLines(
  cwd: string,
  maxCommits: number = DEFAULT_MAX_COMMITS,
): Promise<HistoricalHunk[]> {
  const args = [
    "log",
    "-p",
    "--all",
    "--no-color",
    "--no-merges",
    `--max-count=${maxCommits}`,
    `--format=${HEADER_MARKER}%H${FIELD_SEP}%an${FIELD_SEP}%aI${FIELD_SEP}%s`,
    "--diff-filter=AM",
  ];

  let output: string;
  try {
    output = await runGitLog(cwd, args);
  } catch {
    return [];
  }

  return parseGitLogOutput(output);
}

function runGitLog(cwd: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(
      "git",
      args,
      { cwd, maxBuffer: MAX_BUFFER_BYTES, windowsHide: true },
      (error, stdout) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(stdout);
      },
    );
  });
}

/**
 * Parses the raw `git log -p` output into a flat list of hunks, one per
 * (commit, file) pair that had added lines.
 */
export function parseGitLogOutput(output: string): HistoricalHunk[] {
  const hunks: HistoricalHunk[] = [];
  if (!output) return hunks;

  // Normalize CRLF so line-based parsing behaves the same on Windows.
  const normalized = output.replace(/\r\n/g, "\n");
  const lines = normalized.split("\n");

  let currentSha = "";
  let currentAuthor = "";
  let currentDate = "";
  let currentSubject = "";
  let currentFile = "";
  let currentAdded: { line: string; index: number }[] = [];
  let addedLineCounter = 0;

  const flushFile = () => {
    if (currentFile && currentAdded.length > 0) {
      hunks.push({
        sha: currentSha,
        author: currentAuthor,
        date: currentDate,
        subject: currentSubject,
        file: currentFile,
        addedLines: currentAdded,
      });
    }
    currentAdded = [];
  };

  for (const rawLine of lines) {
    // Commit header line, marked line starting with our NUL-prefixed marker.
    if (rawLine.startsWith(HEADER_MARKER)) {
      flushFile();
      currentFile = "";
      addedLineCounter = 0;

      const headerBody = rawLine.slice(HEADER_MARKER.length);
      const parts = headerBody.split(FIELD_SEP);
      currentSha = parts[0] ?? "";
      currentAuthor = parts[1] ?? "";
      currentDate = parts[2] ?? "";
      currentSubject = parts[3] ?? "";
      continue;
    }

    // New file within the current commit's diff.
    if (rawLine.startsWith("diff --git ")) {
      flushFile();
      addedLineCounter = 0;

      // "diff --git a/path b/path", use the b/ side (post-change path).
      const match = /^diff --git a\/(.+) b\/(.+)$/.exec(rawLine);
      currentFile = match?.[2] ?? "";
      continue;
    }

    // Added line, excluding the "+++ b/path" file header.
    if (rawLine.startsWith("+") && !rawLine.startsWith("+++")) {
      addedLineCounter++;
      currentAdded.push({ line: rawLine.slice(1), index: addedLineCounter });
      continue;
    }
  }

  flushFile();

  return hunks;
}
