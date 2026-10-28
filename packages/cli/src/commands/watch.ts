import path from "node:path";
import chalk from "chalk";
import chokidar from "chokidar";
import { ScannerPipeline, createDefaultRegistry } from "@vibesafe/core";
import {
  ALWAYS_EXCLUDED_ANYWHERE_DIRS,
  ROOT_ANCHORED_EXCLUDED_DIRS,
  SCANNABLE_EXTENSIONS,
  SCANNABLE_FILENAMES,
  WORKSPACE_PACKAGE_CONTAINERS,
} from "@vibesafe/shared";
import type { Finding } from "@vibesafe/shared";
import { createBatcher } from "../watch/batcher.js";
import { computeDelta, type ResultDelta, type Snapshot } from "../watch/delta.js";

export const DEFAULT_DEBOUNCE_MS = 300;

export interface WatchOptions {
  /** Emit NDJSON events (one JSON object per line) instead of formatted text. */
  json?: boolean;
  includeTests?: boolean;
  debounceMs?: number;
  /** Aborting stops the watcher and resolves runWatch. */
  signal?: AbortSignal;
  /** Output sink (defaults to stdout); used by tests. */
  write?: (line: string) => void;
}

/** Strips C0/C1 control characters (incl. ESC) so untrusted names cannot inject terminal sequences. */
export function stripControl(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/[\x00-\x1f\x7f-\x9f]/g, "");
}

function describe(f: Finding): string {
  const where = f.file ? ` (${stripControl(f.file)}${f.line ? `:${f.line}` : ""})` : "";
  return `[${f.severity}] ${stripControl(f.title)}${where}`;
}

export function formatDelta(delta: ResultDelta, files: string[]): string[] {
  const lines: string[] = [];
  lines.push(chalk.cyan(`Changed: ${files.slice(0, 5).map(stripControl).join(", ")}${files.length > 5 ? `, +${files.length - 5} more` : ""}`));
  for (const f of delta.added) lines.push(chalk.red(`  + new      ${describe(f)}`));
  for (const f of delta.resolved) lines.push(chalk.green(`  - resolved ${describe(f)}`));
  if (delta.added.length === 0 && delta.resolved.length === 0) lines.push(chalk.gray("  no change in findings"));
  const sign = delta.scoreChange > 0 ? "+" : "";
  lines.push(
    `  score ${delta.scoreBefore} -> ${delta.scoreAfter} (${sign}${delta.scoreChange}), status: ${delta.statusAfter}`,
  );
  return lines;
}

/** True when the path is inside a default-excluded directory (node_modules, .git, ...). */
export function isExcludedPath(p: string): boolean {
  const parts = p.split(/[\\/]/);
  if (parts.some((part) => (ALWAYS_EXCLUDED_ANYWHERE_DIRS as readonly string[]).includes(part))) return true;
  // Build-output dirs (dist, build, ...) are only excluded at the project root
  // or at a workspace-package root (packages/*/dist), mirroring FileDiscovery.
  const anchored = ROOT_ANCHORED_EXCLUDED_DIRS as readonly string[];
  if (parts.length > 1 && anchored.includes(parts[0] ?? "")) return true;
  return (
    parts.length > 3 &&
    (WORKSPACE_PACKAGE_CONTAINERS as readonly string[]).includes(parts[0] ?? "") &&
    anchored.includes(parts[2] ?? "")
  );
}

/** True when a change to this path can affect scan results (source, config or project-level files). */
export function isRelevantPath(p: string): boolean {
  const base = p.split("/").pop() ?? p;
  if ((SCANNABLE_FILENAMES as readonly string[]).includes(base)) return true;
  if (base === ".gitignore" || base === "package.json" || /^\.env(\..*)?$|\.env$/.test(base)) return true;
  const dot = base.lastIndexOf(".");
  return dot >= 0 && (SCANNABLE_EXTENSIONS as readonly string[]).includes(base.slice(dot));
}

/**
 * Runs an initial scan, then rescans changed files (debounced) and prints the
 * delta. Resolves once stopped via `options.signal`. In --json mode every
 * output line is one NDJSON event: ready | change | error.
 */
export async function runWatch(targetDir: string, options: WatchOptions = {}): Promise<void> {
  const rootPath = path.resolve(process.cwd(), targetDir);
  const includeTests = options.includeTests ?? false;
  const out = options.write ?? ((line: string) => console.log(line));
  const emit = (event: Record<string, unknown>) => out(JSON.stringify(event));
  const say = (line: string) => {
    if (!options.json) out(line);
  };

  const pipeline = new ScannerPipeline(createDefaultRegistry());

  say(chalk.cyan(`Watching ${rootPath} (Ctrl+C to stop)`));
  say(chalk.gray("Running initial scan..."));

  let snapshot: Snapshot | undefined;
  let stopped = false;
  let finish: () => void = () => {};

  const rescan = async (files: string[]) => {
    if (stopped || !snapshot) return;
    try {
      // Always rescan the whole project: several detectors (middleware auth,
      // error boundaries, frontend exposure, security headers) judge a file
      // using other files, so a partial scan yields false or missed findings.
      // computeDelta then reports only what actually changed.
      if (!files.some(isRelevantPath)) return; // nothing scannable changed
      const findings = (await pipeline.scan({ rootPath, includeTests })).findings;
      if (stopped) return;

      const next: Snapshot = { findings, ...pipeline.calculateScore(findings) };
      const delta = computeDelta(snapshot, next);
      snapshot = next;

      if (options.json) {
        emit({
          type: "change",
          files,
          added: delta.added,
          resolved: delta.resolved,
          scoreBefore: delta.scoreBefore,
          score: delta.scoreAfter,
          scoreChange: delta.scoreChange,
          deployStatus: delta.statusAfter,
          totalFindings: findings.length,
        });
      } else {
        for (const line of formatDelta(delta, files)) out(line);
      }
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      if (options.json) emit({ type: "error", message });
      else console.error(chalk.red(`Rescan failed: ${message}`));
    }
  };

  // Serialise work: batches arriving during the initial scan or a rescan queue behind it.
  let chain: Promise<void> = Promise.resolve();
  const batcher = createBatcher(options.debounceMs ?? DEFAULT_DEBOUNCE_MS, (files) => {
    chain = chain.then(() => rescan(files));
  });

  const watcher = chokidar.watch(rootPath, {
    ignoreInitial: true,
    followSymlinks: false, // match FileDiscovery: never follow symlinks
    ignored: (p: string) => isExcludedPath(path.relative(rootPath, p)),
  });

  const onFsEvent = (absolute: string) => {
    const rel = path.relative(rootPath, absolute).split(path.sep).join("/");
    if (rel === "" || rel.startsWith("..")) return;
    batcher.add(rel);
  };
  watcher.on("add", onFsEvent).on("change", onFsEvent).on("unlink", onFsEvent);
  watcher.on("error", (error) => {
    const message = error instanceof Error ? error.message : String(error);
    if (options.json) emit({ type: "error", message });
    else console.error(chalk.red(`Watcher error: ${message}`));
  });

  // The watcher is live before the initial scan starts, so edits made while it
  // runs are queued instead of lost.
  const watcherReady = new Promise<void>((resolve) => {
    watcher.once("ready", () => resolve());
    watcher.once("error", () => resolve()); // do not hang if the watcher fails to start
  });
  chain = (async () => {
    await watcherReady;
    try {
      const initial = await pipeline.scan({ rootPath, includeTests });
      snapshot = { findings: initial.findings, ...pipeline.calculateScore(initial.findings) };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      if (options.json) emit({ type: "error", message });
      else console.error(chalk.red.bold(`Error during initial scan: ${message}`));
      process.exitCode = 2;
      finish();
      return;
    }
    if (options.json) {
      emit({
        type: "ready",
        projectPath: rootPath,
        score: snapshot.score,
        deployStatus: snapshot.deployStatus,
        totalFindings: snapshot.findings.length,
        findings: snapshot.findings,
      });
    } else {
      say(
        `Initial scan: score ${snapshot.score}, status ${snapshot.deployStatus}, ${snapshot.findings.length} finding(s).`,
      );
      say(chalk.gray("Waiting for changes..."));
    }
  })();

  await new Promise<void>((resolve) => {
    finish = resolve;
    const stop = () => resolve();
    if (options.signal?.aborted) stop();
    else options.signal?.addEventListener("abort", stop, { once: true });
  });

  stopped = true;
  batcher.cancel();
  await watcher.close();
  await chain;
  say(chalk.gray("\nStopped watching."));
}
