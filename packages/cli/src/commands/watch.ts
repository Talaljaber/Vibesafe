import path from "node:path";
import chalk from "chalk";
import chokidar from "chokidar";
import { FileDiscovery, ScannerPipeline, createDefaultRegistry } from "@vibesafe/core";
import { ALWAYS_EXCLUDED_ANYWHERE_DIRS, ROOT_ANCHORED_EXCLUDED_DIRS } from "@vibesafe/shared";
import type { Finding } from "@vibesafe/shared";
import { createBatcher } from "../watch/batcher.js";
import {
  computeDelta,
  mergeFindings,
  needsFullRescan,
  type ResultDelta,
  type Snapshot,
} from "../watch/delta.js";

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

function describe(f: Finding): string {
  const where = f.file ? ` (${f.file}${f.line ? `:${f.line}` : ""})` : "";
  return `[${f.severity}] ${f.title}${where}`;
}

export function formatDelta(delta: ResultDelta, files: string[]): string[] {
  const lines: string[] = [];
  lines.push(chalk.cyan(`Changed: ${files.slice(0, 5).join(", ")}${files.length > 5 ? `, +${files.length - 5} more` : ""}`));
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
function isExcludedPath(p: string): boolean {
  const parts = p.split(/[\\/]/);
  if (parts.some((part) => (ALWAYS_EXCLUDED_ANYWHERE_DIRS as readonly string[]).includes(part))) return true;
  // Build-output dirs (dist, build, ...) are only excluded at the project root.
  return parts.length > 1 && (ROOT_ANCHORED_EXCLUDED_DIRS as readonly string[]).includes(parts[0] ?? "");
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
  const discovery = new FileDiscovery(rootPath);

  say(chalk.cyan(`Watching ${rootPath} (Ctrl+C to stop)`));
  say(chalk.gray("Running initial scan..."));
  // (the initial scan runs below, once the file watcher is established)

  let snapshot: Snapshot | undefined;
  let stopped = false;
  let finish: () => void = () => {};

  const rescan = async (files: string[]) => {
    if (stopped || !snapshot) return;
    try {
      const present = new Set<string>();
      const gone = new Set<string>();
      const full = needsFullRescan(files);
      if (!full) {
        const discovered = new Set(await discovery.discoverFiles([], { includeTests }));
        const hadFindings = new Set(snapshot.findings.map((f) => f.file));
        for (const f of files) {
          if (discovered.has(f)) present.add(f);
          else if (hadFindings.has(f)) gone.add(f); // deleted or newly ignored
        }
      }

      let findings: Finding[];
      if (full) {
        findings = (await pipeline.scan({ rootPath, includeTests })).findings;
      } else if (present.size === 0 && gone.size === 0) {
        return; // nothing scannable changed (ignored/unsupported files)
      } else {
        const rescanned =
          present.size > 0
            ? (await pipeline.scan({ rootPath, includeTests, targetFiles: [...present] })).findings
            : [];
        findings = mergeFindings(snapshot.findings, [...present, ...gone], rescanned);
      }
      if (stopped) return;

      const next: Snapshot = { findings, ...pipeline.calculateScore(findings) };
      const delta = computeDelta(snapshot, next);      snapshot = next;

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
  const watcherReady = new Promise<void>((resolve) => watcher.once("ready", () => resolve()));
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
