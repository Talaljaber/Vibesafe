import path from "path";
import chalk from "chalk";
import { ScannerPipeline, createDefaultRegistry, createDefaultFixRegistry } from "@vibesafe/core";
import type { AutoFixer, Finding, FixPreview, FixResult } from "@vibesafe/shared";
import { buildScanOptions, type ScanFlagOptions } from "./scan-options.js";
import { sanitizeTerminal } from "../ui/sanitize.js";

export interface FixAllCandidate {
  finding: Finding;
  fixer: AutoFixer;
  preview: FixPreview;
}

export interface FixAllOutcome {
  findingId: string;
  ruleId: string;
  file?: string | undefined;
  success: boolean;
  message: string;
}

export type FixAllStatus = "nothing-to-fix" | "cancelled" | "no-tty" | "applied";

export interface FixAllResult {
  status: FixAllStatus;
  /** Fixes that will be (or were) attempted: findings whose fixer has a concrete change to make. */
  candidates: number;
  /** Findings with a registered fixer that cannot safely fix them; never counted as failures. */
  skipped: number;
  outcomes: FixAllOutcome[];
  succeeded: number;
  failed: number;
  scoreBefore: number;
  /** Score after the post-fix rescan; equals scoreBefore when nothing was applied. */
  scoreAfter: number;
}

/**
 * Scan flags (--no-config, --trust-config, ...) apply to both the initial scan and the post-fix
 * rescan, so `.vibesafe.config.*` shapes which findings are offered exactly as it does for `scan`.
 */
export interface FixAllOptions extends ScanFlagOptions {
  /** Skip the confirmation prompt. */
  yes?: boolean | undefined;
  /** Whether an interactive terminal is available. Defaults to process.stdin.isTTY. */
  interactive?: boolean | undefined;
  /** Confirmation prompt; defaults to an inquirer confirm. Return false to cancel. */
  confirm?: ((message: string) => Promise<boolean>) | undefined;
  /** Output sink; defaults to console.log. */
  log?: ((line: string) => void) | undefined;
}

function isPromptAbort(err: unknown): boolean {
  return err instanceof Error && err.name === "ExitPromptError";
}

function location(f: Finding): string {
  return f.file ? ` ${sanitizeTerminal(f.file)}${f.line ? ":" + f.line : ""}` : "";
}

function colorDiff(diff: string): string {
  return diff
    .split("\n")
    .map((line) => {
      if (line.startsWith("+")) return chalk.green(line);
      if (line.startsWith("-")) return chalk.red(line);
      return chalk.gray(line);
    })
    .join("\n");
}

function printPreview(log: (line: string) => void, finding: Finding, preview: FixPreview): void {
  log(chalk.cyan(`\n- ${sanitizeTerminal(finding.title)}${location(finding)}`));
  log(chalk.white(`  ${sanitizeTerminal(preview.description)}`));
  preview.filesToCreate.forEach((f) => log(chalk.green(`  + ${sanitizeTerminal(f)}`)));
  preview.filesToModify.forEach((f) => log(chalk.yellow(`  ~ ${sanitizeTerminal(f)}`)));
  if (preview.diff) log(colorDiff(sanitizeTerminal(preview.diff)));
}

/** CLI wrapper: runs the batch fix and maps the outcome to the process exit code. */
export async function runFixAllCommand(
  targetDir: string,
  options: { yes?: boolean | undefined } & ScanFlagOptions = {},
): Promise<FixAllResult> {
  const result = await runFixAll(path.resolve(process.cwd(), targetDir), options);
  if (result.status === "no-tty" || result.failed > 0) process.exitCode = 1;
  return result;
}

/**
 * Batch auto-fix: scan, preview every finding that has a registered fixer, ask for ONE
 * confirmation, apply each fix (a failing fix never stops the rest), then rescan to report
 * the score before and after. Reusable by other front ends (e.g. a setup wizard).
 */
export async function runFixAll(
  rootPath: string,
  options: FixAllOptions = {},
): Promise<FixAllResult> {
  const log = options.log ?? ((line: string) => console.log(line));
  const interactive = options.interactive ?? Boolean(process.stdin.isTTY);
  const root = path.resolve(rootPath);

  log(chalk.gray(`Scanning ${root} for auto-fixable findings...`));
  const pipeline = new ScannerPipeline(createDefaultRegistry());
  const scanOptions = buildScanOptions(root, options);
  const before = await pipeline.scan(scanOptions);
  for (const w of before.warnings ?? []) log(chalk.yellow(`Warning: ${sanitizeTerminal(w)}`));
  const fixers = createDefaultFixRegistry();

  // Preview every registered fixer up front; a fixer that would change nothing (it explains why in
  // the description) is skipped rather than offered, so the prompt count is honest and skips never fail the run.
  const candidates: FixAllCandidate[] = [];
  const skipped: string[] = [];
  for (const finding of before.findings) {
    if (!finding.autoFixAvailable) continue;
    const fixer = fixers.getFixer(finding.ruleId);
    if (!fixer || !fixer.canFix(finding)) continue;
    try {
      const preview = await fixer.preview(finding, root);
      if (preview.filesToModify.length === 0 && preview.filesToCreate.length === 0) {
        skipped.push(
          `${sanitizeTerminal(finding.ruleId)}${location(finding)}: ${sanitizeTerminal(preview.description)}`,
        );
      } else {
        candidates.push({ finding, fixer, preview });
      }
    } catch (err) {
      skipped.push(
        `${sanitizeTerminal(finding.ruleId)}${location(finding)}: preview unavailable (${sanitizeTerminal((err as Error).message)})`,
      );
    }
  }

  const result: FixAllResult = {
    status: "nothing-to-fix",
    candidates: candidates.length,
    skipped: skipped.length,
    outcomes: [],
    succeeded: 0,
    failed: 0,
    scoreBefore: before.score,
    scoreAfter: before.score,
  };

  const logSkipped = (): void => {
    if (skipped.length === 0) return;
    log(chalk.yellow(`\nSkipped (not auto-fixable): ${skipped.length}`));
    skipped.forEach((s) => log(chalk.yellow(`  - ${s}`)));
  };

  if (candidates.length === 0) {
    log(
      chalk.green("\nNothing to auto-fix. No findings have an automatic fix that can be applied."),
    );
    logSkipped();
    return result;
  }

  log(
    chalk.cyan.bold(
      `\nFix preview: ${candidates.length} fix${candidates.length === 1 ? "" : "es"} available`,
    ),
  );
  for (const { finding, preview } of candidates) printPreview(log, finding, preview);
  logSkipped();

  if (!options.yes) {
    if (!interactive) {
      log(
        chalk.red(
          "\nCannot prompt without an interactive terminal. Re-run with --yes to skip confirmation.",
        ),
      );
      result.status = "no-tty";
      return result;
    }
    const ask =
      options.confirm ??
      (async (message: string) => {
        const { confirm } = await import("@inquirer/prompts");
        return confirm({ message, default: true });
      });
    let proceed: boolean;
    try {
      proceed = await ask(`Apply all ${candidates.length} fixes?`);
    } catch (err) {
      if (isPromptAbort(err)) proceed = false;
      else throw err;
    }
    if (!proceed) {
      log(chalk.gray("Fix cancelled. No files were changed."));
      result.status = "cancelled";
      return result;
    }
  }

  log(chalk.gray("\nApplying fixes..."));
  for (const { finding, fixer } of candidates) {
    let fixResult: FixResult;
    try {
      fixResult = await fixer.apply(finding, root);
    } catch (err) {
      fixResult = {
        success: false,
        filesModified: [],
        filesCreated: [],
        message: "Fix threw an error",
        error: (err as Error).message,
      };
    }
    const message = fixResult.success ? fixResult.message : (fixResult.error ?? fixResult.message);
    result.outcomes.push({
      findingId: finding.id,
      ruleId: finding.ruleId,
      file: finding.file,
      success: fixResult.success,
      message,
    });
    if (fixResult.success) {
      result.succeeded++;
      log(
        chalk.green(
          `  OK   ${finding.ruleId}${location(finding)}: ${sanitizeTerminal(fixResult.message)}`,
        ),
      );
    } else {
      result.failed++;
      log(chalk.red(`  FAIL ${finding.ruleId}${location(finding)}: ${sanitizeTerminal(message)}`));
    }
  }

  result.status = "applied";
  const after = await pipeline.scan(scanOptions);
  result.scoreAfter = after.score;
  log(`\n${result.succeeded} applied, ${result.failed} failed.`);
  log(chalk.bold(`Score: ${before.score} -> ${after.score}`));
  return result;
}
