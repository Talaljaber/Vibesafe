import path from "path";
import chalk from "chalk";
import { ScannerPipeline, createDefaultRegistry, createDefaultFixRegistry } from "@vibesafe/core";
import { select } from "@inquirer/prompts";
import type { Finding, FixPreview, ScanResult } from "@vibesafe/shared";
import { buildScanOptions, type ScanFlagOptions } from "./scan-options.js";

/**
 * Scan flags (deep, includeTests, --no-config, --trust-config) are used for the wizard's own
 * scan and its final rescan; unset flags fall back to the `.vibesafe.config.*` values.
 */
export interface WizardOptions extends ScanFlagOptions {
  /** Reuse an existing scan instead of scanning again (used by `scan -i`). */
  initialResult?: ScanResult | undefined;
}

export interface WizardSummary {
  applied: number;
  skipped: number;
  failed: number;
  quit: boolean;
  scoreBefore: number;
  scoreAfter: number;
}

function isPromptAbort(err: unknown): boolean {
  return err instanceof Error && err.name === "ExitPromptError";
}

/**
 * Strips ANSI/OSC escape sequences and control characters from untrusted text
 * (file contents, names) so it cannot rewrite the terminal. Keeps \n and \t.
 */
export function sanitizeTerminal(text: string): string {
  return (
    text
      // eslint-disable-next-line no-control-regex
      .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, "")
      // eslint-disable-next-line no-control-regex
      .replace(/\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)?/g, "")
      // eslint-disable-next-line no-control-regex
      .replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, "")
  );
}

function location(f: Finding): string {
  if (!f.file) return "(project-wide)";
  return sanitizeTerminal(f.line ? `${f.file}:${f.line}` : f.file);
}

function printPreview(preview: FixPreview): void {
  console.log(chalk.white(`\n${sanitizeTerminal(preview.description)}`));
  for (const f of preview.filesToCreate) console.log(chalk.green(`  + ${sanitizeTerminal(f)}`));
  for (const f of preview.filesToModify) console.log(chalk.yellow(`  ~ ${sanitizeTerminal(f)}`));
  if (preview.diff) {
    console.log(
      sanitizeTerminal(preview.diff)
        .split("\n")
        .map((line) => {
          if (line.startsWith("+")) return chalk.green(line);
          if (line.startsWith("-")) return chalk.red(line);
          return chalk.gray(line);
        })
        .join("\n"),
    );
  }
}

type Choice = "apply" | "skip" | "quit";

async function ask(canApply: boolean): Promise<Choice> {
  const choices = [
    ...(canApply ? [{ name: "Apply this fix", value: "apply" as const }] : []),
    { name: "Skip", value: "skip" as const },
    { name: "Quit", value: "quit" as const },
  ];
  try {
    return await select<Choice>({ message: "What would you like to do?", choices });
  } catch (err) {
    if (isPromptAbort(err)) return "quit";
    throw err;
  }
}

/**
 * Walks the repair plan in priority order, letting the user apply, skip or quit
 * on each finding. Returns undefined when it cannot run (no TTY).
 */
export async function runFixWizard(
  targetDir: string,
  options: WizardOptions = {},
): Promise<WizardSummary | undefined> {
  if (!process.stdin.isTTY) {
    console.error(
      chalk.red(
        "\n❌ The interactive fix wizard needs an interactive terminal. Run `vibesafe scan` and `vibesafe fix <id> --yes` instead.",
      ),
    );
    process.exitCode = 1;
    return undefined;
  }

  const rootPath = path.resolve(process.cwd(), targetDir);
  const pipeline = new ScannerPipeline(createDefaultRegistry());
  const scanOpts = buildScanOptions(rootPath, options);

  let result = options.initialResult;
  if (!result) {
    console.log(chalk.gray(`Scanning ${rootPath}...`));
    result = await pipeline.scan(scanOpts);
    for (const w of result.warnings ?? []) console.log(chalk.yellow(`⚠️  ${sanitizeTerminal(w)}`));
  }

  const byId = new Map(result.findings.map((f) => [f.id, f]));
  const steps = result.repairPlan.steps.filter((s) => byId.has(s.findingId));
  const scoreBefore = result.score;
  const summary: WizardSummary = {
    applied: 0,
    skipped: 0,
    failed: 0,
    quit: false,
    scoreBefore,
    scoreAfter: scoreBefore,
  };

  if (steps.length === 0) {
    console.log(chalk.green("\n✅ Nothing to fix. Your project has no findings."));
    return summary;
  }

  const fixRegistry = createDefaultFixRegistry();
  console.log(chalk.cyan.bold(`\n🧙 Fix wizard: ${steps.length} finding(s) to review, most important first.`));

  for (const [i, step] of steps.entries()) {
    const finding = byId.get(step.findingId) as Finding;
    console.log(chalk.bold(`\n[${i + 1}/${steps.length}] ${sanitizeTerminal(finding.title)}`));
    console.log(`  Severity: ${finding.severity.toUpperCase()}   Location: ${location(finding)}`);
    console.log(chalk.gray(`  Why it matters: ${sanitizeTerminal(finding.whyItMatters)}`));

    const fixer = finding.autoFixAvailable ? fixRegistry.getFixer(finding.ruleId) : undefined;
    let canApply = false;
    if (fixer) {
      try {
        const preview = await fixer.preview(finding, rootPath);
        printPreview(preview);
        // Fixers report "cannot fix" as an empty preview rather than throwing.
        canApply = preview.filesToModify.length + preview.filesToCreate.length > 0;
      } catch (err) {
        console.log(
          chalk.yellow(`  Could not preview the auto-fix: ${sanitizeTerminal(err instanceof Error ? err.message : String(err))}`),
        );
      }
    }
    if (!canApply) {
      if (finding.fixSteps.length > 0) {
        console.log(chalk.white("\n  How to fix it:"));
        finding.fixSteps.forEach((s, n) => console.log(`    ${n + 1}. ${sanitizeTerminal(s)}`));
      }
      if (finding.aiFixPrompt) {
        console.log(chalk.white("\n  AI fix prompt (copy into Cursor / Claude Code):"));
        console.log(
          chalk.gray(
            sanitizeTerminal(finding.aiFixPrompt)
              .split("\n")
              .map((l) => `    ${l}`)
              .join("\n"),
          ),
        );
      }
    }

    const choice = await ask(canApply);
    if (choice === "quit") {
      summary.quit = true;
      break;
    }
    if (choice === "skip" || !fixer) {
      summary.skipped++;
      continue;
    }
    try {
      const res = await fixer.apply(finding, rootPath);
      if (res.success) {
        summary.applied++;
        console.log(chalk.green(`  ✅ ${sanitizeTerminal(res.message)}`));
      } else {
        summary.failed++;
        console.log(chalk.red(`  ❌ Failed: ${sanitizeTerminal(res.message)}`));
      }
    } catch (err) {
      summary.failed++;
      console.log(chalk.red(`  ❌ Failed: ${err instanceof Error ? err.message : String(err)}`));
    }
  }

  const remaining = steps.length - summary.applied - summary.skipped - summary.failed;
  if (summary.applied > 0) {
    console.log(chalk.gray("\nRescanning..."));
    const after = await pipeline.scan(scanOpts);
    summary.scoreAfter = after.score;
  }

  const delta = summary.scoreAfter - summary.scoreBefore;
  console.log(chalk.cyan.bold("\nSummary"));
  console.log(
    `  Applied: ${summary.applied}   Skipped: ${summary.skipped}   Failed: ${summary.failed}` +
      (summary.quit ? `   Not reviewed: ${remaining}` : ""),
  );
  console.log(`  Score: ${summary.scoreBefore} -> ${summary.scoreAfter} (${delta >= 0 ? "+" : ""}${delta})`);
  return summary;
}
