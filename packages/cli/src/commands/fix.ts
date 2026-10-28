import path from "path";
import chalk from "chalk";
import { ScannerPipeline, createDefaultRegistry, createDefaultFixRegistry } from "@vibesafe/core";
import { confirm, select } from "@inquirer/prompts";
import type { Finding } from "@vibesafe/shared";

export interface FixOptions {
  /** Skip confirmation prompts. Requires an exact finding id or a single ruleId match. */
  yes?: boolean | undefined;
}

function describeFinding(f: Finding): string {
  const loc = f.file ? ` ${f.file}${f.line ? ":" + f.line : ""}` : "";
  return `${f.id}${loc}`;
}

function isPromptAbort(err: unknown): boolean {
  return err instanceof Error && err.name === "ExitPromptError";
}

function exitNoTty(): never {
  console.log(
    chalk.red("\n❌ Cannot prompt without an interactive terminal. Re-run with --yes to skip confirmation."),
  );
  process.exit(1);
}

export async function runFix(findingId: string, targetDir: string, options: FixOptions = {}) {
  const yes = options.yes === true;
  const rootPath = path.resolve(process.cwd(), targetDir);

  console.log(chalk.gray(`Scanning ${rootPath} to locate finding ${findingId}...`));

  const registry = createDefaultRegistry();
  const pipeline = new ScannerPipeline(registry);
  const result = await pipeline.scan({ rootPath });

  let finding: Finding | undefined = result.findings.find((f) => f.id === findingId);

  if (!finding) {
    const matches = result.findings.filter((f) => f.ruleId === findingId);
    if (matches.length === 1) {
      finding = matches[0];
    } else if (matches.length > 1) {
      console.log(chalk.yellow(`\n'${findingId}' matches ${matches.length} findings:`));
      matches.forEach((f) => console.log(`  - ${describeFinding(f)}`));
      if (yes) {
        console.log(chalk.red("\n❌ Ambiguous rule with --yes. Re-run with one of the exact finding IDs above."));
        process.exit(1);
      }
      if (!process.stdin.isTTY) {
        console.log(chalk.red("\n❌ Ambiguous rule and no interactive terminal. Re-run with an exact finding ID."));
        process.exit(1);
      }
      try {
        const chosen = await select({
          message: "Which finding do you want to fix?",
          choices: matches.map((f) => ({ name: describeFinding(f), value: f.id })),
        });
        finding = matches.find((f) => f.id === chosen);
      } catch (err) {
        if (isPromptAbort(err)) {
          console.log(chalk.gray("\nFix cancelled."));
          process.exit(1);
        }
        throw err;
      }
    }
  }

  if (!finding) {
    console.log(chalk.red(`\n❌ Could not find an issue with ID or Rule: ${findingId}`));
    process.exit(1);
  }

  if (!finding.autoFixAvailable) {
    console.log(chalk.yellow(`\n⚠️  The finding '${finding.title}' does not have an auto-fix available.`));
    process.exit(1);
  }

  const fixRegistry = createDefaultFixRegistry();
  const fixer = fixRegistry.getFixer(finding.ruleId);

  if (!fixer) {
    console.log(chalk.red(`\n❌ No AutoFixer is registered for rule '${finding.ruleId}'.`));
    process.exit(1);
  }

  console.log(chalk.cyan(`\n🔧 Fix Preview for: ${finding.title}`));
  
  const preview = await fixer.preview(finding, rootPath);
  
  console.log(chalk.white(`\n${preview.description}`));
  if (preview.filesToCreate.length > 0) {
    console.log(chalk.green(`\nFiles to be created:`));
    preview.filesToCreate.forEach(f => console.log(`  + ${f}`));
  }
  if (preview.filesToModify.length > 0) {
    console.log(chalk.yellow(`\nFiles to be modified:`));
    preview.filesToModify.forEach(f => console.log(`  ~ ${f}`));
  }
  if (preview.diff) {
    console.log(chalk.gray(`\nChanges:`));
    console.log(preview.diff.split('\n').map(line => {
      if (line.startsWith('+')) return chalk.green(line);
      if (line.startsWith('-')) return chalk.red(line);
      return chalk.gray(line);
    }).join('\n'));
  }

  let proceed = yes;
  if (!yes) {
    if (!process.stdin.isTTY) exitNoTty();
    try {
      proceed = await confirm({
        message: chalk.magenta.bold("\nAre you sure you want to apply this fix?"),
        default: true,
      });
    } catch (err) {
      if (isPromptAbort(err)) exitNoTty();
      throw err;
    }
  }

  if (!proceed) {
    console.log(chalk.gray("Fix cancelled."));
    process.exit(0);
  }

  console.log(chalk.gray("\nApplying fix..."));
  
  const fixResult = await fixer.apply(finding, rootPath);

  if (fixResult.success) {
    console.log(chalk.green(`\n✅ Success: ${fixResult.message}`));
    
    // Fix verification (rescan)
    console.log(chalk.gray("\nVerifying fix..."));
    const verifyResult = await pipeline.scan({ rootPath });
    const stillExists = verifyResult.findings.some(f => 
      f.ruleId === finding.ruleId && f.file === finding.file && f.line === finding.line
    );

    if (stillExists) {
      console.log(chalk.yellow("⚠️  The fix was applied, but the issue still appears in the scan."));
    } else {
      console.log(chalk.green("✅ Fix verified! The issue is resolved."));
    }
  } else {
    console.log(chalk.red(`\n❌ Failed to apply fix: ${fixResult.message}`));
    if (fixResult.error) console.log(chalk.red(fixResult.error));
  }
}
