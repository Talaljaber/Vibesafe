import path from "path";
import chalk from "chalk";
import { ScannerPipeline, createDefaultRegistry } from "@vibesafe/core";
import { printScanResult } from "../ui/printer.js";
import { confirm } from "@inquirer/prompts";
import cliProgress from "cli-progress";
import { generateHtmlReport } from "../ui/html-reporter.js";
import { formatMarkdownReport } from "../ui/markdown-reporter.js";
import open from "open";
import { pathToFileURL } from "node:url";

export interface ScanOptions {
  interactive?: boolean;
  html?: boolean;
  openReport?: boolean;
  json?: boolean;
  /** "markdown" prints a PR-comment summary as the only stdout output. */
  format?: string;
  deep?: boolean;
  includeTests?: boolean;
}

export async function runScan(targetDir: string, options: ScanOptions = {}) {
  const rootPath = path.resolve(process.cwd(), targetDir);
  const markdown = options.format === "markdown";
  if (options.format !== undefined && !markdown) {
    console.error(`Unknown --format "${options.format}". Supported: markdown.`);
    process.exitCode = 2;
    return;
  }
  const quiet = Boolean(options.json) || markdown;

  if (!quiet) {
    console.log(chalk.cyan(`Ready to scan directory: ${rootPath}`));
  }

  if (options.interactive) {
    const proceed = await confirm({
      message: chalk.magenta.bold("Ready to scan your codebase for security, code mess, and more?"),
      default: true,
    });

    if (!proceed) {
      if (!quiet) console.log(chalk.gray("Scan cancelled."));
      process.exitCode = 0;
      return;
    }
  }

  if (!quiet) {
    console.log(chalk.gray("\nStarting VibeSafe scan...\n"));
  }

  if (options.deep && !quiet) {
    console.log(
      chalk.yellow(
        "Deep scan enabled: also inspecting git history for leaked secrets, this can take longer on large repos.\n",
      ),
    );
  }

  try {
    const registry = createDefaultRegistry();
    const pipeline = new ScannerPipeline(registry);

    // Only draw a progress bar for interactive terminals, never in --json mode.
    const showProgress = !quiet && Boolean(process.stdout.isTTY);
    const progressBar = new cliProgress.SingleBar({
      format: chalk.cyan("{bar}") + " {percentage}% | {value}/{total} | " + chalk.magenta("{message}"),
      barCompleteChar: "█",
      barIncompleteChar: "░",
      hideCursor: true,
    });

    let barStarted = false;
    const onProgress = showProgress
      ? (message: string, current: number, total: number) => {
          if (!barStarted) {
            progressBar.start(total, current, { message });
            barStarted = true;
          } else {
            progressBar.setTotal(total);
            progressBar.update(current, { message });
          }
        }
      : undefined;

    let result;
    try {
      result = await pipeline.scan(
        { rootPath, deep: options.deep ?? false, includeTests: options.includeTests ?? false },
        onProgress,
      );
    } finally {
      if (barStarted) {
        progressBar.stop();
        console.log("");
      }
    }

    if (options.json) {
      console.log(JSON.stringify(result, null, 2));
    } else if (markdown) {
      process.stdout.write(formatMarkdownReport(result));
    } else {
      if (result.errors && result.errors.length > 0) {
        console.log(
          chalk.yellow.bold(
            `\n⚠️  ${result.errors.length} detector(s) failed. Scan may be incomplete.`,
          ),
        );
      }
      if (result.warnings && result.warnings.length > 0) {
        for (const w of result.warnings) console.log(chalk.yellow(`⚠️  ${w}`));
      }
      await printScanResult(result);
    }

    // Generate HTML Report if requested
    if (options.html || options.openReport) {
      const htmlReportPath = await generateHtmlReport(result);
      if (!quiet) {
        console.log(chalk.cyan.bold(`\n📄 Detailed HTML report generated: ${htmlReportPath}`));
      }

      if (options.openReport) {
        try {
          const fileUrl = pathToFileURL(htmlReportPath).href;
          await open(fileUrl);
        } catch {
          if (!quiet) console.log(chalk.gray("Could not automatically open the report in your browser."));
        }
      }
    }

    // CI/CD Integration: exit code 1 if deploy blocker. Set exitCode (instead of
    // process.exit) so piped stdout is fully flushed.
    if (result.deployStatus === "blocker" || result.deployStatus === "danger") {
      if (!quiet) {
        console.log(chalk.red.bold("\n❌ Scan failed: Blocking issues found. Please fix them before deploying."));
      }
      process.exitCode = 1;
    } else {
      if (!quiet) console.log(chalk.green.bold("\n✅ Scan passed! You are clear to deploy."));
      process.exitCode = 0;
    }
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    if (!quiet) console.error(chalk.red.bold(`\n❌ Error during scan: ${message}`));
    else console.error(`Error during scan: ${message}`);
    process.exitCode = 2;
  }
}
