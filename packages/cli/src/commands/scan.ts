import path from "path";
import chalk from "chalk";
import { ScannerPipeline, createDefaultRegistry } from "@vibesafe/core";
import { printScanResult } from "../ui/printer.js";
import { confirm } from "@inquirer/prompts";
import cliProgress from "cli-progress";
import { generateHtmlReport } from "../ui/html-reporter.js";
import open from "open";
import { pathToFileURL } from "node:url";
import fs from "node:fs/promises";
import { createRequire } from "node:module";
import { OUTPUT_FORMAT_NAMES, isOutputFormat, renderOutput, type OutputFormat } from "../formatters/index.js";

// Both dist/commands/scan.js and src/commands/scan.ts sit two levels below package.json.
const require = createRequire(import.meta.url);
const { version: CLI_VERSION } = require("../../package.json") as { version: string };

export interface ScanOptions {
  interactive?: boolean;
  html?: boolean;
  openReport?: boolean;
  json?: boolean;
  /** Machine-readable output format (see OUTPUT_FORMATS). Wins over --json. */
  format?: string;
  /** Write the --format/--json output to this file instead of stdout. */
  output?: string;
  deep?: boolean;
  includeTests?: boolean;
}

export async function runScan(targetDir: string, options: ScanOptions = {}) {
  const rootPath = path.resolve(process.cwd(), targetDir);

  let format: OutputFormat | undefined;
  if (options.format !== undefined) {
    if (!isOutputFormat(options.format)) {
      console.error(
        `Error: unknown --format "${options.format}". Supported formats: ${OUTPUT_FORMAT_NAMES.join(", ")}.`,
      );
      process.exitCode = 2;
      return;
    }
    format = options.format;
  } else if (options.json || options.output) {
    format = "json";
  }
  // Machine-readable mode: stdout carries only the report (or nothing, with --output).
  options = { ...options, json: format !== undefined };

  if (!options.json) {
    console.log(chalk.cyan(`Ready to scan directory: ${rootPath}`));
  }

  if (options.interactive) {
    const proceed = await confirm({
      message: chalk.magenta.bold("Ready to scan your codebase for security, code mess, and more?"),
      default: true,
    });

    if (!proceed) {
      if (!options.json) console.log(chalk.gray("Scan cancelled."));
      process.exitCode = 0;
      return;
    }
  }

  if (!options.json) {
    console.log(chalk.gray("\nStarting VibeSafe scan...\n"));
  }

  if (options.deep && !options.json) {
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
    const showProgress = !options.json && Boolean(process.stdout.isTTY);
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

    if (format) {
      const rendered = renderOutput(format, result, { version: CLI_VERSION });
      if (options.output) {
        const outPath = path.resolve(process.cwd(), options.output);
        await fs.mkdir(path.dirname(outPath), { recursive: true });
        await fs.writeFile(outPath, rendered + "\n", "utf-8");
        console.error(`Wrote ${format} report to ${outPath}`);
      } else {
        console.log(rendered);
      }
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
      if (!options.json) {
        console.log(chalk.cyan.bold(`\n📄 Detailed HTML report generated: ${htmlReportPath}`));
      }

      if (options.openReport) {
        try {
          const fileUrl = pathToFileURL(htmlReportPath).href;
          await open(fileUrl);
        } catch {
          if (!options.json) console.log(chalk.gray("Could not automatically open the report in your browser."));
        }
      }
    }

    // CI/CD Integration: exit code 1 if deploy blocker. Set exitCode (instead of
    // process.exit) so piped stdout is fully flushed.
    if (result.deployStatus === "blocker" || result.deployStatus === "danger") {
      if (!options.json) {
        console.log(chalk.red.bold("\n❌ Scan failed: Blocking issues found. Please fix them before deploying."));
      }
      process.exitCode = 1;
    } else {
      if (!options.json) console.log(chalk.green.bold("\n✅ Scan passed! You are clear to deploy."));
      process.exitCode = 0;
    }
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    if (!options.json) console.error(chalk.red.bold(`\n❌ Error during scan: ${message}`));
    else console.error(`Error during scan: ${message}`);
    process.exitCode = 2;
  }
}
