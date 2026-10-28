import path from "path";
import chalk from "chalk";
import { ScannerPipeline, createDefaultRegistry } from "@vibesafe/core";
import { printScanResult } from "../ui/printer.js";
import { confirm } from "@inquirer/prompts";
import cliProgress from "cli-progress";
import { generateHtmlReport } from "../ui/html-reporter.js";
import open from "open";
import { runFixWizard } from "./fix-wizard.js";
import { pathToFileURL } from "node:url";
import fs from "node:fs/promises";
import { createRequire } from "node:module";
import {
  OUTPUT_FORMAT_NAMES,
  isOutputFormat,
  renderOutput,
  type OutputFormat,
} from "../formatters/index.js";
import { buildScanOptions } from "./scan-options.js";
import { sanitizeTerminal } from "../ui/sanitize.js";

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
  /**
   * Write the report to this file instead of stdout (implies --format json when no format is
   * given). Treated as trusted CLI input: parent directories are created, but an existing
   * symlink at the path is refused.
   */
  output?: string;
  deep?: boolean;
  includeTests?: boolean;
  /** commander sets this to false for --no-config. */
  config?: boolean;
  trustConfig?: boolean;
}

// Re-exported for existing importers; the implementation lives in scan-options.ts.
export { buildScanOptions };

export async function runScan(targetDir: string, options: ScanOptions = {}) {
  const rootPath = path.resolve(process.cwd(), targetDir);

  if (options.output !== undefined && options.output.trim() === "") {
    console.error("Error: --output requires a non-empty file path.");
    process.exitCode = 2;
    return;
  }

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
  } else if (options.json || options.output !== undefined) {
    format = "json";
  }
  // Machine-readable mode: stdout carries only the report (or nothing, with --output).
  options = { ...options, json: format !== undefined };

  if (!options.json) {
    console.log(chalk.cyan(`Ready to scan directory: ${rootPath}`));
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
      format:
        chalk.cyan("{bar}") + " {percentage}% | {value}/{total} | " + chalk.magenta("{message}"),
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
      result = await pipeline.scan(buildScanOptions(rootPath, options), onProgress);
    } finally {
      if (barStarted) {
        progressBar.stop();
        console.log("");
      }
    }

    if (format) {
      // Machine mode keeps stdout clean, so surface an incomplete scan on stderr.
      if (result.errors && result.errors.length > 0) {
        console.error(
          `Warning: ${result.errors.length} detector(s) failed. Scan may be incomplete.`,
        );
        for (const e of result.errors) console.error(`  - ${e.detectorName}: ${e.message}`);
      }
      for (const w of result.warnings ?? []) console.error(`Warning: ${sanitizeTerminal(w)}`);
      // Strip any trailing newline (markdown ends with one, JSON does not) so both stdout and the
      // --output file end with exactly one.
      const rendered = renderOutput(format, result, { version: CLI_VERSION }).replace(/\n+$/, "");
      if (options.output !== undefined) {
        const outPath = path.resolve(process.cwd(), options.output);
        try {
          const st = await fs.lstat(outPath).catch(() => undefined);
          if (st?.isSymbolicLink()) throw new Error("refusing to write through a symbolic link");
          await fs.mkdir(path.dirname(outPath), { recursive: true });
          await fs.writeFile(outPath, rendered + "\n", { encoding: "utf-8", flag: "w" });
        } catch (err: unknown) {
          console.error(
            `Error: could not write report to ${outPath}: ${err instanceof Error ? err.message : String(err)}`,
          );
          process.exitCode = 2;
          return;
        }
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
        for (const w of result.warnings) console.log(chalk.yellow(`⚠️  ${sanitizeTerminal(w)}`));
      }
      await printScanResult(result);
    }

    // Generate HTML Report if requested
    if (options.html || options.openReport) {
      const htmlReportPath = await generateHtmlReport(result);
      if (options.json) {
        console.error(`HTML report generated: ${htmlReportPath}`);
      } else {
        console.log(chalk.cyan.bold(`\n📄 Detailed HTML report generated: ${htmlReportPath}`));
      }

      if (options.openReport) {
        try {
          const fileUrl = pathToFileURL(htmlReportPath).href;
          await open(fileUrl);
        } catch {
          if (!options.json)
            console.log(chalk.gray("Could not automatically open the report in your browser."));
        }
      }
    }

    // CI/CD Integration: exit code 1 if deploy blocker. Set exitCode (instead of
    // process.exit) so piped stdout is fully flushed.
    if (result.deployStatus === "blocker" || result.deployStatus === "danger") {
      if (!options.json) {
        console.log(
          chalk.red.bold(
            "\n❌ Scan failed: Blocking issues found. Please fix them before deploying.",
          ),
        );
      }
      process.exitCode = 1;
    } else {
      if (!options.json)
        console.log(chalk.green.bold("\n✅ Scan passed! You are clear to deploy."));
      process.exitCode = 0;
    }

    // Interactive mode: offer the fix wizard once the results are on screen.
    // Skipped without a TTY or when there is nothing to fix.
    if (options.interactive && !options.json && process.stdin.isTTY && result.findings.length > 0) {
      let start = false;
      try {
        start = await confirm({
          message: chalk.magenta.bold("Walk through the fixes now?"),
          default: true,
        });
      } catch (err) {
        if (!(err instanceof Error && err.name === "ExitPromptError")) throw err;
      }
      if (start) {
        const scanExitCode = process.exitCode;
        try {
          // Same flags as the scan, so the wizard's rescan applies the config file the same way.
          await runFixWizard(rootPath, {
            initialResult: result,
            deep: options.deep,
            includeTests: options.includeTests,
            config: options.config,
            trustConfig: options.trustConfig,
          });
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          console.error(chalk.red.bold(`\n\u274c Error during fix wizard: ${message}`));
        } finally {
          // The wizard must not mask the scan's CI exit code.
          process.exitCode = scanExitCode;
        }
      }
    }
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    if (!options.json)
      console.error(chalk.red.bold(`\n❌ Error during scan: ${sanitizeTerminal(message)}`));
    else console.error(`Error during scan: ${sanitizeTerminal(message)}`);
    process.exitCode = 2;
  }
}
