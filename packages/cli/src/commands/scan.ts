import path from "path";
import chalk from "chalk";
import { ScannerPipeline, createDefaultRegistry } from "@vibesafe/core";
import { printScanResult } from "../ui/printer.js";
import { confirm } from "@inquirer/prompts";
import cliProgress from "cli-progress";
import { generateHtmlReport } from "../ui/html-reporter.js";
import open from "open";
import { pathToFileURL } from "node:url";

export interface ScanOptions {
  interactive?: boolean;
  html?: boolean;
  openReport?: boolean;
  json?: boolean;
}

export async function runScan(targetDir: string, options: ScanOptions = {}) {
  const rootPath = path.resolve(process.cwd(), targetDir);

  if (!options.json) {
    console.log(chalk.cyan(`Ready to scan directory: ${rootPath}`));
  }
  
  if (options.interactive) {
    const proceed = await confirm({
      message: chalk.magenta.bold("Ready to scan your codebase for security, code mess, and more?"),
      default: true
    });

    if (!proceed) {
      if (!options.json) console.log(chalk.gray("Scan cancelled."));
      process.exit(0);
    }
  }

  if (!options.json) {
    console.log(chalk.gray("\nStarting VibeSafe scan...\n"));
  }

  try {
    const registry = createDefaultRegistry();
    const pipeline = new ScannerPipeline(registry);
    
    const progressBar = new cliProgress.SingleBar({
      format: chalk.cyan('{bar}') + ' {percentage}% | {value}/{total} | ' + chalk.magenta('{message}'),
      barCompleteChar: '\u2588',
      barIncompleteChar: '\u2591',
      hideCursor: true
    });

    if (!options.json) {
      progressBar.start(registry.getDetectors().length, 0, { message: 'Initializing...' });
    }

    const result = await pipeline.scan({ rootPath }, (message, current, total) => {
      if (!options.json) {
        progressBar.update(current, { message });
      }
    });

    if (!options.json) {
      progressBar.update(registry.getDetectors().length, { message: 'Scan complete!' });
      progressBar.stop();
      console.log("");
    }

    if (options.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      // Check for errors and show warning
      if (result.errors && result.errors.length > 0) {
        console.log(chalk.yellow.bold(`\n⚠️  ${result.errors.length} detector(s) failed. Scan may be incomplete.`));
      }
      printScanResult(result);
    }
    
    // Generate HTML Report if requested
    if (options.html || options.openReport) {
      const htmlReportPath = await generateHtmlReport(result);
      if (!options.json) {
        console.log(chalk.cyan.bold(`\n📄 Detailed HTML report generated: ${htmlReportPath}`));
      }
      
      // Open the HTML report
      if (options.openReport) {
        try {
          const fileUrl = pathToFileURL(htmlReportPath).href;
          await open(fileUrl);
        } catch (e) {
          if (!options.json) console.log(chalk.gray("Could not automatically open the report in your browser."));
        }
      }
    }

    // CI/CD Integration: Return exit code 1 if deploy blocker
    if (result.deployStatus === "blocker" || result.deployStatus === "danger") {
      if (!options.json) console.log(chalk.red.bold("\n❌ Scan failed: Blocking issues found. Please fix them before deploying."));
      process.exit(1);
    } else {
      if (!options.json) console.log(chalk.green.bold("\n✅ Scan passed! You are clear to deploy."));
      process.exit(0);
    }
  } catch (error: any) {
    if (!options.json) console.error(chalk.red.bold(`\n❌ Error during scan: ${error.message}`));
    process.exit(2);
  }
}
