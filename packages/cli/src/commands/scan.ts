import path from "path";
import chalk from "chalk";
import { ScannerPipeline, createDefaultRegistry } from "@vibeguard/core";
import { printScanResult } from "../ui/printer.js";
import { confirm } from "@inquirer/prompts";
import cliProgress from "cli-progress";
import { generateHtmlReport } from "../ui/html-reporter.js";
import open from "open";
import { pathToFileURL } from "node:url";

export async function runScan(targetDir: string) {
  const rootPath = path.resolve(process.cwd(), targetDir);

  console.log(chalk.cyan(`Ready to scan directory: ${rootPath}`));
  
  const proceed = await confirm({
    message: chalk.magenta.bold("Ready to scan your codebase for security, code mess, and more?"),
    default: true
  });

  if (!proceed) {
    console.log(chalk.gray("Scan cancelled."));
    process.exit(0);
  }

  console.log(chalk.gray("\nStarting VibeGuard scan...\n"));

  try {
    const registry = createDefaultRegistry();
    const pipeline = new ScannerPipeline(registry);
    
    const progressBar = new cliProgress.SingleBar({
      format: chalk.cyan('{bar}') + ' {percentage}% | {value}/{total} | ' + chalk.magenta('{message}'),
      barCompleteChar: '\u2588',
      barIncompleteChar: '\u2591',
      hideCursor: true
    });

    progressBar.start(registry.getDetectors().length, 0, { message: 'Initializing...' });

    const result = await pipeline.scan({ rootPath }, (message, current, total) => {
      progressBar.update(current, { message });
    });

    progressBar.update(registry.getDetectors().length, { message: 'Scan complete!' });
    progressBar.stop();

    console.log("");
    printScanResult(result);
    
    // Generate HTML Report
    const htmlReportPath = await generateHtmlReport(result);
    console.log(chalk.cyan.bold(`\n📄 Detailed HTML report generated: ${htmlReportPath}`));
    
    // Open the HTML report
    try {
      const fileUrl = pathToFileURL(htmlReportPath).href;
      await open(fileUrl);
    } catch (e) {
      console.log(chalk.gray("Could not automatically open the report in your browser."));
    }

    // CI/CD Integration: Return exit code 1 if deploy blocker
    if (result.deployStatus === "blocker" || result.deployStatus === "danger") {
      console.log(chalk.red.bold("\n❌ Scan failed: Blocking issues found. Please fix them before deploying."));
      process.exit(1);
    } else {
      console.log(chalk.green.bold("\n✅ Scan passed! You are clear to deploy."));
      process.exit(0);
    }
  } catch (error: any) {
    console.error(chalk.red.bold(`\n❌ Error during scan: ${error.message}`));
    process.exit(1);
  }
}
