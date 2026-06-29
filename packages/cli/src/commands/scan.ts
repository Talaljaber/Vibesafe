import path from "path";
import chalk from "chalk";
import { ScannerPipeline, createDefaultRegistry } from "@vibeguard/core";
import { printScanResult } from "../ui/printer.js";

export async function runScan(targetDir: string) {
  const rootPath = path.resolve(process.cwd(), targetDir);

  console.log(chalk.cyan(`Scanning directory: ${rootPath}`));
  console.log(chalk.gray("Running VibeGuard detectors...\n"));

  try {
    const registry = createDefaultRegistry();
    const pipeline = new ScannerPipeline(registry);

    const result = await pipeline.scan({ rootPath });

    printScanResult(result);

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
