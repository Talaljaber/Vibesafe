#!/usr/bin/env node
import { Command } from "commander";
import { printBanner } from "./ui/banner.js";
import { runScan } from "./commands/scan.js";
import { runFix } from "./commands/fix.js";
import { VIBESAFE_VERSION } from "@vibesafe/shared";

// Print banner unless --json is used, but we need to parse args first.
const isJson = process.argv.includes("--json") || process.argv.includes("-j");
if (!isJson) {
  printBanner();
}

const program = new Command();

program
  .name("vibesafe")
  .description("The don't-deploy-that-yet tool for vibe-coded apps")
  .version(VIBESAFE_VERSION);

program
  .command("scan")
  .description("Scan a directory for vibe-coding security and quality issues")
  .argument("[dir]", "Directory to scan", ".")
  .option("-i, --interactive", "Prompt for confirmation before scanning", false)
  .option("--html", "Generate HTML report", false)
  .option("--open-report", "Automatically open the HTML report after scan", false)
  .option("-j, --json", "Output pure JSON without console formatting", false)
  .action(async (dir, options) => {
    await runScan(dir, options);
  });

program
  .command("fix")
  .description("Automatically apply a safe fix for a specific finding or rule ID")
  .argument("<finding-id>", "The ID of the finding or rule to fix")
  .argument("[dir]", "Directory to run the fix in", ".")
  .action(async (findingId, dir) => {
    await runFix(findingId, dir);
  });

program.parse(process.argv);
