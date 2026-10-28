#!/usr/bin/env node
import { Command } from "commander";
import { printBanner } from "./ui/banner.js";
import { runScan } from "./commands/scan.js";
import { runFix } from "./commands/fix.js";
import { createRequire } from "node:module";

// Real CLI version; both dist/bin.js and src/bin.ts sit one level below package.json.
const require = createRequire(import.meta.url);
const { version: CLI_VERSION } = require("../package.json") as { version: string };

// Print banner unless machine-readable output is requested (--json, --format, --output);
// we need to check args before commander parses them.
const isMachineOutput = process.argv.some(
  (a) =>
    a === "--json" ||
    a === "-j" ||
    a === "--format" ||
    a.startsWith("--format=") ||
    a === "--output" ||
    a.startsWith("--output="),
);
if (!isMachineOutput) {
  printBanner();
}

const program = new Command();

program
  .name("vibesafe")
  .description("The don't-deploy-that-yet tool for vibe-coded apps")
  .version(CLI_VERSION);

program
  .command("scan")
  .description("Scan a directory for vibe-coding security and quality issues")
  .argument("[dir]", "Directory to scan", ".")
  .option("-i, --interactive", "Prompt for confirmation before scanning", false)
  .option("--html", "Generate HTML report", false)
  .option("--open-report", "Automatically open the HTML report after scan", false)
  .option("-j, --json", "Output pure JSON without console formatting", false)
  .option("--format <format>", "Machine-readable output format: json | sarif (pure output on stdout)")
  .option("--output <file>", "Write --format/--json output to a file instead of stdout")
  .option("--deep", "Also scan git history for leaked secrets (slower)", false)
  .option("--include-tests", "Also scan test files and fixtures (excluded by default)", false)
  .action(async (dir, options) => {
    await runScan(dir, options);
  });

program
  .command("fix")
  .description("Automatically apply a safe fix for a specific finding or rule ID")
  .argument("<finding-id>", "The ID of the finding or rule to fix")
  .argument("[dir]", "Directory to run the fix in", ".")
  .option("-y, --yes", "Skip confirmation (needs an exact finding id or a single match)", false)
  .action(async (findingId, dir, options) => {
    await runFix(findingId, dir, { yes: Boolean(options.yes) });
  });

program.parse(process.argv);
