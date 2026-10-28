#!/usr/bin/env node
import { Command } from "commander";
import { printBanner } from "./ui/banner.js";
import { runScan } from "./commands/scan.js";
import { runFix } from "./commands/fix.js";
import { runFixAllCommand } from "./commands/fix-all.js";
import { createRequire } from "node:module";

// Real CLI version; both dist/bin.js and src/bin.ts sit one level below package.json.
const require = createRequire(import.meta.url);
const { version: CLI_VERSION } = require("../package.json") as { version: string };

// Print banner unless --json is used, but we need to parse args first.
const isJson = process.argv.includes("--json") || process.argv.includes("-j");
if (!isJson) {
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
  .option("--deep", "Also scan git history for leaked secrets (slower)", false)
  .option("--include-tests", "Also scan test files and fixtures (excluded by default)", false)
  .action(async (dir, options) => {
    await runScan(dir, options);
  });

program
  .command("fix")
  .description("Automatically apply a safe fix for a finding or rule ID, or for all auto-fixable findings with --all")
  .argument("[finding-id]", "The ID of the finding or rule to fix (omit with --all)")
  .argument("[dir]", "Directory to run the fix in", ".")
  .option("-a, --all", "Preview and apply every auto-fixable finding with a single confirmation", false)
  .option("-y, --yes", "Skip confirmation (single fix: needs an exact finding id or a single match)", false)
  .action(async (findingId: string | undefined, dir: string, options) => {
    if (options.all) {
      // With --all there is no finding id, so `vibesafe fix --all ./app` puts the dir in the first positional.
      await runFixAllCommand(dir !== "." ? dir : (findingId ?? "."), { yes: Boolean(options.yes) });
      return;
    }
    if (!findingId) {
      console.error("error: missing required argument 'finding-id' (or use --all)");
      process.exitCode = 1;
      return;
    }
    await runFix(findingId, dir, { yes: Boolean(options.yes) });
  });

program.parse(process.argv);
