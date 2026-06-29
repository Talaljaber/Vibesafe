#!/usr/bin/env node
import { Command } from "commander";
import { printBanner } from "./ui/banner.js";
import { runScan } from "./commands/scan.js";
import { runFix } from "./commands/fix.js";
import { VIBEGUARD_VERSION } from "@vibeguard/shared";

// Print the professional startup banner
printBanner();

const program = new Command();

program
  .name("vibeguard")
  .description("The don't-deploy-that-yet tool for vibe-coded apps")
  .version(VIBEGUARD_VERSION);

program
  .command("scan")
  .description("Scan a directory for vibe-coding security and quality issues")
  .argument("[dir]", "Directory to scan", ".")
  .action(async (dir) => {
    await runScan(dir);
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
