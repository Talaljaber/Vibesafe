#!/usr/bin/env node
import { Command } from "commander";
import { printBanner } from "./ui/banner.js";
import { shouldPrintBanner } from "./ui/format-args.js";
import { runScan } from "./commands/scan.js";
import { runFix } from "./commands/fix.js";
import { runWatch } from "./commands/watch.js";
import { runFixWizard } from "./commands/fix-wizard.js";
import { runFixAllCommand } from "./commands/fix-all.js";
import { runHookClaude } from "./commands/hook.js";
import { createRequire } from "node:module";

// Real CLI version; both dist/bin.js and src/bin.ts sit one level below package.json.
const require = createRequire(import.meta.url);
const { version: CLI_VERSION } = require("../package.json") as { version: string };

// Print banner unless machine-readable output is requested (--json, --format, --output) or the
// command prints a config snippet (`hook`); we need to check args before commander parses them.
if (shouldPrintBanner(process.argv) && process.argv[2] !== "hook") {
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
  .option(
    "-i, --interactive",
    "After the scan, offer to walk through the fixes interactively",
    false,
  )
  .option("--html", "Generate HTML report", false)
  .option("--open-report", "Automatically open the HTML report after scan", false)
  .option(
    "-j, --json",
    "Output pure JSON without console formatting (alias of --format json)",
    false,
  )
  .option(
    "--format <format>",
    "Machine-readable output format: json | sarif | markdown (PR-comment summary); pure output on stdout",
  )
  .option("--output <file>", "Write the report to a file (defaults to json format)")
  .option("--deep", "Also scan git history for leaked secrets (slower)")
  .option("--no-deep", "Do not scan git history, even if the config file enables it")
  .option("--include-tests", "Also scan test files and fixtures (excluded by default)")
  .option("--no-include-tests", "Exclude test files, even if the config file includes them")
  .option("--no-config", "Ignore any .vibesafe.config file")
  .option(
    "--trust-config",
    "Execute .ts/.js config files from the scanned directory (runs that code; trusted projects only)",
  )
  .option(
    "--online",
    "Also check dependencies online: OSV advisories for installed versions, and that each direct dependency exists on npm/PyPI (sends package names and versions to api.osv.dev, registry.npmjs.org, api.npmjs.org and pypi.org; off by default)",
  )
  .action(async (dir, options) => {
    await runScan(dir, options);
  });

program
  .command("fix")
  .description(
    "Automatically apply a safe fix for a finding or rule ID, all auto-fixable findings with --all, or walk through fixes with -i",
  )
  .argument(
    "[finding-id]",
    "The ID of the finding or rule to fix (with --all or -i: optional directory instead)",
  )
  .argument("[dir]", "Directory to run the fix in (default: .)")
  .option(
    "-a, --all",
    "Preview and apply every auto-fixable finding with a single confirmation (the one positional is then the directory)",
    false,
  )
  .option("-i, --interactive", "Scan, then walk through the fixes one by one", false)
  .option(
    "-y, --yes",
    "Skip confirmation (single fix: needs an exact finding id or a single match)",
    false,
  )
  .option("--no-config", "Ignore any .vibesafe.config file")
  .option(
    "--trust-config",
    "Execute .ts/.js config files from the directory (runs that code; trusted projects only)",
  )
  .action(async (first: string | undefined, second: string | undefined, options) => {
    // Same config handling for every fix mode (single, --all, -i).
    const configFlags = {
      ...(options.config === false ? { config: false } : {}),
      trustConfig: Boolean(options.trustConfig),
    };
    if (options.all && options.interactive) {
      console.error("error: --all and --interactive cannot be used together");
      process.exitCode = 1;
      return;
    }
    if (options.all) {
      // With --all there is no finding id, so `vibesafe fix --all ./app` puts the dir in the first positional.
      if (first !== undefined && second !== undefined) {
        console.error(
          "error: --all takes no finding id; pass only the directory (vibesafe fix --all [dir])",
        );
        process.exitCode = 1;
        return;
      }
      await runFixAllCommand(first ?? ".", { yes: Boolean(options.yes), ...configFlags });
      return;
    }
    if (options.interactive) {
      if (first !== undefined && second !== undefined) {
        console.error(
          "error: --interactive takes an optional directory, not a finding id. Use `vibesafe fix -i [dir]`.",
        );
        process.exitCode = 1;
        return;
      }
      try {
        await runFixWizard(first ?? ".", configFlags);
      } catch (err) {
        console.error(
          `Error during fix wizard: ${err instanceof Error ? err.message : String(err)}`,
        );
        process.exitCode = 1;
      }
      return;
    }
    if (first === undefined) {
      console.error("error: missing required argument 'finding-id' (or use --all / --interactive)");
      process.exitCode = 1;
      return;
    }
    await runFix(first, second ?? ".", { yes: Boolean(options.yes), ...configFlags });
  });

program
  .command("watch")
  .description("Scan, then keep watching for changes and print what got better or worse")
  .argument("[dir]", "Directory to watch", ".")
  .option(
    "-j, --json",
    "Emit NDJSON events (ready, change, error), one JSON object per line",
    false,
  )
  .option("--include-tests", "Also scan test files and fixtures (excluded by default)")
  .option("--no-include-tests", "Exclude test files, even if the config file includes them")
  .option("--no-config", "Ignore any .vibesafe.config file")
  .option(
    "--trust-config",
    "Execute .ts/.js config files from the watched directory (runs that code; trusted projects only)",
  )
  .action(async (dir, options) => {
    const controller = new AbortController();
    process.once("SIGINT", () => controller.abort());
    process.once("SIGTERM", () => controller.abort());
    // Watch never scans git history (a config `deep: true` is ignored here).
    await runWatch(dir, {
      json: Boolean(options.json),
      ...(options.includeTests !== undefined
        ? { includeTests: Boolean(options.includeTests) }
        : {}),
      ...(options.config === false ? { config: false } : {}),
      trustConfig: Boolean(options.trustConfig),
      signal: controller.signal,
    });
  });

// Agent hooks and scan exit-code help.
program
  .command("hook")
  .description("Print or install agent hooks that run VibeSafe automatically")
  .command("claude")
  .description(
    "Print a Claude Code hook that re-scans after each edit; --write merges it into .claude/settings.json",
  )
  .option("--write", "Merge the hook into <dir>/.claude/settings.json (keeps existing settings)")
  .option("--dir <dir>", "Project directory for --write", ".")
  .action(async (options: { write?: boolean; dir?: string }) => {
    await runHookClaude({ write: Boolean(options.write), dir: options.dir });
  });
program.commands
  .find((c) => c.name() === "scan")
  ?.addHelpText(
    "after",
    [
      "",
      "Exit codes:",
      "  0  scan passed: deploy status safe or warning",
      "  1  deploy status danger or blocker (a deploy-blocking finding, or score below 40)",
      "  2  usage or runtime error (unknown --format, unwritable --output, scan failure)",
    ].join("\n"),
  );

program.parse(process.argv);
