#!/usr/bin/env node
/**
 * Copies the Attack Mode demo app out of this repo into a fresh, throwaway git
 * repo so it can be attacked on stage:
 *
 *   main   - the vulnerable app (fixtures/attack-demo-app), commit "vulnerable demo"
 *   fixed  - main plus the overlay from fixtures/attack-demo-app-fixed
 *
 * The working tree is left on `main`. A demo CLAUDE.md is written for the agent
 * on stage (the copied-out app does not inherit this repo's CLAUDE.md, which says
 * the fixtures are deliberately insecure and must not be fixed).
 *
 * Usage:
 *   node scripts/create-attack-demo.mjs [outDir] [--harness-only]
 *
 * outDir defaults to <os tmpdir>/vibesafe-attack-demo. It must not exist or must
 * be empty: the script never deletes anything and writes only inside outDir.
 *
 * --harness-only copies just the app files (no git repo, no branches, no
 * CLAUDE.md), for running the zero-dependency harness (server.mjs) directly.
 *
 * Uses execFileSync with array args only (no shell) so it behaves the same on
 * Windows and POSIX shells.
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const fixtureDir = path.join(repoRoot, "fixtures", "attack-demo-app");
const overlayDir = path.join(repoRoot, "fixtures", "attack-demo-app-fixed");

const DEMO_CLAUDE_MD = `# Demo app

This is your app. When asked, fix what \`.vibesafe/attack-report.md\` reports.
Do not run vibesafe attack yourself.
`;

const args = process.argv.slice(2);
const harnessOnly = args.includes("--harness-only");
const positional = args.filter((a) => !a.startsWith("--"));
const outDir = path.resolve(
  process.cwd(),
  positional[0] ?? path.join(os.tmpdir(), "vibesafe-attack-demo"),
);

function git(cwd, gitArgs) {
  execFileSync("git", gitArgs, { cwd, stdio: "inherit" });
}

function copyTree(from, to) {
  fs.cpSync(from, to, {
    recursive: true,
    filter: (src) => !src.split(path.sep).includes("node_modules"),
  });
}

function fail(message) {
  console.error(`create-attack-demo: ${message}`);
  process.exit(1);
}

function main() {
  if (!fs.existsSync(fixtureDir) || !fs.existsSync(overlayDir)) {
    fail("fixtures/attack-demo-app and fixtures/attack-demo-app-fixed must exist.");
  }
  if (fs.existsSync(outDir)) {
    if (!fs.statSync(outDir).isDirectory() || fs.readdirSync(outDir).length > 0) {
      fail(`${outDir} already exists and is not an empty directory; refusing to touch it.`);
    }
  }
  fs.mkdirSync(outDir, { recursive: true });

  copyTree(fixtureDir, outDir);

  if (harnessOnly) {
    console.log(`\nHarness-only copy written to ${outDir}`);
    console.log(`  cd ${outDir}`);
    console.log("  node server.mjs --port 3000");
    return;
  }

  git(outDir, ["init", "--quiet", "-b", "main"]);
  git(outDir, ["config", "user.email", "demo@vibesafe.local"]);
  git(outDir, ["config", "user.name", "VibeSafe Demo"]);
  git(outDir, ["config", "commit.gpgsign", "false"]);

  fs.writeFileSync(path.join(outDir, "CLAUDE.md"), DEMO_CLAUDE_MD, "utf-8");
  git(outDir, ["add", "-A"]);
  git(outDir, ["commit", "--quiet", "-m", "vulnerable demo"]);

  git(outDir, ["checkout", "--quiet", "-b", "fixed"]);
  copyTree(overlayDir, outDir);
  git(outDir, ["add", "-A"]);
  git(outDir, ["commit", "--quiet", "-m", "fixed demo"]);

  git(outDir, ["checkout", "--quiet", "main"]);

  console.log(`\nAttack demo repo created at ${outDir} (branches: main = vulnerable, fixed)`);
  console.log("\nNext steps:");
  console.log(`  cd ${outDir}`);
  console.log("  node server.mjs --port 3000            # harness (or: pnpm install && pnpm dev)");
  console.log("  vibesafe attack . --target http://127.0.0.1:3000");
  console.log("  git checkout fixed                      # restart the harness, then --retest");
}

main();
