#!/usr/bin/env node
/**
 * Builds a throwaway demo repo with a planted 3-commit history for the
 * Git History Secret Forensics demo:
 *
 *   1. "feat: scaffold upload service" - a clean starting point
 *   2. "feat: wire up S3 upload with AWS credentials" - a hardcoded AWS key
 *      is committed directly into the source
 *   3. "fix: move AWS credentials to environment variables" - the key is
 *      removed from the working tree, but it's still sitting in commit 2's
 *      history forever
 *
 * A normal `vibesafe scan` on the resulting repo looks clean, because the
 * working tree has no secret in it. `vibesafe scan --deep` finds it anyway.
 *
 * Uses execFileSync with array args only (no shell, no string-concatenated
 * commands) so it behaves the same on Windows and POSIX shells.
 *
 * Usage:
 *   node scripts/create-demo-repo.mjs [outDir]
 *
 * outDir defaults to ./demo-app next to this repo. The directory is wiped
 * and rebuilt from scratch on every run, so it's safe to re-run.
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");

const outDir = path.resolve(process.cwd(), process.argv[2] ?? path.join(repoRoot, "demo-app"));

// Realistic-shaped, but fake, AWS credentials. These are generated at runtime
// rather than written as literals so that this file never itself contains
// anything matching a secret-scanning pattern — the finished values only exist
// inside the throwaway demo repo, which is gitignored. The access key still
// matches SECRET_PATTERNS "sec-aws-access-key" (AKIA + 16 alphanumerics) once
// assembled, so the demo trips the detector as intended.
function randomChars(alphabet, length) {
  let out = "";
  for (let i = 0; i < length; i++) {
    out += alphabet[Math.floor(Math.random() * alphabet.length)];
  }
  return out;
}

const UPPER_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const MIXED_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

const FAKE_AWS_ACCESS_KEY = "AKIA" + randomChars(UPPER_ALNUM, 16);
const FAKE_AWS_SECRET_KEY = randomChars(MIXED_ALNUM, 40);

function git(cwd, args) {
  execFileSync("git", args, { cwd, stdio: "inherit" });
}

function write(file, content) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content, "utf-8");
}

function main() {
  if (fs.existsSync(outDir)) {
    fs.rmSync(outDir, { recursive: true, force: true });
  }
  fs.mkdirSync(outDir, { recursive: true });

  git(outDir, ["init", "--quiet"]);
  git(outDir, ["config", "user.email", "demo@vibesafe.local"]);
  git(outDir, ["config", "user.name", "VibeSafe Demo"]);
  git(outDir, ["config", "commit.gpgsign", "false"]);

  // ── Commit 1: clean scaffold ────────────────────────────────────────────
  write(
    path.join(outDir, "package.json"),
    JSON.stringify(
      {
        name: "demo-app",
        version: "1.0.0",
        private: true,
        description: "VibeSafe git-history demo app",
        main: "src/index.js",
        dependencies: {
          express: "^4.19.2",
        },
      },
      null,
      2,
    ) + "\n",
  );

  write(
    path.join(outDir, ".gitignore"),
    ["node_modules/", ".env", ".env.local", ""].join("\n"),
  );

  write(
    path.join(outDir, "README.md"),
    "# demo-app\n\nA tiny demo app used to show off VibeSafe's git history forensics detector.\n",
  );

  write(
    path.join(outDir, "src", "index.js"),
    [
      "const express = require('express');",
      "const app = express();",
      "",
      "app.get('/health', (req, res) => res.json({ ok: true }));",
      "",
      "app.listen(3000, () => console.log('demo-app listening on :3000'));",
      "",
    ].join("\n"),
  );

  git(outDir, ["add", "-A"]);
  git(outDir, ["commit", "--quiet", "-m", "feat: scaffold upload service"]);

  // ── Commit 2: the leak ──────────────────────────────────────────────────
  write(
    path.join(outDir, "src", "upload.js"),
    [
      "const AWS = require('aws-sdk');",
      "",
      "// TODO: move this to env vars before shipping",
      `const AWS_ACCESS_KEY_ID = '${FAKE_AWS_ACCESS_KEY}';`,
      `const AWS_SECRET_ACCESS_KEY = '${FAKE_AWS_SECRET_KEY}';`,
      "",
      "const s3 = new AWS.S3({",
      "  accessKeyId: AWS_ACCESS_KEY_ID,",
      "  secretAccessKey: AWS_SECRET_ACCESS_KEY,",
      "});",
      "",
      "module.exports = { s3 };",
      "",
    ].join("\n"),
  );

  git(outDir, ["add", "-A"]);
  git(outDir, ["commit", "--quiet", "-m", "feat: wire up S3 upload with AWS credentials"]);

  // ── Commit 3: "fixed" - key removed from the working tree, not from history ──
  write(
    path.join(outDir, "src", "upload.js"),
    [
      "const AWS = require('aws-sdk');",
      "",
      "const s3 = new AWS.S3({",
      "  accessKeyId: process.env.AWS_ACCESS_KEY_ID,",
      "  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,",
      "});",
      "",
      "module.exports = { s3 };",
      "",
    ].join("\n"),
  );

  write(
    path.join(outDir, ".env.example"),
    ["AWS_ACCESS_KEY_ID=", "AWS_SECRET_ACCESS_KEY=", ""].join("\n"),
  );

  git(outDir, ["add", "-A"]);
  git(outDir, ["commit", "--quiet", "-m", "fix: move AWS credentials to environment variables"]);

  console.log(`\nDemo repo created at: ${outDir}`);
  console.log("\nDemo script:");
  console.log(`  vibesafe scan "${outDir}"          # looks clean, no secret in the working tree`);
  console.log(`  vibesafe scan "${outDir}" --deep   # CRITICAL: AWS key committed 3 commits ago, deleted but recoverable`);
}

main();
