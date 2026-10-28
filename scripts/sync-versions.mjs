#!/usr/bin/env node
// Keeps every workspace package (and VIBESAFE_VERSION in @vibesafe/shared) on one version.
//
// Usage:
//   node scripts/sync-versions.mjs            # align everything to the highest current version
//   node scripts/sync-versions.mjs 0.4.0      # align everything to 0.4.0
//   node scripts/sync-versions.mjs --check    # exit 1 if versions differ (no writes)
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const CONSTANT_FILE = path.join("packages", "shared", "src", "constants.ts");
const CONSTANT_RE = /(export const VIBESAFE_VERSION = ")([^"]*)(")/;

function compare(a, b) {
  const pa = a.split("-")[0].split(".").map(Number);
  const pb = b.split("-")[0].split(".").map(Number);
  for (let i = 0; i < 3; i++) if (pa[i] !== pb[i]) return pa[i] - pb[i];
  return 0;
}

/** Collect the package.json files under `<root>/packages/*` and the version constant. */
export function collectVersions(root) {
  const entries = [];
  const pkgDir = path.join(root, "packages");
  for (const name of fs.readdirSync(pkgDir).sort()) {
    const file = path.join(pkgDir, name, "package.json");
    if (!fs.existsSync(file)) continue;
    const json = JSON.parse(fs.readFileSync(file, "utf8"));
    entries.push({ kind: "package", file, name: json.name, version: json.version });
  }
  const constFile = path.join(root, CONSTANT_FILE);
  if (fs.existsSync(constFile)) {
    const m = CONSTANT_RE.exec(fs.readFileSync(constFile, "utf8"));
    if (m) entries.push({ kind: "constant", file: constFile, name: "VIBESAFE_VERSION", version: m[2] });
  }
  return entries;
}

/**
 * Align versions. Returns `{ target, entries, mismatched, changed }`.
 * With `check: true` nothing is written.
 */
export function syncVersions(root, { version, check = false } = {}) {
  const entries = collectVersions(root);
  if (entries.length === 0) throw new Error("No packages found");
  let target = version;
  if (target === undefined) {
    target = entries.map((e) => e.version).reduce((a, b) => (compare(a, b) >= 0 ? a : b));
  }
  if (!SEMVER.test(target)) throw new Error(`Invalid version: ${target}`);
  const mismatched = entries.filter((e) => e.version !== target);
  const changed = [];
  if (!check) {
    for (const e of mismatched) {
      const text = fs.readFileSync(e.file, "utf8");
      const next =
        e.kind === "package"
          ? text.replace(/("version"\s*:\s*")[^"]*(")/, (_m, a, b) => `${a}${target}${b}`)
          : text.replace(CONSTANT_RE, (_m, a, _v, c) => `${a}${target}${c}`);
      fs.writeFileSync(e.file, next);
      changed.push(e.file);
    }
  }
  return { target, entries, mismatched, changed };
}

function main(argv) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const check = argv.includes("--check");
  const version = argv.find((a) => !a.startsWith("--"));
  try {
    const result = syncVersions(root, { check, ...(version !== undefined ? { version } : {}) });
    for (const e of result.mismatched) {
      console.log(`${check ? "mismatch" : "updated"}: ${e.name} ${e.version} -> ${result.target}`);
    }
    if (check && result.mismatched.length > 0) {
      console.error(`Versions are not aligned (expected ${result.target}).`);
      process.exit(1);
    }
    if (result.mismatched.length === 0) console.log(`All versions are ${result.target}.`);
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(2);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2));
}
