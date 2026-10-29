#!/usr/bin/env node
// Measures VibeSafe against a seeded benchmark app and its answer key.
//
//   pnpm bench --app <dir> --key <answer-key.json> [--cli packages/cli/dist/bin.js]
//              [--baseline base.json] [--deep] [--window 3] [--out report.json]
//              [--fail-on-regression]
//
// The answer key is a JSON array of { id, file, line, category, title, isDecoy }.
// A finding is "located" at a key item when it is in the same file and within
// `window` lines (file-level findings without a line count as located); it is
// "compatible" when it is also of a compatible category. Non-decoy items are
// caught strictly (a compatible finding) or leniently (any located finding); a
// decoy is "hit" when any finding with a line is located at it. `--baseline` takes a raw
// `scan --json` output or a previous `--out` report and prints the delta.
//
// Paths containing a `holdout` segment are refused: a held-out evaluation set
// must never be scanned while rules are being written.

import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

/** Key category -> finding categories that count as the same kind of issue. */
export const COMPATIBLE_CATEGORIES = {
  secret: ["secret", "frontend_exposure", "crypto"],
  crypto: ["crypto", "secret"],
  auth: ["auth", "authorization"],
  authorization: ["authorization", "auth"],
  injection: ["injection", "xss"],
  ssrf: ["injection"],
  validation: ["validation", "injection"],
  logic: ["validation", "authorization"],
  security_config: ["security_config"],
  frontend_exposure: ["frontend_exposure", "secret"],
  xss: ["xss", "injection"],
  structure: ["structure", "code_quality"],
  code_quality: ["code_quality", "structure"],
  dependency: ["dependency"],
};

/** Throws when any path has a `holdout` segment (case-insensitive, either separator). */
export function assertNotHoldout(...paths) {
  for (const p of paths) {
    if (typeof p !== "string") continue;
    if (p.split(/[\\/]+/).some((seg) => seg.toLowerCase() === "holdout")) {
      throw new Error(`Refusing to use ${p}: holdout sets are for blind evaluation only.`);
    }
  }
}

/** Normalizes a finding or key path to a forward-slash path relative to the app root. */
export function normalizePath(file, appRoot) {
  if (typeof file !== "string") return "";
  let p = file.replace(/\\/g, "/").replace(/^\(git history\)\s*/, "");
  if (appRoot) {
    const root = appRoot.replace(/\\/g, "/").replace(/\/+$/, "");
    if (p.toLowerCase().startsWith(`${root.toLowerCase()}/`)) p = p.slice(root.length + 1);
  }
  return p.replace(/^\.\//, "");
}

/** True when the category of `finding` counts for a key item of `keyCategory`. */
export function isCompatible(keyCategory, findingCategory) {
  if (keyCategory === "other") return true;
  const allowed = COMPATIBLE_CATEGORIES[keyCategory] ?? [keyCategory];
  return allowed.includes(findingCategory);
}

/** True when the finding is in the item's file and within `window` lines of it. */
export function isLocated(item, finding, window = 3, appRoot) {
  if (normalizePath(finding.file, appRoot) !== normalizePath(item.file, appRoot)) return false;
  if (typeof finding.line !== "number") return true;
  return Math.abs(finding.line - item.line) <= window;
}

/** Signature used to compare findings across runs (ids may change when rules change). */
export function findingSignature(f, appRoot) {
  return `${f.ruleId}|${normalizePath(f.file, appRoot)}|${f.line ?? ""}`;
}

/**
 * Matches scan findings against the answer key. Returns per-item rows, recall over
 * non-decoy items, flagged decoys and findings located at no key item.
 */
export function matchFindings(key, findings, { window = 3, appRoot } = {}) {
  const rows = key.map((item) => {
    const located = findings.filter((f) => isLocated(item, f, window, appRoot));
    const compatible = located.filter((f) => isCompatible(item.category, f.category));
    let status;
    // A file-level finding (no line) makes no claim about a decoy's line.
    if (item.isDecoy) {
      const onLine = located.filter((f) => typeof f.line === "number");
      status = onLine.length > 0 ? "decoy-hit" : "decoy-clean";
    } else if (compatible.length > 0) status = "caught";
    else if (located.length > 0) status = "located";
    else status = "missed";
    return {
      id: item.id,
      isDecoy: Boolean(item.isDecoy),
      file: normalizePath(item.file, appRoot),
      line: item.line,
      category: item.category,
      status,
      ruleIds: [...new Set(located.map((f) => f.ruleId))].sort(),
    };
  });
  const real = rows.filter((r) => !r.isDecoy);
  const strict = real.filter((r) => r.status === "caught").length;
  const lenient = real.filter((r) => r.status === "caught" || r.status === "located").length;
  const unmatched = findings.filter(
    (f) => !key.some((item) => isLocated(item, f, window, appRoot)),
  );
  const unmatchedByRule = {};
  for (const f of unmatched) unmatchedByRule[f.ruleId] = (unmatchedByRule[f.ruleId] ?? 0) + 1;
  return {
    rows,
    total: real.length,
    strict,
    lenient,
    decoysFlagged: rows.filter((r) => r.status === "decoy-hit"),
    unmatched: unmatched.map((f) => findingSignature(f, appRoot)),
    unmatchedByRule,
  };
}

const isHit = (r) => r.status === "caught" || r.status === "located";

/** Differences between a baseline match and the current one. */
export function compareMatches(base, current) {
  const byId = new Map(base.rows.map((r) => [r.id, r]));
  const newlyCaught = [];
  const newlyStrict = [];
  const lost = [];
  const newDecoys = [];
  for (const r of current.rows) {
    const b = byId.get(r.id);
    if (!b) continue;
    if (r.isDecoy) {
      if (r.status === "decoy-hit" && b.status !== "decoy-hit") newDecoys.push(r.id);
      continue;
    }
    if (isHit(r) && !isHit(b)) newlyCaught.push(r.id);
    if (r.status === "caught" && b.status !== "caught") newlyStrict.push(r.id);
    if ((isHit(b) && !isHit(r)) || (b.status === "caught" && r.status !== "caught")) {
      lost.push(r.id);
    }
  }
  const baseUnmatched = new Set(base.unmatched);
  const newUnmatched = current.unmatched.filter((s) => !baseUnmatched.has(s));
  return { newlyCaught, newlyStrict, lost, newDecoys, newUnmatched };
}

/** Parses `scan --json` output (tolerates a BOM or leading log lines). */
export function parseScanOutput(text) {
  const t = text.replace(/^﻿/, "");
  const start = t.indexOf("{");
  if (start === -1) throw new Error("No JSON object in scan output.");
  return JSON.parse(t.slice(start));
}

/** Accepts a raw scan result or a previous bench report and returns its findings. */
export function findingsOf(json) {
  if (json && Array.isArray(json.findings)) return json.findings;
  if (json && json.scan && Array.isArray(json.scan.findings)) return json.scan.findings;
  throw new Error("Baseline is neither a scan result nor a bench report.");
}

function parseArgs(argv) {
  const opts = { window: 3, deep: false, failOnRegression: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`${a} needs a value`);
      return v;
    };
    if (a === "--app") opts.app = next();
    else if (a === "--key") opts.key = next();
    else if (a === "--cli") opts.cli = next();
    else if (a === "--baseline") opts.baseline = next();
    else if (a === "--out") opts.out = next();
    else if (a === "--window") opts.window = Number(next());
    else if (a === "--deep") opts.deep = true;
    else if (a === "--fail-on-regression") opts.failOnRegression = true;
    else throw new Error(`Unknown option ${a}`);
  }
  if (!opts.app || !opts.key) throw new Error("--app and --key are required");
  if (!Number.isInteger(opts.window) || opts.window < 0) throw new Error("--window must be >= 0");
  return opts;
}

function runScan(cli, app, deep) {
  const args = [cli, "scan", app, "--json", ...(deep ? ["--deep"] : [])];
  return new Promise((resolve, reject) => {
    // The CLI exits non-zero when it finds blockers; only the output matters here.
    execFile(process.execPath, args, { maxBuffer: 64 * 1024 * 1024 }, (error, stdout) => {
      if (stdout && stdout.includes("{")) resolve(stdout);
      else reject(error ?? new Error("scan produced no output"));
    });
  });
}

function readJson(file) {
  return parseScanOutput(fs.readFileSync(file, "utf8"));
}

function printReport(match, scan, delta) {
  const out = [];
  out.push(
    `Findings: ${scan.findings.length}   score ${scan.score}   engine ${scan.durationMs} ms`,
  );
  out.push(
    `Recall: strict ${match.strict}/${match.total}   lenient ${match.lenient}/${match.total}`,
  );
  out.push("");
  for (const r of match.rows) {
    const rules = r.ruleIds.length > 0 ? `  [${r.ruleIds.join(", ")}]` : "";
    out.push(`${r.id.padEnd(6)} ${r.status.padEnd(11)} ${r.file}:${r.line}${rules}`);
  }
  out.push("");
  out.push(
    `Decoys flagged: ${match.decoysFlagged.length === 0 ? "none" : match.decoysFlagged.map((r) => `${r.id} [${r.ruleIds.join(", ")}]`).join("; ")}`,
  );
  const unmatched = Object.entries(match.unmatchedByRule).sort((a, b) => b[1] - a[1]);
  out.push(`Unmatched findings by rule: ${unmatched.length === 0 ? "none" : ""}`);
  for (const [rule, n] of unmatched) out.push(`  ${n}  ${rule}`);
  if (delta) {
    const list = (xs) => (xs.length === 0 ? "none" : xs.join(", "));
    out.push("");
    out.push(`Newly caught (lenient): ${list(delta.newlyCaught)}`);
    out.push(`Newly caught (strict): ${list(delta.newlyStrict)}`);
    out.push(`Lost: ${list(delta.lost)}`);
    out.push(`Newly flagged decoys: ${list(delta.newDecoys)}`);
    out.push(`New unmatched findings: ${list(delta.newUnmatched)}`);
  }
  process.stdout.write(`${out.join("\n")}\n`);
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const here = path.dirname(fileURLToPath(import.meta.url));
  const cli = opts.cli ?? path.join(here, "..", "packages", "cli", "dist", "bin.js");
  assertNotHoldout(opts.app, opts.key, opts.baseline, opts.out, cli);
  const app = path.resolve(opts.app);
  const key = JSON.parse(fs.readFileSync(opts.key, "utf8").replace(/^﻿/, ""));
  if (!Array.isArray(key)) throw new Error("The answer key must be a JSON array.");

  const scan = parseScanOutput(await runScan(cli, app, opts.deep));
  const match = matchFindings(key, scan.findings, { window: opts.window, appRoot: app });
  let delta;
  if (opts.baseline) {
    const baseFindings = findingsOf(readJson(opts.baseline));
    const base = matchFindings(key, baseFindings, { window: opts.window, appRoot: app });
    delta = compareMatches(base, match);
  }
  printReport(match, scan, delta);
  if (opts.out) {
    const report = { app, window: opts.window, deep: opts.deep, match, delta, scan };
    fs.writeFileSync(opts.out, `${JSON.stringify(report, null, 2)}\n`);
  }
  if (opts.failOnRegression && delta && (delta.lost.length > 0 || delta.newDecoys.length > 0)) {
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((error) => {
    process.stderr.write(`bench: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 2;
  });
}
