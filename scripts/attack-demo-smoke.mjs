#!/usr/bin/env node
/**
 * Booth smoke test for the Attack Mode demo (spec 14). Runs the whole stage flow with the built
 * CLI against the zero-dependency harness and prints PASS or FAIL:
 *
 *   1. baseline on the vulnerable app      -> ledger 4/2/1/1, exit 1
 *   2. plain run while a baseline exists   -> exit 2, baseline untouched
 *   3. the fix lands, harness restarts with --overlay fixed, --retest
 *                                          -> notes GET + admin/users BLOCKED (owner ok),
 *                                             invoices + notes PATCH UNCHANGED, exit 0
 *
 *   pnpm build && pnpm demo:smoke
 *
 * Works on a copy in the OS temp dir; nothing in the repo is touched. Children are spawned with
 * process.execPath (no shell) and always killed. No network beyond 127.0.0.1.
 */
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const BIN = path.join(repoRoot, "packages", "cli", "dist", "bin.js");
const fixture = path.join(repoRoot, "fixtures", "attack-demo-app");
const overlay = path.join(repoRoot, "fixtures", "attack-demo-app-fixed");

const children = new Set();
const failures = [];
const started = Date.now();

function check(ok, label, detail = "") {
  console.log(`  ${ok ? "ok  " : "FAIL"}  ${label}${!ok && detail ? `  (${detail})` : ""}`);
  if (!ok) failures.push(label);
  return ok;
}

function startHarness(app, extra = []) {
  const proc = spawn(process.execPath, [path.join(app, "server.mjs"), "--port", "0", ...extra], {
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  children.add(proc);
  return new Promise((resolve, reject) => {
    let out = "";
    let err = "";
    const timer = setTimeout(() => reject(new Error(`harness did not start ${err}`)), 20_000);
    proc.stderr.on("data", (d) => (err += d));
    proc.stdout.on("data", (d) => {
      out += d;
      const m = /LISTENING (\d+)/.exec(out);
      if (m) {
        clearTimeout(timer);
        resolve({ proc, target: `http://127.0.0.1:${m[1]}` });
      }
    });
    proc.once("error", reject);
    proc.once("exit", (code) => reject(new Error(`harness exited (${code}) ${err}`)));
  });
}

function stop(proc) {
  if (!proc || proc.exitCode !== null || proc.signalCode !== null) return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      proc.kill("SIGKILL");
      resolve();
    }, 5_000);
    proc.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
    proc.kill();
  });
}

function vibesafe(args) {
  const proc = spawn(process.execPath, [BIN, ...args], {
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
    env: { ...process.env, FORCE_COLOR: "0", NO_COLOR: "1" },
  });
  children.add(proc);
  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      proc.kill("SIGKILL");
      reject(new Error(`vibesafe ${args.join(" ")} timed out`));
    }, 60_000);
    proc.stdout.on("data", (d) => (stdout += d));
    proc.stderr.on("data", (d) => (stderr += d));
    proc.once("error", reject);
    proc.once("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}

function parseRun(res) {
  try {
    return JSON.parse(res.stdout);
  } catch {
    return undefined;
  }
}

const key = (r) => `${r.method} ${r.route}`;
const byRoute = (run) => Object.fromEntries((run?.results ?? []).map((r) => [key(r), r]));
const ledgerText = (l) =>
  l
    ? `Static flagged ${l.staticFlagged} · live confirmed ${l.confirmed} · refuted ${l.refuted} · couldn't test ${l.untested}`
    : "no ledger";

const retestLedgerText = (run) => {
  const l = run?.ledger;
  if (!l) return "no ledger";
  const fixed = (run.diff ?? []).filter((d) => d.state === "BLOCKED").length;
  return `Static flagged ${l.staticFlagged} · fixed & verified ${fixed} · still vulnerable ${l.confirmed} · refuted ${Math.max(0, l.refuted - fixed)} · couldn't test ${l.untested}`;
};

async function main() {
  if (!fs.existsSync(BIN)) {
    console.error("FAIL  packages/cli/dist/bin.js is missing. Run `pnpm build` first.");
    process.exit(1);
  }
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vs-attack-smoke-"));
  const app = path.join(tmp, "app");
  fs.cpSync(fixture, app, { recursive: true });
  const baselineFile = path.join(app, ".vibesafe", "attack-baseline.json");

  try {
    console.log("VibeSafe Attack Mode demo smoke test (harness, loopback only)\n");

    // 1. Baseline
    let h = await startHarness(app);
    console.log(`1. Baseline attack on the vulnerable app (${h.target})`);
    const b = await vibesafe(["attack", app, "--target", h.target, "--json"]);
    const baseline = parseRun(b);
    const br = byRoute(baseline);
    check(baseline !== undefined, "CLI printed the run as JSON", b.stderr.trim().slice(0, 200));
    console.log(`        ${ledgerText(baseline?.ledger)}`);
    check(
      ledgerText(baseline?.ledger) ===
        "Static flagged 4 · live confirmed 2 · refuted 1 · couldn't test 1",
      "ledger is 4 / 2 / 1 / 1",
    );
    check(
      br["GET /api/notes/[id]"]?.outcome === "CONFIRMED",
      "CONFIRMED: Alice read Bob's note (GET /api/notes/[id])",
    );
    check(
      br["GET /api/admin/users"]?.outcome === "CONFIRMED",
      "CONFIRMED: logged-out visitor read GET /api/admin/users",
    );
    check(
      br["GET /api/invoices/[id]"]?.outcome === "NOT_REPRODUCED",
      "REFUTED: invoices static finding (the guard works live)",
    );
    check(
      br["PATCH /api/notes/[id]"]?.outcome === "INCONCLUSIVE",
      "NOT TESTED: PATCH /api/notes/[id] (write path)",
    );
    check(b.code === 1, "exit code 1", `got ${b.code}`);

    // 2. Baseline protection
    console.log("\n2. Plain run while a baseline exists");
    const before = fs.existsSync(baselineFile) ? fs.readFileSync(baselineFile, "utf8") : "";
    const p = await vibesafe(["attack", app, "--target", h.target]);
    check(p.code === 2, "exit code 2 (use --retest or --new-baseline)", `got ${p.code}`);
    check(
      before !== "" && fs.readFileSync(baselineFile, "utf8") === before,
      "baseline left untouched",
    );

    // 3. Fix + retest
    await stop(h.proc);
    fs.cpSync(overlay, app, { recursive: true });
    h = await startHarness(app, ["--overlay", overlay]);
    console.log(`\n3. Fix applied, harness restarted on the fixed twin (${h.target}), --retest`);
    const r = await vibesafe(["attack", app, "--target", h.target, "--retest", "--json"]);
    const retest = parseRun(r);
    const idOf = (k) => br[k]?.attackId;
    const diff = (k) => (retest?.diff ?? []).find((d) => d.attackId === idOf(k));
    check(retest !== undefined, "CLI printed the retest as JSON", r.stderr.trim().slice(0, 200));
    const notes = diff("GET /api/notes/[id]");
    check(
      notes?.state === "BLOCKED" && notes?.ownerOk === true,
      "BLOCKED: notes GET, owner access still works",
      `${notes?.state} ownerOk=${notes?.ownerOk}`,
    );
    check(
      diff("GET /api/admin/users")?.state === "BLOCKED",
      "BLOCKED: admin/users refuses logged-out visitors",
      diff("GET /api/admin/users")?.state,
    );
    check(
      retestLedgerText(retest) ===
        "Static flagged 1 · fixed & verified 2 · still vulnerable 0 · refuted 0 · couldn't test 0",
      "retest ledger calls out fixed & verified 2",
      retestLedgerText(retest),
    );
    check(
      diff("GET /api/invoices/[id]")?.state === "UNCHANGED",
      "UNCHANGED: invoices still refuted by the live test",
    );
    check(
      diff("PATCH /api/notes/[id]")?.state === "UNCHANGED",
      "UNCHANGED: notes PATCH still not tested",
    );
    check(r.code === 0, "exit code 0", `got ${r.code}`);
    check(fs.readFileSync(baselineFile, "utf8") === before, "retest kept the baseline");
  } catch (err) {
    check(false, "flow completed", err instanceof Error ? err.message : String(err));
  } finally {
    for (const c of children) await stop(c);
    try {
      fs.rmSync(tmp, { recursive: true, force: true });
    } catch {
      // Windows may still hold a handle; the OS temp dir is swept later.
    }
  }

  const secs = ((Date.now() - started) / 1000).toFixed(1);
  if (failures.length === 0) {
    console.log(`\nPASS  demo flow works end to end (${secs}s)`);
    process.exit(0);
  }
  console.log(`\nFAIL  ${failures.length} check(s) failed (${secs}s): ${failures.join("; ")}`);
  process.exit(1);
}

await main();
