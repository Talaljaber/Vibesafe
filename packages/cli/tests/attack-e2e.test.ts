/**
 * End-to-end demo flow (spec 13, D2): the built `vibesafe` binary against the zero-dependency
 * demo harness, exactly as on stage.
 *
 * 1. Baseline on the vulnerable app: ledger 4/2/1/1, exit 1.
 * 2. The fix lands, the harness restarts with `--overlay fixed`, `--retest`: notes GET and
 *    admin/users BLOCKED (owner access intact), invoices and the notes PATCH UNCHANGED, exit 0.
 * 3. A plain run while a baseline exists exits 2 and leaves the baseline alone.
 *
 * Requires `pnpm build` (dist/bin.js). Every child is spawned with process.execPath and no shell,
 * and every child is killed in afterAll.
 */
import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { AttackResult, AttackRun } from "@talaljaber/vibesafe-attack";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(__dirname, "../dist/bin.js");
const repoRoot = path.resolve(__dirname, "../../..");
const fixture = path.join(repoRoot, "fixtures", "attack-demo-app");
const fixedOverlay = path.join(repoRoot, "fixtures", "attack-demo-app-fixed");

const children = new Set<ChildProcess>();
let harness: ChildProcess | undefined;
let tmp = "";
let app = "";

function alive(proc: ChildProcess): boolean {
  return proc.exitCode === null && proc.signalCode === null;
}

function startHarness(extra: string[] = []): Promise<string> {
  const proc = spawn(process.execPath, [path.join(app, "server.mjs"), "--port", "0", ...extra], {
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  harness = proc;
  children.add(proc);
  return new Promise<string>((resolve, reject) => {
    let out = "";
    let err = "";
    const timer = setTimeout(() => reject(new Error(`harness did not start: ${err}`)), 20_000);
    proc.stderr?.on("data", (d: Buffer) => {
      err += d.toString();
    });
    proc.stdout?.on("data", (d: Buffer) => {
      out += d.toString();
      const m = /LISTENING (\d+)/.exec(out);
      if (m) {
        clearTimeout(timer);
        resolve(`http://127.0.0.1:${m[1]}`);
      }
    });
    proc.once("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    proc.once("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`harness exited (${code}): ${err}`));
    });
  });
}

function stop(proc: ChildProcess | undefined): Promise<void> {
  if (!proc || !alive(proc)) return Promise.resolve();
  return new Promise<void>((resolve) => {
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

interface CliResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

/** Runs the built CLI (no shell) and collects its output. */
function vibesafe(args: string[]): Promise<CliResult> {
  const proc = spawn(process.execPath, [BIN, ...args], {
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
    env: { ...process.env, FORCE_COLOR: "0", NO_COLOR: "1" },
  });
  children.add(proc);
  return new Promise<CliResult>((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      proc.kill("SIGKILL");
      reject(new Error(`vibesafe ${args.join(" ")} timed out\n${stderr}`));
    }, 45_000);
    proc.stdout?.on("data", (d: Buffer) => {
      stdout += d.toString();
    });
    proc.stderr?.on("data", (d: Buffer) => {
      stderr += d.toString();
    });
    proc.once("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    proc.once("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}

function parseRun(res: CliResult): AttackRun {
  try {
    return JSON.parse(res.stdout) as AttackRun;
  } catch {
    throw new Error(`not JSON (exit ${res.code}):\n${res.stdout}\n${res.stderr}`);
  }
}

const routeKey = (r: Pick<AttackResult, "method" | "route">): string => `${r.method} ${r.route}`;
const byRoute = (run: AttackRun): Record<string, AttackResult> =>
  Object.fromEntries(run.results.map((r) => [routeKey(r), r]));
const vs = (...p: string[]): string => path.join(app, ".vibesafe", ...p);

beforeAll(() => {
  expect(fs.existsSync(BIN), "run `pnpm build` first").toBe(true);
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vs-attack-e2e-"));
  app = path.join(tmp, "app");
  fs.cpSync(fixture, app, { recursive: true });
});

afterAll(async () => {
  for (const c of children) await stop(c);
  for (const c of children) expect(alive(c)).toBe(false);
  try {
    fs.rmSync(tmp, { recursive: true, force: true });
  } catch {
    // Windows may still hold a handle for a moment; the OS temp dir is swept later.
  }
});

describe("vibesafe attack end to end on the demo harness", () => {
  let baseline: AttackRun;

  it("baseline: Static flagged 4 · live confirmed 2 · refuted 1 · couldn't test 1, exit 1", async () => {
    const target = await startHarness();
    const res = await vibesafe(["attack", app, "--target", target, "--rate", "50", "--json"]);
    expect(res.code, res.stderr).toBe(1);
    baseline = parseRun(res);
    expect(baseline.mode).toBe("baseline");
    expect(baseline.ledger).toEqual({
      staticFlagged: 4,
      confirmed: 2,
      refuted: 1,
      untested: 1,
      errors: 0,
    });
    const r = byRoute(baseline);
    expect(r["GET /api/notes/[id]"]).toMatchObject({ outcome: "CONFIRMED", ownerOk: true });
    expect(r["GET /api/admin/users"]?.outcome).toBe("CONFIRMED");
    expect(r["GET /api/invoices/[id]"]?.outcome).toBe("NOT_REPRODUCED");
    expect(r["PATCH /api/notes/[id]"]?.outcome).toBe("INCONCLUSIVE");
    // every request was a GET to the loopback harness
    for (const e of baseline.requestLog) {
      expect(e.method).toBe("GET");
      expect(e.url.startsWith(`${target}/`)).toBe(true);
    }
    for (const f of ["attack-baseline.json", "attack-report.md", "attack-report.html"]) {
      expect(fs.existsSync(vs(f)), f).toBe(true);
    }
  }, 60_000);

  it("a plain run while a baseline exists exits 2 and keeps the baseline", async () => {
    const before = fs.readFileSync(vs("attack-baseline.json"), "utf8");
    const target = `http://127.0.0.1:${new URL(baseline.targetUrl).port}`;
    const res = await vibesafe(["attack", app, "--target", target]);
    expect(res.code).toBe(2);
    expect(res.stderr).toContain("A baseline exists");
    expect(fs.readFileSync(vs("attack-baseline.json"), "utf8")).toBe(before);
  }, 60_000);

  it("retest after the fix: notes GET and admin/users BLOCKED, the rest UNCHANGED, exit 0", async () => {
    await stop(harness);
    // The agent's fix lands in the project, and the harness restarts on the fixed twin.
    fs.cpSync(fixedOverlay, app, { recursive: true });
    const target = await startHarness(["--overlay", fixedOverlay]);
    const before = fs.readFileSync(vs("attack-baseline.json"), "utf8");

    const res = await vibesafe([
      "attack",
      app,
      "--target",
      target,
      "--retest",
      "--rate",
      "50",
      "--json",
    ]);
    expect(res.code, res.stderr).toBe(0);
    const retest = parseRun(res);
    expect(retest.mode).toBe("retest");
    const idOf = (k: string): string => byRoute(baseline)[k]?.attackId ?? "";
    const state = (k: string) => retest.diff?.find((d) => d.attackId === idOf(k));

    expect(state("GET /api/notes/[id]")).toMatchObject({ state: "BLOCKED", ownerOk: true });
    expect(state("GET /api/admin/users")?.state).toBe("BLOCKED");
    expect(state("GET /api/invoices/[id]")?.state).toBe("UNCHANGED");
    expect(state("PATCH /api/notes/[id]")?.state).toBe("UNCHANGED");
    expect(retest.diff).toHaveLength(4);
    expect(retest.ledger.confirmed).toBe(0);
    // a retest never overwrites the baseline
    expect(fs.readFileSync(vs("attack-baseline.json"), "utf8")).toBe(before);
  }, 60_000);

  it("the terminal retest view shows the fix and owner access", async () => {
    const target = `http://127.0.0.1:${
      new URL(JSON.parse(fs.readFileSync(vs("attack-last.json"), "utf8")).targetUrl as string).port
    }`;
    const res = await vibesafe(["attack", app, "--target", target, "--retest", "--rate", "50"]);
    expect(res.code, res.stderr).toBe(0);
    expect(res.stdout).toContain("BLOCKED");
    expect(res.stdout).toContain("Alice can no longer read Bob's note");
    expect(res.stdout).toContain("owner access still works");
    expect(res.stdout).toContain("Still refuted by the live test");
  }, 60_000);
});
