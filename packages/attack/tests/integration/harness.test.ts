/**
 * Vertical slice (spec 13 C4): runAttack against the zero-dependency demo harness.
 * Baseline ledger 4/2/1/1, then the fixed overlay and a retest: notes GET and admin/users
 * BLOCKED, invoices and the notes PATCH UNCHANGED. A plain run with a baseline is refused.
 */
import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { exitCodeForRun } from "../../src/diff.js";
import { replayAttack, runAttack } from "../../src/index.js";
import {
  AttackPersistError,
  BASELINE_EXISTS_MESSAGE,
  BASELINE_FILE,
  LAST_FILE,
  REPORT_HTML_FILE,
  REPORT_MD_FILE,
} from "../../src/persist.js";
import { ledgerLine } from "../../src/report/text.js";
import type { AttackResult, AttackRun } from "../../src/types.js";

const repoRoot = path.resolve(import.meta.dirname, "../../../..");
const fixture = path.join(repoRoot, "fixtures", "attack-demo-app");
const fixedOverlay = path.join(repoRoot, "fixtures", "attack-demo-app-fixed");

let tmp = "";
let root = "";
let child: ChildProcess | undefined;
const children: ChildProcess[] = [];

function startHarness(extra: string[] = []): Promise<string> {
  const proc = spawn(process.execPath, [path.join(root, "server.mjs"), "--port", "0", ...extra], {
    stdio: ["ignore", "pipe", "inherit"],
  });
  child = proc;
  children.push(proc);
  return new Promise<string>((resolve, reject) => {
    let buf = "";
    const timer = setTimeout(() => reject(new Error("harness did not start")), 20_000);
    proc.stdout?.on("data", (d: Buffer) => {
      buf += d.toString();
      const m = /LISTENING (\d+)/.exec(buf);
      if (m) {
        clearTimeout(timer);
        resolve(`http://127.0.0.1:${m[1]}`);
      }
    });
    proc.on("error", reject);
    proc.on("exit", () => reject(new Error("harness exited")));
  });
}

function stopHarness(): Promise<void> {
  const proc = child;
  child = undefined;
  if (!proc || proc.exitCode !== null) return Promise.resolve();
  return new Promise<void>((resolve) => {
    proc.once("exit", () => resolve());
    proc.kill();
  });
}

beforeAll(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vs-attack-runner-"));
  root = path.join(tmp, "app");
  fs.cpSync(fixture, root, { recursive: true });
});

afterEach(() => {
  vi.restoreAllMocks();
});

afterAll(async () => {
  await stopHarness();
  for (const c of children) if (c.exitCode === null) c.kill();
  try {
    fs.rmSync(tmp, { recursive: true, force: true });
  } catch {
    // Windows may still hold a handle; the OS temp dir is swept later
  }
});

const key = (r: Pick<AttackResult, "method" | "route">): string => `${r.method} ${r.route}`;
const byRoute = (run: AttackRun): Record<string, AttackResult> =>
  Object.fromEntries(run.results.map((r) => [key(r), r]));
const vs = (...p: string[]): string => path.join(root, ".vibesafe", ...p);

describe("runAttack on the demo harness", () => {
  let base = "";
  let baseline: AttackRun;

  it("dry run plans at least four groups and opens no connection", async () => {
    base = await startHarness();
    const connect = vi.spyOn(net.Socket.prototype, "connect");
    const run = await runAttack({ projectPath: root, target: base, mode: "dry-run" });
    expect(connect).not.toHaveBeenCalled();
    expect(run.mode).toBe("dry-run");
    expect(run.groups.length).toBeGreaterThanOrEqual(4);
    expect(run.requestLog.length).toBeGreaterThan(0);
    expect(run.requestLog.every((e) => e.blocked === "dry-run" && e.status === 0)).toBe(true);
    expect(run.ledger.staticFlagged).toBe(4);
    // a dry run writes nothing
    expect(fs.existsSync(vs(BASELINE_FILE))).toBe(false);
    expect(fs.existsSync(vs(LAST_FILE))).toBe(false);
  });

  it("baseline: Static flagged 4 · live confirmed 2 · refuted 1 · couldn't test 1", async () => {
    const lines: string[] = [];
    baseline = await runAttack({
      projectPath: root,
      target: base,
      mode: "baseline",
      rate: 50,
      log: (l) => lines.push(l),
    });
    expect(baseline.ledger).toEqual({
      staticFlagged: 4,
      confirmed: 2,
      refuted: 1,
      untested: 1,
      errors: 0,
    });
    expect(ledgerLine(baseline.ledger)).toBe(
      "Static flagged 4 · live confirmed 2 · refuted 1 · couldn't test 1",
    );
    const r = byRoute(baseline);
    expect(Object.keys(r).sort()).toEqual([
      "GET /api/admin/users",
      "GET /api/invoices/[id]",
      "GET /api/notes/[id]",
      "PATCH /api/notes/[id]",
    ]);
    // live confirmed 2: notes GET, admin/users
    expect(r["GET /api/notes/[id]"]).toMatchObject({
      outcome: "CONFIRMED",
      checkId: "idor",
      ownerOk: true,
    });
    expect(r["GET /api/admin/users"]).toMatchObject({
      outcome: "CONFIRMED",
      checkId: "unauth-route",
    });
    // refuted 1: invoices
    expect(r["GET /api/invoices/[id]"]).toMatchObject({ outcome: "NOT_REPRODUCED", ownerOk: true });
    // couldn't test 1: notes PATCH (write path)
    expect(r["PATCH /api/notes/[id]"]?.outcome).toBe("INCONCLUSIVE");
    expect(r["PATCH /api/notes/[id]"]?.reasoning).toMatch(/write path, not tested/);
    expect(exitCodeForRun(baseline)).toBe(1);

    expect(baseline.targetUrl).toBe(base);
    expect(lines.some((l) => l.includes("x-vibesafe-harness"))).toBe(true);
    // pre-warm first, every request a GET to the harness, nothing anywhere else
    expect(baseline.requestLog[0]?.url).toBe(`${base}/`);
    for (const e of baseline.requestLog) {
      expect(e.method).toBe("GET");
      expect(e.url.startsWith(`${base}/`)).toBe(true);
      expect(e.blocked).toBeUndefined();
    }
  });

  it("persists the baseline, last run and both reports with real-base curl lines", () => {
    for (const f of [BASELINE_FILE, LAST_FILE, REPORT_MD_FILE, REPORT_HTML_FILE]) {
      expect(fs.existsSync(vs(f))).toBe(true);
    }
    const md = fs.readFileSync(vs(REPORT_MD_FILE), "utf8");
    expect(md).toContain("Static flagged 4 · live confirmed 2 · refuted 1 · couldn't test 1");
    const notes = byRoute(baseline)["GET /api/notes/[id]"];
    expect(notes?.curl).toHaveLength(4);
    for (const line of notes?.curl ?? []) {
      expect(line).toContain(`${base}/api/notes/`);
      expect(line).not.toContain("<target>");
    }
    expect(notes?.curl.some((l) => /ALICE_COOKIE/.test(l))).toBe(true);
    const everything = [
      md,
      fs.readFileSync(vs(REPORT_HTML_FILE), "utf8"),
      fs.readFileSync(vs(BASELINE_FILE), "utf8"),
      fs.readFileSync(vs(LAST_FILE), "utf8"),
    ].join("\n");
    expect(everything).toContain(`${base}/api/notes/`);
    // cookie values never leave sessions.json
    expect(everything).not.toContain("alice-dev");
    expect(everything).not.toContain("bob-dev");
    // response values never reach the agent report
    expect(md).not.toContain("alice@");
  });

  it("a plain run when a baseline exists is refused with exit code 2 before any request", async () => {
    const connect = vi.spyOn(net.Socket.prototype, "connect");
    const before = fs.readFileSync(vs(BASELINE_FILE), "utf8");
    const err = await runAttack({ projectPath: root, target: base, mode: "baseline" }).catch(
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(AttackPersistError);
    expect((err as AttackPersistError).exitCode).toBe(2);
    expect((err as Error).message).toBe(BASELINE_EXISTS_MESSAGE);
    expect(connect).not.toHaveBeenCalled();
    expect(fs.readFileSync(vs(BASELINE_FILE), "utf8")).toBe(before);
  });

  it("retest with the fixed overlay: notes GET and admin/users BLOCKED, the rest UNCHANGED", async () => {
    await stopHarness();
    // The user's agent applies the fix in the project; the harness serves the fixed twin.
    fs.cpSync(fixedOverlay, root, { recursive: true });
    const fixedBase = await startHarness(["--overlay", fixedOverlay]);
    const before = fs.readFileSync(vs(BASELINE_FILE), "utf8");

    const retest = await runAttack({
      projectPath: root,
      target: fixedBase,
      mode: "retest",
      rate: 50,
    });
    const idOf = (k: string): string => byRoute(baseline)[k]?.attackId ?? "";
    const state = (k: string) => retest.diff?.find((d) => d.attackId === idOf(k));

    expect(state("GET /api/notes/[id]")).toMatchObject({
      state: "BLOCKED",
      was: "CONFIRMED",
      now: "NOT_REPRODUCED",
      ownerOk: true,
    });
    expect(state("GET /api/admin/users")).toMatchObject({
      state: "BLOCKED",
      was: "CONFIRMED",
      now: "NOT_REPRODUCED",
      ownerOk: true,
    });
    expect(state("GET /api/invoices/[id]")).toMatchObject({
      state: "UNCHANGED",
      now: "NOT_REPRODUCED",
    });
    expect(state("PATCH /api/notes/[id]")).toMatchObject({
      state: "UNCHANGED",
      now: "INCONCLUSIVE",
    });
    expect(retest.diff).toHaveLength(4);
    // admin/users: U1 401, U2 (alice, admin) 200
    const admin = byRoute(retest)["GET /api/admin/users"];
    expect(admin?.shapes.map((s) => [s.label, s.status])).toEqual([
      ["U1", 401],
      ["U2", 200],
    ]);
    expect(exitCodeForRun(retest)).toBe(0);
    expect(retest.mode).toBe("retest");
    // the fixed twin keeps only the deliberate static false positive (invoices)
    expect(retest.ledger.staticFlagged).toBe(1);
    // a retest never overwrites the baseline
    expect(fs.readFileSync(vs(BASELINE_FILE), "utf8")).toBe(before);
    expect(JSON.parse(fs.readFileSync(vs(LAST_FILE), "utf8")).mode).toBe("retest");
    expect(fs.readFileSync(vs(REPORT_MD_FILE), "utf8")).toContain("## Retest results");

    // --replay of the notes GET against the fixed app no longer reproduces
    const replay = await replayAttack(
      { projectPath: root, target: fixedBase, mode: "retest", rate: 50 },
      idOf("GET /api/notes/[id]"),
    );
    expect(replay).toMatchObject({ outcome: "NOT_REPRODUCED", ownerOk: true });
    expect(replay.curl.every((l) => l.includes(fixedBase))).toBe(true);
  });
});
