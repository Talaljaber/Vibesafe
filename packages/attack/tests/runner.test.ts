import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { ScannerPipeline } from "@talaljaber/vibesafe-core";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { computeLedger, routeServes } from "../src/runner.js";
import { replayAttack, runAttack } from "../src/index.js";
import { AttackPersistError, LAST_FILE, NO_BASELINE_MESSAGE } from "../src/persist.js";
import type { AttackResult, AttackRun } from "../src/types.js";

const repoRoot = path.resolve(import.meta.dirname, "../../..");
const fixture = path.join(repoRoot, "fixtures", "attack-demo-app");

let tmp = "";
beforeAll(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vs-attack-runner-unit-"));
});
afterAll(() => {
  try {
    fs.rmSync(tmp, { recursive: true, force: true });
  } catch {
    // best effort on Windows
  }
});
afterEach(() => {
  vi.restoreAllMocks();
});

function copyDemo(name: string): string {
  const dir = path.join(tmp, name);
  fs.cpSync(fixture, dir, { recursive: true });
  return dir;
}

describe("runner static pass", () => {
  it("scans with online:false even when the project config asks for network", async () => {
    const dir = copyDemo("online-config");
    fs.writeFileSync(path.join(dir, ".vibesafe.config.json"), '{ "online": true }\n');
    const scan = vi.spyOn(ScannerPipeline.prototype, "scan");
    const net1 = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("no network"));
    const connect = vi.spyOn(net.Socket.prototype, "connect");
    const err = await runAttack({ projectPath: dir, mode: "dry-run" }).then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(scan).toHaveBeenCalledTimes(1);
    expect(scan.mock.calls[0]?.[0]).toMatchObject({ rootPath: dir, online: false, deep: false });
    // The guarantee is the spy assertion above (explicit online:false reaches the scan). Core also
    // rejects the key in a config file, so here the run stops early with exit 2.
    if (err !== undefined) expect((err as { exitCode?: number }).exitCode).toBe(2);
    expect(net1).not.toHaveBeenCalled();
    expect(connect).not.toHaveBeenCalled();
  });

  it("a valid project config still gets online:false and never reaches OSV or a registry", async () => {
    const dir = copyDemo("valid-config");
    fs.writeFileSync(path.join(dir, ".vibesafe.config.json"), '{ "minSeverity": "low" }\n');
    const scan = vi.spyOn(ScannerPipeline.prototype, "scan");
    const net1 = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("no network"));
    const connect = vi.spyOn(net.Socket.prototype, "connect");
    const run = await runAttack({ projectPath: dir, mode: "dry-run" });
    expect(scan.mock.calls[0]?.[0]).toMatchObject({ online: false });
    expect(run.ledger.staticFlagged).toBe(4);
    expect(net1).not.toHaveBeenCalled();
    expect(connect).not.toHaveBeenCalled();
  });

  it("rejects a rate above the attack.json cap before scanning", async () => {
    const dir = copyDemo("rate-cap");
    const scan = vi.spyOn(ScannerPipeline.prototype, "scan");
    const err = await runAttack({ projectPath: dir, mode: "dry-run", rate: 101 }).catch(
      (e: unknown) => e,
    );
    expect((err as Error).message).toMatch(/invalid rate: 101/);
    expect(scan).not.toHaveBeenCalled();
  });

  it("a retest without a baseline is refused (exit 2) before scanning or sending", async () => {
    const dir = copyDemo("no-baseline");
    const scan = vi.spyOn(ScannerPipeline.prototype, "scan");
    const connect = vi.spyOn(net.Socket.prototype, "connect");
    const err = await runAttack({ projectPath: dir, mode: "retest" }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AttackPersistError);
    expect((err as AttackPersistError).exitCode).toBe(2);
    expect((err as Error).message).toBe(NO_BASELINE_MESSAGE);
    expect(scan).not.toHaveBeenCalled();
    expect(connect).not.toHaveBeenCalled();
  });
});

describe("computeLedger", () => {
  it("counts findings merged into one attack group once", () => {
    const f = (ruleId: string) => ({ ruleId }) as never;
    const l = computeLedger(
      [f("authorization/idor-unscoped-lookup"), f("authorization/idor-unscoped-lookup")],
      [{ outcome: "CONFIRMED" } as AttackResult],
      undefined,
      [{ attackId: "ATK-a" }, { attackId: "ATK-a" }],
    );
    expect(l).toEqual({ staticFlagged: 1, confirmed: 1, refuted: 0, untested: 0, errors: 0 });
  });

  it("counts consumed findings and outcomes", () => {
    const f = (ruleId: string) => ({ ruleId }) as never;
    const r = (outcome: AttackResult["outcome"]) => ({ outcome }) as AttackResult;
    expect(
      computeLedger(
        [
          f("authorization/idor-unscoped-lookup"),
          f("auth/missing-route-auth"),
          f("secrets/hardcoded-api-key"),
        ],
        [r("CONFIRMED"), r("NOT_REPRODUCED"), r("INCONCLUSIVE"), r("ERROR"), r("CONFIRMED")],
      ),
    ).toEqual({ staticFlagged: 2, confirmed: 2, refuted: 1, untested: 1, errors: 1 });
  });
});

describe("routeServes", () => {
  it("matches dynamic, catch-all and optional catch-all segments", () => {
    expect(routeServes("/api/notes/[id]", "/api/notes/n1?x=1")).toBe(true);
    expect(routeServes("/api/notes/[id]", "/api/notes")).toBe(false);
    expect(routeServes("/api/notes/[id]", "/api/notes/a/b")).toBe(false);
    expect(routeServes("/api/[...slug]", "/api/notes/a/b")).toBe(true);
    expect(routeServes("/api/[...slug]", "/api")).toBe(false);
    expect(routeServes("/api/[[...slug]]", "/api")).toBe(true);
    expect(routeServes("/api/cron", "/api/notes/n1")).toBe(false);
  });
});

describe("replayAttack", () => {
  const seen: string[] = [];
  let server: http.Server;
  let base = "";

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      seen.push(req.url ?? "");
      res.setHeader("x-vibesafe-harness", "1");
      res.statusCode = 404;
      res.end('{"error":"not found"}');
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  function projectWithRun(name: string): string {
    const dir = path.join(tmp, name);
    fs.mkdirSync(path.join(dir, ".vibesafe"), { recursive: true });
    fs.writeFileSync(
      path.join(dir, ".vibesafe", "sessions.json"),
      JSON.stringify({
        schemaVersion: 1,
        sessions: [{ label: "alice", headers: { Cookie: "s=a" }, resources: {} }],
      }),
    );
    const run: AttackRun = {
      schemaVersion: 1,
      vibesafeVersion: "0.0.0",
      mode: "baseline",
      startedAt: "2026-11-01T00:00:00.000Z",
      finishedAt: "2026-11-01T00:00:01.000Z",
      projectPath: dir,
      targetUrl: base,
      groups: [
        {
          attackId: "ATK-0123456789ab",
          checkId: "idor",
          title: "One signed-in user can read another user's notes.",
          route: "/api/notes/[id]",
          method: "GET",
          ownerLabels: ["R1", "R2"],
          requests: [
            { label: "R0", method: "GET", host: "target", path: "/api/notes/secret_probe" },
            { label: "R1", method: "GET", host: "target", path: "/api/notes/c1", session: "carol" },
            {
              label: "R2",
              method: "GET",
              host: "target",
              path: "/api/notes/secret_probe",
              session: "dave",
            },
            {
              label: "R3",
              method: "GET",
              host: "target",
              path: "/api/notes/secret_probe",
              session: "carol",
            },
          ],
        },
      ],
      results: [],
      requestLog: [],
      ledger: { staticFlagged: 1, confirmed: 0, refuted: 0, untested: 0, errors: 0 },
    };
    fs.writeFileSync(path.join(dir, ".vibesafe", LAST_FILE), JSON.stringify(run));
    return dir;
  }

  it("never sends a request whose session is gone: INCONCLUSIVE instead of a false refusal", async () => {
    const dir = projectWithRun("missing-session");
    seen.length = 0;
    const r = await replayAttack(
      { projectPath: dir, target: base, mode: "retest", rate: 100 },
      "ATK-0123456789ab",
    );
    expect(r.outcome).toBe("INCONCLUSIVE");
    expect(r.reasoning).toMatch(/session "carol" is not in sessions.json/);
    // judged before any pre-warm, control or target detection request
    expect(seen).toEqual([]);
  });

  function sessionsWith(dir: string, labels: string[]): void {
    fs.writeFileSync(
      path.join(dir, ".vibesafe", "sessions.json"),
      JSON.stringify({
        schemaVersion: 1,
        sessions: labels.map((label) => ({
          label,
          headers: { Cookie: `s=${label}` },
          resources: {},
        })),
      }),
    );
  }

  function writeRoute(dir: string, rel: string, body: string): void {
    const f = path.join(dir, rel);
    fs.mkdirSync(path.dirname(f), { recursive: true });
    fs.writeFileSync(f, body);
  }

  const WRITING_GET =
    "export async function GET(req: Request) { await db.from('audit').insert({ a: 1 }); return Response.json({}); }\n";

  it("a renamed dynamic segment that now writes is still skipped (no request reaches it)", async () => {
    const dir = projectWithRun("renamed-writes");
    sessionsWith(dir, ["carol", "dave"]);
    writeRoute(dir, "app/api/notes/[noteId]/route.ts", WRITING_GET);
    seen.length = 0;
    const r = await replayAttack(
      { projectPath: dir, target: base, mode: "retest", rate: 100 },
      "ATK-0123456789ab",
    );
    expect(r.outcome).toBe("INCONCLUSIVE");
    expect(r.reasoning).toMatch(/may write/);
    expect(seen).toEqual([]);
  });

  it("a catch-all route now serving the saved path that writes is skipped", async () => {
    const dir = projectWithRun("catch-all-writes");
    sessionsWith(dir, ["carol", "dave"]);
    writeRoute(dir, "app/api/[...slug]/route.ts", WRITING_GET);
    seen.length = 0;
    const r = await replayAttack(
      { projectPath: dir, target: base, mode: "retest", rate: 100 },
      "ATK-0123456789ab",
    );
    expect(r.outcome).toBe("INCONCLUSIVE");
    expect(seen).toEqual([]);
  });

  it("a saved request that does not belong to the saved route is never sent", async () => {
    const dir = projectWithRun("foreign-path");
    sessionsWith(dir, ["carol", "dave"]);
    const f = path.join(dir, ".vibesafe", LAST_FILE);
    const run = JSON.parse(fs.readFileSync(f, "utf8")) as AttackRun;
    run.groups[0]?.requests.push({
      label: "R9",
      method: "GET",
      host: "target",
      path: "/api/cron/purge",
    });
    fs.writeFileSync(f, JSON.stringify(run));
    seen.length = 0;
    const r = await replayAttack(
      { projectPath: dir, target: base, mode: "retest", rate: 100 },
      "ATK-0123456789ab",
    );
    expect(r.outcome).toBe("INCONCLUSIVE");
    expect(seen).toEqual([]);
  });

  it("a saved group without a route is never sent", async () => {
    const dir = projectWithRun("no-route");
    sessionsWith(dir, ["carol", "dave"]);
    const f = path.join(dir, ".vibesafe", LAST_FILE);
    const run = JSON.parse(fs.readFileSync(f, "utf8")) as AttackRun;
    delete run.groups[0]?.route;
    fs.writeFileSync(f, JSON.stringify(run));
    seen.length = 0;
    const r = await replayAttack(
      { projectPath: dir, target: base, mode: "retest", rate: 100 },
      "ATK-0123456789ab",
    );
    expect(r.outcome).toBe("INCONCLUSIVE");
    expect(seen).toEqual([]);
  });

  it("a skip group in attack-last.json falls back to the baseline group", async () => {
    const dir = projectWithRun("skip-fallback");
    sessionsWith(dir, ["carol", "dave"]);
    const last = path.join(dir, ".vibesafe", LAST_FILE);
    const run = JSON.parse(fs.readFileSync(last, "utf8")) as AttackRun;
    fs.writeFileSync(path.join(dir, ".vibesafe", "attack-baseline.json"), JSON.stringify(run));
    const g = run.groups[0];
    if (g) {
      g.requests = [];
      g.skip = { outcome: "INCONCLUSIVE", reason: "handler may write" };
    }
    fs.writeFileSync(last, JSON.stringify(run));
    seen.length = 0;
    const r = await replayAttack(
      { projectPath: dir, target: base, mode: "retest", rate: 100 },
      "ATK-0123456789ab",
    );
    expect(r.reasoning).not.toMatch(/may write/);
    expect(seen.some((u) => u.includes("secret_probe"))).toBe(true);
  });

  it("an unknown attack id is an exit-2 error", async () => {
    const dir = projectWithRun("unknown-id");
    const err = await replayAttack(
      { projectPath: dir, target: base, mode: "retest" },
      "ATK-ffffffffffff",
    ).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AttackPersistError);
    expect((err as AttackPersistError).exitCode).toBe(2);
  });
});
