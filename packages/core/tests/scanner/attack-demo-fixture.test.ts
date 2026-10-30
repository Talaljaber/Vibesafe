import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { spawn, type ChildProcess } from "node:child_process";
import { fileURLToPath } from "node:url";
import { ScannerPipeline } from "../../src/scanner/pipeline.js";
import { createDefaultRegistry } from "../../src/scanner/detector-registry.js";
import type { Finding } from "@talaljaber/vibesafe-shared";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.resolve(here, "../../../../fixtures");
const demoDir = path.join(fixturesDir, "attack-demo-app");
const fixedDir = path.join(fixturesDir, "attack-demo-app-fixed");

const NOTES = "app/api/notes/[id]/route.js";
const INVOICES = "app/api/invoices/[id]/route.js";
const ADMIN = "app/api/admin/users/route.js";

async function scan(root: string): Promise<Finding[]> {
  const result = await new ScannerPipeline(createDefaultRegistry()).scan({ rootPath: root });
  return result.findings;
}

function lineOf(root: string, rel: string, needle: string): number {
  const lines = fs.readFileSync(path.join(root, rel), "utf-8").split(/\r?\n/);
  return lines.findIndex((l) => l.includes(needle)) + 1;
}

const idor = (fs_: Finding[], file: string): Finding[] =>
  fs_.filter((f) => f.ruleId === "authorization/idor-unscoped-lookup" && f.file === file);
const missingAuth = (fs_: Finding[], file: string): Finding[] =>
  fs_.filter((f) => f.ruleId === "auth/missing-route-auth" && f.file === file);

const ledger = (fs_: Finding[]): Finding[] =>
  fs_.filter(
    (f) =>
      f.ruleId === "authorization/idor-unscoped-lookup" || f.ruleId === "auth/missing-route-auth",
  );

describe("attack-demo-app fixture: static findings", () => {
  it("emits the four expected findings", async () => {
    const findings = await scan(demoDir);
    const notes = idor(findings, NOTES);
    expect(notes.map((f) => f.line).sort((a, b) => a - b)).toEqual(
      [lineOf(demoDir, NOTES, '.from("notes").select'), lineOf(demoDir, NOTES, ".update(")].sort(
        (a, b) => a - b,
      ),
    );
    const byLine = (n: number) => notes.find((f) => f.line === n)!;
    expect(byLine(lineOf(demoDir, NOTES, '.from("notes").select')).plainEnglishProblem).toMatch(
      /^This handler reads/,
    );
    expect(byLine(lineOf(demoDir, NOTES, ".update(")).plainEnglishProblem).toMatch(
      /^This handler changes/,
    );
    expect(idor(findings, INVOICES)[0]!.plainEnglishProblem).toMatch(/^This handler reads/);
    expect(idor(findings, INVOICES)).toHaveLength(1);
    expect(missingAuth(findings, ADMIN)).toHaveLength(1);
    expect(ledger(findings)).toHaveLength(4);
  });

  it("package.json has no BOM and the scan detects nextjs", async () => {
    const raw = fs.readFileSync(path.join(demoDir, "package.json"));
    expect(raw[0]).toBe(0x7b);
    const result = await new ScannerPipeline(createDefaultRegistry()).scan({ rootPath: demoDir });
    expect(result.projectContext.framework).toBe("nextjs");
  });

  it("ships a sessions file matching the SessionsFile shape", () => {
    const f = JSON.parse(
      fs.readFileSync(path.join(demoDir, ".vibesafe", "sessions.json"), "utf-8"),
    ) as {
      schemaVersion: number;
      sessions: { label: string; headers: object; resources: object }[];
    };
    expect(f.schemaVersion).toBe(1);
    expect(f.sessions.map((s) => s.label)).toEqual(["alice", "bob"]);
    for (const s of f.sessions) {
      expect(s.headers).toBeTypeOf("object");
      expect(s.resources).toBeTypeOf("object");
    }
  });

  it("with the overlay merged only the invoices idor remains of those four", async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vs-attack-fixed-"));
    try {
      fs.cpSync(demoDir, tmp, { recursive: true });
      fs.cpSync(fixedDir, tmp, { recursive: true });
      const findings = await scan(tmp);
      expect(idor(findings, NOTES)).toHaveLength(0);
      expect(missingAuth(findings, ADMIN)).toHaveLength(0);
      expect(idor(findings, INVOICES)).toHaveLength(1);
      expect(ledger(findings)).toHaveLength(1);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

interface Res {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
}

function request(
  port: number,
  rawPath: string,
  opts: { method?: string; headers?: Record<string, string>; body?: string } = {},
): Promise<Res> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        path: rawPath,
        method: opts.method ?? "GET",
        headers: opts.headers ?? {},
      },
      (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
      },
    );
    req.on("error", reject);
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

function startHarness(
  extraArgs: string[],
): Promise<{ child: ChildProcess; port: number; stdout: string; merged: string | undefined }> {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [path.join(demoDir, "server.mjs"), "--port", "0", ...extraArgs],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    let stdout = "";
    let stderr = "";
    const fail = (e: Error) => {
      clearTimeout(timer);
      child.kill();
      reject(e);
    };
    const timer = setTimeout(() => fail(new Error(`harness did not start: ${stderr}`)), 15000);
    child.stderr!.on("data", (c) => (stderr += String(c)));
    child.on("exit", (code) => fail(new Error(`harness exited ${code}: ${stderr}`)));
    child.stdout!.on("data", (c) => {
      stdout += String(c);
      const m = /^LISTENING (\d+)$/m.exec(stdout);
      if (m) {
        clearTimeout(timer);
        child.removeAllListeners("exit");
        resolve({
          child,
          port: Number(m[1]),
          stdout,
          merged: /^MERGED (.+)$/m.exec(stdout)?.[1]?.trim(),
        });
      }
    });
    child.on("error", fail);
  });
}

const ALICE = { cookie: "vs_session=alice-dev" };
const BOB = { cookie: "vs_session=bob-dev" };

describe("attack-demo-app harness", () => {
  const children: ChildProcess[] = [];
  const mergedDirs: string[] = [];
  let port = 0;
  let lineSeen = "";

  beforeAll(async () => {
    const h = await startHarness([]);
    children.push(h.child);
    port = h.port;
    lineSeen = h.stdout;
  });

  afterAll(async () => {
    await Promise.all(
      children.map(
        (c) =>
          new Promise<void>((res) => {
            if (c.exitCode !== null) return res();
            const t = setTimeout(res, 3000);
            c.once("exit", () => (clearTimeout(t), res()));
            c.kill();
          }),
      ),
    );
    for (const d of mergedDirs) {
      fs.rmSync(d, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  it("prints LISTENING <port>", () => {
    expect(lineSeen).toMatch(/^LISTENING \d+$/m);
    expect(port).toBeGreaterThan(0);
  });

  it("serves routes with the harness header", async () => {
    const res = await request(port, "/api/notes/n_bob_1", { headers: ALICE });
    expect(res.headers["x-vibesafe-harness"]).toBe("1");
    expect(res.status).toBe(200);
    // The IDOR: alice reads bob's note.
    expect(JSON.parse(res.body).user_id).toBe("u_bob");
  });

  it("requires a session on notes and returns 401 without one", async () => {
    expect((await request(port, "/api/notes/n_bob_1")).status).toBe(401);
  });

  it("invoices refuse the other user with 404 and serve the owner", async () => {
    expect((await request(port, "/api/invoices/inv_bob_1", { headers: ALICE })).status).toBe(404);
    expect((await request(port, "/api/invoices/inv_bob_1", { headers: BOB })).status).toBe(200);
  });

  it("serves admin users without auth", async () => {
    const res = await request(port, "/api/admin/users");
    expect(res.status).toBe(200);
    expect(res.body).toContain("alice@example.test");
  });

  it("returns 405 for an unexported method", async () => {
    const res = await request(port, "/api/admin/users", { method: "DELETE" });
    expect(res.status).toBe(405);
    expect(res.headers["x-vibesafe-harness"]).toBe("1");
  });

  it("serves public/.env (dotfile) statically", async () => {
    const res = await request(port, "/.env");
    expect(res.status).toBe(200);
    expect(res.body).toContain("DEMO_API_KEY=vs_demo_not_a_real_key");
    expect(res.headers["x-vibesafe-harness"]).toBe("1");
  });

  it("returns 404 JSON for unknown paths", async () => {
    const res = await request(port, "/nope");
    expect(res.status).toBe(404);
    expect(JSON.parse(res.body)).toEqual({ error: "not found" });
    expect(res.headers["x-vibesafe-harness"]).toBe("1");
  });

  it("rejects .. traversal, plain and encoded", async () => {
    for (const p of ["/../server.mjs", "/%2e%2e/server.mjs", "/..%2fserver.mjs"]) {
      const res = await request(port, p);
      expect(res.status).toBeGreaterThanOrEqual(400);
      expect(res.body).not.toContain("createServer");
    }
  });

  it("with --overlay serves the fixed routes", async () => {
    const h = await startHarness(["--overlay", fixedDir]);
    children.push(h.child);
    if (h.merged) mergedDirs.push(h.merged);
    const leak = await request(h.port, "/api/notes/n_bob_1", { headers: ALICE });
    expect(leak.status).toBe(404);
    const own = await request(h.port, "/api/notes/n_bob_1", { headers: BOB });
    expect(JSON.parse(own.body).user_id).toBe("u_bob");
    expect((await request(h.port, "/api/admin/users")).status).toBe(401);
    expect((await request(h.port, "/api/admin/users", { headers: BOB })).status).toBe(403);
    expect((await request(h.port, "/api/admin/users", { headers: ALICE })).status).toBe(200);
    // Invoices are untouched by the overlay.
    expect((await request(h.port, "/api/invoices/inv_bob_1", { headers: ALICE })).status).toBe(404);
  });
});
