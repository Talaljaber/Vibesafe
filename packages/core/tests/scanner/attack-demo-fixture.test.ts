import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
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

describe("attack-demo-app fixture: static findings", () => {
  it("emits the four expected findings", async () => {
    const findings = await scan(demoDir);
    const notes = idor(findings, NOTES);
    expect(notes.map((f) => f.line).sort()).toEqual(
      [lineOf(demoDir, NOTES, '.from("notes").select'), lineOf(demoDir, NOTES, ".update(")].sort(),
    );
    expect(idor(findings, INVOICES)).toHaveLength(1);
    expect(missingAuth(findings, ADMIN)).toHaveLength(1);
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
): Promise<{ child: ChildProcess; port: number; stdout: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [path.join(demoDir, "server.mjs"), "--port", "0", ...extraArgs],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    let stdout = "";
    const timer = setTimeout(() => reject(new Error("harness did not start")), 15000);
    child.stdout!.on("data", (c) => {
      stdout += String(c);
      const m = /^LISTENING (\d+)$/m.exec(stdout);
      if (m) {
        clearTimeout(timer);
        resolve({ child, port: Number(m[1]), stdout });
      }
    });
    child.on("error", reject);
  });
}

const ALICE = { cookie: "vs_session=alice-dev" };
const BOB = { cookie: "vs_session=bob-dev" };

describe("attack-demo-app harness", () => {
  const children: ChildProcess[] = [];
  let port = 0;
  let lineSeen = "";

  beforeAll(async () => {
    const h = await startHarness([]);
    children.push(h.child);
    port = h.port;
    lineSeen = h.stdout;
  });

  afterAll(() => {
    for (const c of children) c.kill();
  });

  afterEach(() => undefined);

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
    const leak = await request(h.port, "/api/notes/n_bob_1", { headers: ALICE });
    expect(JSON.parse(leak.body)).toBeNull();
    const own = await request(h.port, "/api/notes/n_bob_1", { headers: BOB });
    expect(JSON.parse(own.body).user_id).toBe("u_bob");
    expect((await request(h.port, "/api/admin/users")).status).toBe(401);
    expect((await request(h.port, "/api/admin/users", { headers: BOB })).status).toBe(403);
    expect((await request(h.port, "/api/admin/users", { headers: ALICE })).status).toBe(200);
    // Invoices are untouched by the overlay.
    expect((await request(h.port, "/api/invoices/inv_bob_1", { headers: ALICE })).status).toBe(404);
  });
});
