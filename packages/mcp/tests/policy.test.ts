import { describe, it, expect, afterEach } from "vitest";
import path from "node:path";
import fs from "node:fs";
import os from "node:os";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer } from "../src/server.js";
import { isPathAllowed, resolvePolicy, type ServerPolicy } from "../src/policy.js";

interface ToolResult {
  isError?: boolean;
  content: { type: string; text: string }[];
}

const cleanups: (() => void | Promise<void>)[] = [];

afterEach(async () => {
  while (cleanups.length) await cleanups.pop()!();
});

function tmp(prefix: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  cleanups.push(() => fs.rmSync(dir, { recursive: true, force: true }));
  return fs.realpathSync(dir);
}

async function connect(policy: ServerPolicy): Promise<Client> {
  const server = await createServer(policy);
  const [ct, st] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "t", version: "0.0.0" });
  await Promise.all([server.connect(st), client.connect(ct)]);
  cleanups.push(() => client.close());
  return client;
}

async function call(client: Client, name: string, args: Record<string, unknown>): Promise<ToolResult> {
  return (await client.callTool({ name, arguments: args })) as unknown as ToolResult;
}

function makeProject(): string {
  const dir = tmp("vibesafe-mcp-proj-");
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "x" }));
  fs.writeFileSync(path.join(dir, ".env"), "FOO=bar\n");
  return dir;
}

async function fixableId(client: Client, dir: string): Promise<string> {
  const scan = await call(client, "vibesafe_scan", { path: dir });
  expect(scan.isError).toBeFalsy();
  const ids = (JSON.parse(scan.content[1]!.text) as { topFindings: { id: string }[] }).topFindings.map(
    (f) => f.id,
  );
  for (const id of ids) {
    const d = await call(client, "vibesafe_explain", { findingId: id });
    if ((JSON.parse(d.content[1]!.text) as { autoFixAvailable: boolean }).autoFixAvailable) return id;
  }
  throw new Error("no fixable finding in test project");
}

describe("resolvePolicy", () => {
  it("defaults to the cwd with writes disabled", () => {
    const p = resolvePolicy([], {}, "/work");
    expect(p.roots).toEqual([path.resolve("/work")]);
    expect(p.allowFix).toBe(false);
  });

  it("reads roots from argv and VIBESAFE_MCP_ROOTS, and allow-fix from flag or env", () => {
    const env = { VIBESAFE_MCP_ROOTS: ["/a", "/b"].join(path.delimiter) };
    const p = resolvePolicy(["--root", "/c", "--root=/d", "--allow-fix"], env, "/work");
    expect(p.roots).toEqual(["/c", "/d", "/a", "/b"].map((r) => path.resolve(r)));
    expect(p.allowFix).toBe(true);
    expect(resolvePolicy([], { VIBESAFE_MCP_ALLOW_FIX: "1" }, "/work").allowFix).toBe(true);
    expect(resolvePolicy([], { VIBESAFE_MCP_ALLOW_FIX: "0" }, "/work").allowFix).toBe(false);
  });
});

describe("scan roots", () => {
  it("isPathAllowed accepts the root and subpaths, rejects siblings and parents", () => {
    const root = tmp("vibesafe-mcp-root-");
    const sub = path.join(root, "sub");
    fs.mkdirSync(sub);
    const policy = { roots: [root], allowFix: false };
    expect(isPathAllowed(policy, root)).toBe(true);
    expect(isPathAllowed(policy, sub)).toBe(true);
    expect(isPathAllowed(policy, path.dirname(root))).toBe(false);
    expect(isPathAllowed(policy, path.join(root, "..", "elsewhere"))).toBe(false);
  });

  it("vibesafe_scan rejects paths outside the allowed roots", async () => {
    const allowed = makeProject();
    const outside = makeProject();
    const client = await connect({ roots: [allowed], allowFix: false });

    const bad = await call(client, "vibesafe_scan", { path: outside });
    expect(bad.isError).toBe(true);
    expect(bad.content[0]!.text).toContain("outside the allowed scan roots");

    const traversal = await call(client, "vibesafe_scan", {
      path: path.join(allowed, "..", path.basename(outside)),
    });
    expect(traversal.isError).toBe(true);

    const ok = await call(client, "vibesafe_scan", { path: allowed });
    expect(ok.isError).toBeFalsy();
  });

  it("rejects a symlink inside the root that points outside it", async () => {
    const allowed = tmp("vibesafe-mcp-allowed-");
    const outside = makeProject();
    const link = path.join(allowed, "link");
    try {
      fs.symlinkSync(outside, link, "junction");
    } catch {
      return; // symlinks not permitted on this machine
    }
    const client = await connect({ roots: [allowed], allowFix: false });
    const res = await call(client, "vibesafe_scan", { path: link });
    expect(res.isError).toBe(true);
  });
});

describe("opt-in writes", () => {
  it("dryRun:false returns a preview and does not write unless allowFix is set", async () => {
    const dir = makeProject();
    const client = await connect({ roots: [dir], allowFix: false });
    const id = await fixableId(client, dir);

    const res = await call(client, "vibesafe_fix", { findingId: id, dryRun: false });
    expect(res.isError).toBeFalsy();
    expect(res.content[0]!.text).toContain("Not applied");
    expect(res.content[0]!.text).toContain("--allow-fix");
    expect(fs.existsSync(path.join(dir, ".gitignore"))).toBe(false);
  });

  it("dryRun:false applies the fix when allowFix is set", async () => {
    const dir = makeProject();
    const client = await connect({ roots: [dir], allowFix: true });
    const id = await fixableId(client, dir);

    const res = await call(client, "vibesafe_fix", { findingId: id, dryRun: false });
    expect(res.isError).toBeFalsy();
    expect(res.content[0]!.text).toContain("Fix applied");
    expect(fs.existsSync(path.join(dir, ".gitignore"))).toBe(true);
  });
});

describe("tool descriptions", () => {
  it("warn that output contains untrusted repository text", async () => {
    const client = await connect({ roots: [os.tmpdir()], allowFix: false });
    const { tools } = await client.listTools();
    for (const t of tools) {
      expect(t.description ?? "").toMatch(/untrusted/i);
    }
  });
});
