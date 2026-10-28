import { describe, it, expect, beforeEach, afterEach } from "vitest";
import path from "node:path";
import fs from "node:fs";
import os from "node:os";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer, readServerVersion } from "../src/server.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE = path.resolve(__dirname, "../../../fixtures/nextjs-vibecoded-bad-app");

interface ToolResult {
  isError?: boolean;
  content: { type: string; text: string }[];
}

async function connect(): Promise<{ client: Client; close: () => Promise<void> }> {
  const server = await createServer();
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "0.0.0" });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return { client, close: () => client.close() };
}

async function call(client: Client, name: string, args: Record<string, unknown> = {}): Promise<ToolResult> {
  return (await client.callTool({ name, arguments: args })) as unknown as ToolResult;
}

function summaryOf(res: ToolResult): { topFindings: { id: string }[] } {
  return JSON.parse(res.content[1]!.text);
}

describe("MCP tool handlers", () => {
  let client: Client;
  let close: () => Promise<void>;

  beforeEach(async () => {
    ({ client, close } = await connect());
  });
  afterEach(async () => {
    await close();
  });

  it("reports the package.json version", () => {
    const pkg = JSON.parse(
      fs.readFileSync(path.resolve(__dirname, "../package.json"), "utf-8"),
    ) as { version: string };
    expect(readServerVersion()).toBe(pkg.version);
    expect(client.getServerVersion()?.version).toBe(pkg.version);
  });

  it("advertises the deep option on vibesafe_scan", async () => {
    const { tools } = await client.listTools();
    const scan = tools.find((t) => t.name === "vibesafe_scan");
    const props = (scan?.inputSchema as { properties?: Record<string, unknown> }).properties ?? {};
    expect(props).toHaveProperty("deep");
  });

  describe("without a prior scan", () => {
    it("explain, repair_plan and fix return an error", async () => {
      for (const [name, args] of [
        ["vibesafe_explain", { findingId: "X" }],
        ["vibesafe_repair_plan", {}],
        ["vibesafe_fix", { findingId: "X" }],
      ] as const) {
        const res = await call(client, name, args);
        expect(res.isError).toBe(true);
        expect(res.content[0]!.text).toContain("vibesafe_scan");
      }
    });
  });

  describe("after a scan", () => {
    let findings: { id: string }[];

    beforeEach(async () => {
      const res = await call(client, "vibesafe_scan", { path: FIXTURE });
      expect(res.isError).toBeFalsy();
      findings = summaryOf(res).topFindings;
      expect(findings.length).toBeGreaterThan(0);
    });

    it("scan accepts deep: true", async () => {
      const res = await call(client, "vibesafe_scan", { path: FIXTURE, deep: true });
      expect(res.isError).toBeFalsy();
    });

    it("explain returns detail for a known id and errors for an unknown id", async () => {
      const ok = await call(client, "vibesafe_explain", { findingId: findings[0]!.id });
      expect(ok.isError).toBeFalsy();
      expect(ok.content[0]!.text).toContain("Fix steps");

      const bad = await call(client, "vibesafe_explain", { findingId: "NOPE-000" });
      expect(bad.isError).toBe(true);
      expect(bad.content[0]!.text).toContain("Unknown finding ID");
    });

    it("repair_plan returns the plan", async () => {
      const res = await call(client, "vibesafe_repair_plan");
      expect(res.isError).toBeFalsy();
      expect(JSON.parse(res.content[1]!.text).steps.length).toBeGreaterThan(0);
    });

    it("fix errors for an unknown id", async () => {
      const res = await call(client, "vibesafe_fix", { findingId: "NOPE-000" });
      expect(res.isError).toBe(true);
      expect(res.content[0]!.text).toContain("Unknown finding ID");
    });

    async function findByAutoFix(want: boolean): Promise<string | undefined> {
      for (const f of findings) {
        const res = await call(client, "vibesafe_explain", { findingId: f.id });
        const detail = JSON.parse(res.content[1]!.text) as { autoFixAvailable: boolean };
        if (detail.autoFixAvailable === want) return f.id;
      }
      return undefined;
    }

    it("fix defaults to a dry run and leaves files untouched", async () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vibesafe-mcp-fix-"));
      try {
        fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "x" }));
        fs.writeFileSync(path.join(dir, ".env"), "FOO=bar\n");
        const scan = await call(client, "vibesafe_scan", { path: dir });
        const ids = summaryOf(scan).topFindings.map((f) => f.id);
        let fixable: string | undefined;
        for (const id of ids) {
          const d = await call(client, "vibesafe_explain", { findingId: id });
          if ((JSON.parse(d.content[1]!.text) as { autoFixAvailable: boolean }).autoFixAvailable) {
            fixable = id;
            break;
          }
        }
        expect(fixable).toBeDefined();
        const res = await call(client, "vibesafe_fix", { findingId: fixable! });
        expect(res.isError).toBeFalsy();
        expect(res.content[0]!.text).toContain("Dry run");
        expect(fs.existsSync(path.join(dir, ".gitignore"))).toBe(false);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    it("fix errors when no auto-fix is available", async () => {
      const manual = await findByAutoFix(false);
      expect(manual).toBeDefined();
      const res = await call(client, "vibesafe_fix", { findingId: manual!, dryRun: false });
      expect(res.isError).toBe(true);
      expect(res.content[0]!.text).toContain("No auto-fix is available");
    });
  });
});
