import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Requires `pnpm build` (dist/bin.js).
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(__dirname, "../dist/bin.js");
const FIXTURE = path.resolve(__dirname, "../../../fixtures/nextjs-vibecoded-bad-app");

describe("vibesafe CLI (built binary)", () => {
  it("scan --json prints pure parseable JSON and exits 1 on the bad fixture", () => {
    const res = spawnSync(process.execPath, [BIN, "scan", FIXTURE, "--json"], {
      encoding: "utf-8",
      maxBuffer: 64 * 1024 * 1024,
    });
    expect(res.status).toBe(1);
    // eslint-disable-next-line no-control-regex
    expect(res.stdout).not.toMatch(/\u001b\[/);
    const parsed = JSON.parse(res.stdout);
    expect(["blocker", "danger"]).toContain(parsed.deployStatus);
    expect(parsed.findings.length).toBeGreaterThan(0);
  }, 30000);
});
