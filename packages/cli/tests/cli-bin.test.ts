import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
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

describe("vibesafe CLI --format / --output", () => {
  it("scan --format sarif prints pure SARIF JSON on stdout", () => {
    const res = spawnSync(process.execPath, [BIN, "scan", FIXTURE, "--format", "sarif"], {
      encoding: "utf-8",
      maxBuffer: 64 * 1024 * 1024,
    });
    expect(res.status).toBe(1);
    const parsed = JSON.parse(res.stdout);
    expect(parsed.version).toBe("2.1.0");
    expect(parsed.runs[0].tool.driver.name).toBe("VibeSafe");
    expect(parsed.runs[0].results.length).toBeGreaterThan(0);
    for (const r of parsed.runs[0].results) {
      expect(r.locations?.[0]?.physicalLocation.artifactLocation.uri ?? "").not.toContain("\\");
    }
  }, 30000);

  it("scan --format sarif --output writes the file and keeps stdout empty", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vibesafe-sarif-"));
    try {
      const out = path.join(dir, "nested", "r.sarif");
      const res = spawnSync(process.execPath, [BIN, "scan", FIXTURE, "--format", "sarif", "--output", out], {
        encoding: "utf-8",
        maxBuffer: 64 * 1024 * 1024,
      });
      expect(res.status).toBe(1);
      expect(res.stdout).toBe("");
      expect(JSON.parse(fs.readFileSync(out, "utf-8")).version).toBe("2.1.0");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }, 30000);

  it("rejects an unknown --format with exit code 2", () => {
    const res = spawnSync(process.execPath, [BIN, "scan", FIXTURE, "--format", "xml"], { encoding: "utf-8" });
    expect(res.status).toBe(2);
    expect(res.stdout).toBe("");
    expect(res.stderr).toContain("unknown --format");
  }, 30000);
});
