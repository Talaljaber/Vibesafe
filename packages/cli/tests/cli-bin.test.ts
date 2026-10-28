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

  // spawnSync gives the child a non-TTY stdin, so the wizard refuses to start.
  it("fix -i and fix -i <dir> route to the wizard (no TTY -> exit 1)", () => {
    for (const args of [["fix", "-i"], ["fix", "-i", FIXTURE]]) {
      const res = spawnSync(process.execPath, [BIN, ...args], { encoding: "utf-8" });
      expect(res.status).toBe(1);
      expect(res.stderr).toContain("interactive terminal");
    }
  }, 30000);

  it("fix -i <id> <dir> errors instead of treating the id as a directory", () => {
    const res = spawnSync(process.execPath, [BIN, "fix", "-i", "some-id", FIXTURE], { encoding: "utf-8" });
    expect(res.status).toBe(1);
    expect(res.stderr).toContain("--interactive takes an optional directory");
  }, 30000);

  it("fix rejects --all combined with --interactive", () => {
    const res = spawnSync(process.execPath, [BIN, "fix", "--all", "-i", FIXTURE], { encoding: "utf-8" });
    expect(res.status).toBe(1);
    expect(res.stderr).toContain("--all and --interactive cannot be used together");
  }, 30000);

  it("fix with no arguments errors with exit code 1", () => {
    const res = spawnSync(process.execPath, [BIN, "fix"], { encoding: "utf-8" });
    expect(res.status).toBe(1);
    expect(res.stderr).toContain("missing required argument 'finding-id'");
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

  const run = (args: string[]) =>
    spawnSync(process.execPath, [BIN, "scan", FIXTURE, ...args], { encoding: "utf-8", maxBuffer: 64 * 1024 * 1024 });

  it("--output alone implies json and keeps stdout empty", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vibesafe-out-"));
    try {
      const out = path.join(dir, "r.json");
      const res = run(["--output", out]);
      expect(res.stdout).toBe("");
      const parsed = JSON.parse(fs.readFileSync(out, "utf-8"));
      expect(parsed.findings.length).toBeGreaterThan(0);
      expect(parsed.version).toBeUndefined();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }, 30000);

  it("--format wins over --json", () => {
    const res = run(["--json", "--format", "sarif"]);
    expect(JSON.parse(res.stdout).version).toBe("2.1.0");
  }, 30000);

  it("--format=sarif suppresses the banner", () => {
    const res = run(["--format=sarif"]);
    expect(res.stdout.startsWith("{")).toBe(true);
    expect(JSON.parse(res.stdout).version).toBe("2.1.0");
  }, 30000);

  it("--format json prints ScanResult JSON", () => {
    const res = run(["--format", "json"]);
    expect(JSON.parse(res.stdout).findings.length).toBeGreaterThan(0);
  }, 30000);

  it("rejects an empty --output with exit code 2", () => {
    const res = run(["--output", ""]);
    expect(res.status).toBe(2);
    expect(res.stdout).toBe("");
    expect(res.stderr).toContain("--output");
  }, 30000);

  it("exits 2 with a clear message when the --output file cannot be written", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vibesafe-out-"));
    try {
      const res = run(["--format", "sarif", "--output", dir]); // a directory, not a file
      expect(res.status).toBe(2);
      expect(res.stderr).toContain("could not write report");
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
