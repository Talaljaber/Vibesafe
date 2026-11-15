import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const repoRoot = path.resolve(import.meta.dirname, "..", "..", "..");
const read = (rel: string): string => fs.readFileSync(path.join(repoRoot, rel), "utf8");

const prewarm = (await import("../../../scripts/attack-prewarm.mjs")) as {
  checkTarget: (raw: string) => { ok: boolean; base?: string; reason?: string };
  discoverPaths: (root: string) => string[];
};

describe("scripts/attack-prewarm.mjs", () => {
  it("accepts loopback http targets only", () => {
    expect(prewarm.checkTarget("http://127.0.0.1:3000/x")).toEqual({
      ok: true,
      base: "http://127.0.0.1:3000",
    });
    expect(prewarm.checkTarget("http://[::1]:3001").ok).toBe(true);
    expect(prewarm.checkTarget("http://localhost:3000").ok).toBe(true);
    for (const bad of [
      "http://example.com",
      "http://192.168.1.10:3000",
      "https://127.0.0.1:3000",
      "http://127.0.0.1.nip.io:3000",
      "not a url",
    ]) {
      expect(prewarm.checkTarget(bad).ok, bad).toBe(false);
    }
  });

  it("discovers every demo route with the session resource ids", () => {
    const paths = prewarm.discoverPaths(path.join(repoRoot, "fixtures", "attack-demo-app"));
    expect(paths.sort()).toEqual([
      "/",
      "/api/admin/users",
      "/api/invoices/inv_alice_1",
      "/api/notes/n_alice_1",
    ]);
  });
});

describe("booth runbook", () => {
  it("names scripts and package scripts that exist", () => {
    const demo = read("DEMO.md");
    const pkg = JSON.parse(read("package.json")) as { scripts: Record<string, string> };
    for (const s of ["demo:smoke"]) {
      expect(demo, s).toContain(`pnpm ${s}`);
      expect(pkg.scripts[s], s).toBeDefined();
    }
    for (const f of ["scripts/attack-prewarm.mjs", "scripts/create-attack-demo.mjs"]) {
      expect(demo).toContain(f.replace("scripts/", ""));
      expect(fs.existsSync(path.join(repoRoot, f)), f).toBe(true);
    }
    for (const flag of ["--retest", "--open-report", "--replay", "--new-baseline"]) {
      expect(read("packages/cli/src/bin.ts"), flag).toContain(flag);
    }
    expect(demo).toContain("Fix the issues in .vibesafe/attack-report.md");
  });
});
