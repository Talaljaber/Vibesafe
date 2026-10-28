import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { ScannerPipeline } from "../../src/scanner/pipeline.js";
import { DetectorRegistry } from "../../src/scanner/detector-registry.js";
import { FileDiscovery } from "../../src/scanner/file-discovery.js";
import { isDeployBlocker, MAX_FILE_SIZE_BYTES } from "@vibesafe/shared";
import type { Detector, Finding, Severity } from "@vibesafe/shared";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "QUAL-x",
    ruleId: "mock/rule",
    title: "Mock",
    severity: "low",
    category: "code_quality",
    deployBlocking: false,
    confidence: "high",
    plainEnglishProblem: "p",
    whyItMatters: "w",
    fixSteps: ["f"],
    autoFixAvailable: false,
    ...overrides,
  };
}

function mockDetector(
  id: string,
  findings: Finding[],
  delayMs = 0,
): Detector {
  return {
    id,
    name: id,
    category: "code_quality",
    description: id,
    detect: async () => {
      if (delayMs) await new Promise((r) => setTimeout(r, delayMs));
      return findings;
    },
  };
}

async function writeFiles(root: string, files: Record<string, string>): Promise<void> {
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(root, rel);
    await fs.mkdir(path.dirname(abs), { recursive: true });
    await fs.writeFile(abs, content);
  }
}

describe("scan engine (#42)", () => {
  let tmp: string;
  beforeEach(async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), "vibesafe-engine-"));
  });
  afterEach(async () => {
    await fs.rm(tmp, { recursive: true, force: true });
  });

  it("enforces timeoutMs between detectors and keeps partial findings", async () => {
    const registry = new DetectorRegistry();
    registry.register(mockDetector("slow", [makeFinding({ id: "A" })], 60));
    registry.register(mockDetector("never-runs", [makeFinding({ id: "B" })]));
    await writeFiles(tmp, { "a.ts": "x\n" });

    const result = await new ScannerPipeline(registry).scan({ rootPath: tmp, timeoutMs: 10 });

    expect(result.findings.map((f) => f.id)).toEqual(["A"]);
    expect(result.errors?.some((e) => e.detectorId === "scan-timeout")).toBe(true);
    expect(result.warnings?.some((w) => /timed out/i.test(w))).toBe(true);
  });

  it("populates linesScanned from files actually read", async () => {
    await writeFiles(tmp, { "a.ts": "1\n2\n3\n", "b.ts": "one\ntwo" });
    const registry = new DetectorRegistry();
    registry.register({
      id: "reader",
      name: "reader",
      category: "code_quality",
      description: "reads files",
      detect: async (ctx) => {
        for (const f of ctx.files) await ctx.readFile(f);
        return [];
      },
    });
    const result = await new ScannerPipeline(registry).scan({ rootPath: tmp });
    expect(result.summary.filesScanned).toBe(2);
    expect(result.summary.linesScanned).toBe(5);
  });

  it("warns when maxFiles truncates the file list", async () => {
    await writeFiles(tmp, { "a.ts": "1", "b.ts": "2", "c.ts": "3" });
    const result = await new ScannerPipeline(new DetectorRegistry()).scan({
      rootPath: tmp,
      maxFiles: 2,
    });
    expect(result.summary.filesScanned).toBe(2);
    expect(result.warnings?.some((w) => w.includes("maxFiles"))).toBe(true);
  });

  it("computes the score before the minSeverity filter", async () => {
    await writeFiles(tmp, { "a.ts": "1" });
    const registry = new DetectorRegistry();
    registry.register(
      mockDetector("high", [makeFinding({ id: "H", severity: "high", category: "validation" })]),
    );
    const unfiltered = await new ScannerPipeline(registry).scan({ rootPath: tmp });
    const filtered = await new ScannerPipeline(registry).scan({
      rootPath: tmp,
      minSeverity: "critical",
    });
    expect(filtered.findings).toHaveLength(0);
    expect(filtered.score).toBe(unfiltered.score);
    expect(filtered.score).toBe(90);
  });

  it("treats deployBlocking findings as blockers even when not critical", async () => {
    await writeFiles(tmp, { "a.ts": "1" });
    const registry = new DetectorRegistry();
    registry.register(
      mockDetector("blocking", [makeFinding({ severity: "low", deployBlocking: true })]),
    );
    const result = await new ScannerPipeline(registry).scan({ rootPath: tmp });
    expect(result.deployStatus).toBe("blocker");

    const registry2 = new DetectorRegistry();
    registry2.register(mockDetector("plain", [makeFinding({ severity: "low" })]));
    const result2 = await new ScannerPipeline(registry2).scan({ rootPath: tmp });
    expect(result2.deployStatus).toBe("safe");
  });

  it("isDeployBlocker covers critical and deployBlocking", () => {
    const sev = (severity: Severity, deployBlocking: boolean) => ({ severity, deployBlocking });
    expect(isDeployBlocker(sev("critical", false))).toBe(true);
    expect(isDeployBlocker(sev("medium", true))).toBe(true);
    expect(isDeployBlocker(sev("high", false))).toBe(false);
  });

  it("skips files over the size cap and warns", async () => {
    await writeFiles(tmp, {
      "big.ts": "a".repeat(MAX_FILE_SIZE_BYTES + 1),
      "small.ts": "ok\n",
    });
    const seen: Record<string, number> = {};
    const registry = new DetectorRegistry();
    registry.register({
      id: "reader",
      name: "reader",
      category: "code_quality",
      description: "reads files",
      detect: async (ctx) => {
        for (const f of ctx.files) seen[f] = (await ctx.readFile(f)).length;
        return [];
      },
    });
    const result = await new ScannerPipeline(registry).scan({ rootPath: tmp });
    expect(seen["big.ts"]).toBe(0);
    expect(seen["small.ts"]).toBe(3);
    expect(result.warnings?.some((w) => w.includes("big.ts"))).toBe(true);
  });
});

describe("FileDiscovery scoping (#42)", () => {
  let tmp: string;
  beforeEach(async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), "vibesafe-disc-"));
  });
  afterEach(async () => {
    await fs.rm(tmp, { recursive: true, force: true });
  });

  it("excludes build dirs at root and workspace-package root only", async () => {
    await writeFiles(tmp, {
      "build/a.ts": "x",
      "dist/a.ts": "x",
      "packages/web/dist/a.ts": "x",
      "packages/web/src/ok.ts": "x",
      "src/build/keep.ts": "x",
      "src/out/keep.ts": "x",
      "src/tmp/keep.ts": "x",
      "node_modules/m/i.ts": "x",
      "packages/web/node_modules/m/i.ts": "x",
      "src/deep/node_modules/m/i.ts": "x",
    });
    const files = (await new FileDiscovery(tmp).discoverFiles()).sort();
    expect(files).toEqual(
      ["packages/web/src/ok.ts", "src/build/keep.ts", "src/out/keep.ts", "src/tmp/keep.ts"].sort(),
    );
  });

  it("supports nested .gitignore files scoped to their directory", async () => {
    await writeFiles(tmp, {
      ".gitignore": "root-ignored.ts\n",
      "root-ignored.ts": "x",
      "keep.ts": "x",
      "pkg/.gitignore": "generated.ts\nsub/\n",
      "pkg/generated.ts": "x",
      "pkg/sub/a.ts": "x",
      "pkg/real.ts": "x",
      "generated.ts": "x", // not ignored: pkg/.gitignore only scopes to pkg/
    });
    const files = (await new FileDiscovery(tmp).discoverFiles()).sort();
    expect(files).toContain("keep.ts");
    expect(files).toContain("generated.ts");
    expect(files).toContain("pkg/real.ts");
    expect(files).not.toContain("root-ignored.ts");
    expect(files).not.toContain("pkg/generated.ts");
    expect(files).not.toContain("pkg/sub/a.ts");
  });

  it("does not follow or return symbolic links", async (ctx) => {
    await writeFiles(tmp, { "real/a.ts": "x", "outside/secret.ts": "x" });
    try {
      await fs.symlink(path.join(tmp, "outside"), path.join(tmp, "linked-dir"), "junction");
      await fs.symlink(path.join(tmp, "outside", "secret.ts"), path.join(tmp, "linked.ts"), "file");
    } catch {
      ctx.skip(); // symlinks not permitted in this environment
      return;
    }
    const root = path.join(tmp, "real");
    await fs.symlink(path.join(tmp, "outside"), path.join(root, "escape"), "junction");
    const files = await new FileDiscovery(root).discoverFiles();
    expect(files).toEqual(["a.ts"]);

    const all = await new FileDiscovery(tmp).discoverFiles();
    expect(all).not.toContain("linked.ts");
    expect(all.some((f) => f.startsWith("linked-dir/"))).toBe(false);
  });
});
