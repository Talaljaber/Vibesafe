import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { FileDiscovery } from "../../src/scanner/file-discovery.js";
import { ScannerPipeline } from "../../src/scanner/pipeline.js";
import { DetectorRegistry } from "../../src/scanner/detector-registry.js";

const FILES = [
  "src/app.ts",
  "src/app.test.ts",
  "src/app.spec.tsx",
  "src/__tests__/a.ts",
  "tests/b.ts",
  "packages/x/tests/c.ts",
  "fixtures/bad-app/d.ts",
  "src/fixtures/keep.ts", // only root-level fixtures/ is excluded
];

describe("default test/fixture exclusion (#41)", () => {
  let tmp: string;
  beforeEach(async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), "vibesafe-tests-"));
    for (const rel of FILES) {
      await fs.mkdir(path.dirname(path.join(tmp, rel)), { recursive: true });
      await fs.writeFile(path.join(tmp, rel), "x");
    }
  });
  afterEach(async () => {
    await fs.rm(tmp, { recursive: true, force: true });
  });

  it("excludes test and fixture paths by default", async () => {
    const files = (await new FileDiscovery(tmp).discoverFiles()).sort();
    expect(files).toEqual(["src/app.ts", "src/fixtures/keep.ts"]);
  });

  it("includes them with includeTests", async () => {
    const files = await new FileDiscovery(tmp).discoverFiles([], { includeTests: true });
    expect(files.sort()).toEqual([...FILES].sort());
  });

  it("pipeline honours ScanConfig.includeTests", async () => {
    const pipeline = new ScannerPipeline(new DetectorRegistry());
    const def = await pipeline.scan({ rootPath: tmp });
    const all = await pipeline.scan({ rootPath: tmp, includeTests: true });
    expect(def.summary.filesScanned).toBe(2);
    expect(all.summary.filesScanned).toBe(FILES.length);
  });

  it("paths are relative to rootPath, so scanning a fixtures dir directly still works", async () => {
    const files = await new FileDiscovery(path.join(tmp, "fixtures", "bad-app")).discoverFiles();
    expect(files).toEqual(["d.ts"]);
  });
});
