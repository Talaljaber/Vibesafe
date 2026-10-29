import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { FileDiscovery } from "../../src/scanner/file-discovery.js";
import { ScannerPipeline } from "../../src/scanner/pipeline.js";
import { DetectorRegistry, createDefaultRegistry } from "../../src/scanner/detector-registry.js";

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

describe("onTestFile and testFiles (placeholder tests in default mode)", () => {
  let tmp: string;
  const put = async (rel: string, body = "x"): Promise<void> => {
    await fs.mkdir(path.dirname(path.join(tmp, rel)), { recursive: true });
    await fs.writeFile(path.join(tmp, rel), body);
  };
  beforeEach(async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), "vibesafe-tf-"));
    await put("src/app.ts");
    await put("src/a.test.ts");
    await put("__tests__/b.js");
    await put("fixtures/x.test.ts");
    await put("tmp/c.test.ts");
    await put("node_modules/pkg/d.test.js");
    await put("tests/helper.ts");
    await put(".gitignore", "tmp/\n");
  });
  afterEach(async () => {
    await fs.rm(tmp, { recursive: true, force: true });
  });

  it("reports only real, non-ignored test files and leaves the file list alone", async () => {
    const seen: string[] = [];
    const files = await new FileDiscovery(tmp).discoverFiles([], {
      onTestFile: (f) => seen.push(f),
    });
    expect(seen.sort()).toEqual(["__tests__/b.js", "src/a.test.ts"]);
    for (const s of seen) expect(files).not.toContain(s);
    expect(files).not.toContain("tests/helper.ts");
  });

  it("is never called with includeTests", async () => {
    const seen: string[] = [];
    await new FileDiscovery(tmp).discoverFiles([], {
      includeTests: true,
      onTestFile: (f) => seen.push(f),
    });
    expect(seen).toEqual([]);
  });

  it("pipeline flags a todo-only test file in default mode, from that detector alone", async () => {
    await put("tests/app.test.ts", `import { it } from "vitest";\nit.todo("x");\n`);
    const result = await new ScannerPipeline(createDefaultRegistry()).scan({ rootPath: tmp });
    const onFile = result.findings.filter((f) => f.file === "tests/app.test.ts");
    expect(onFile.length).toBeGreaterThan(0);
    expect(onFile.every((f) => f.ruleId === "structure/placeholder-only-tests")).toBe(true);
    expect(onFile[0]?.line).toBe(2);
  });

  it("emits no test-file findings with targetFiles", async () => {
    await put("tests/app.test.ts", `it.todo("x");\n`);
    const result = await new ScannerPipeline(createDefaultRegistry()).scan({
      rootPath: tmp,
      targetFiles: ["src/app.ts"],
    });
    expect(result.findings.filter((f) => f.file === "tests/app.test.ts")).toEqual([]);
  });
});
