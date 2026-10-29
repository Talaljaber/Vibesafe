import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  MAX_FILE_SIZE_BYTES,
  MAX_LOCKFILE_SIZE_BYTES,
  type Detector,
  type Finding,
  type ScanConfig,
  type ScanContext,
} from "@talaljaber/vibesafe-shared";
import { DetectorRegistry } from "../../src/scanner/detector-registry.js";
import { ScannerPipeline } from "../../src/scanner/pipeline.js";
import { validateUserConfig } from "../../src/config/schema.js";

class WarningDetector implements Detector {
  id = "warning-detector";
  name = "Warning";
  category = "dependency" as const;
  description = "Adds warnings";
  async detect(context: ScanContext): Promise<Finding[]> {
    context.addWarning?.("Lockfile could not be parsed; dependency checks are partial.");
    context.addWarning?.("Lockfile could not be parsed; dependency checks are partial.");
    context.addWarning?.("Second notice.");
    return [];
  }
}

class ReadSizesDetector implements Detector {
  id = "read-sizes-detector";
  name = "Read sizes";
  category = "dependency" as const;
  description = "Records the length of each file it reads";
  sizes: Record<string, number> = {};
  async detect(context: ScanContext): Promise<Finding[]> {
    for (const f of context.files)
      this.sizes[f.replace(/\\/g, "/")] = (await context.readFile(f)).length;
    return [];
  }
}

describe("pipeline plumbing", () => {
  let root: string;

  beforeAll(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), "vibesafe-plumb-"));
    const big = (n: number) => "x".repeat(n);
    await fs.writeFile(path.join(root, "package-lock.json"), big(MAX_FILE_SIZE_BYTES + 10));
    await fs.mkdir(path.join(root, "apps/web"), { recursive: true });
    await fs.writeFile(path.join(root, "apps/web/yarn.lock"), big(MAX_LOCKFILE_SIZE_BYTES + 1));
    await fs.writeFile(path.join(root, "big.json"), big(MAX_FILE_SIZE_BYTES + 10));
    await fs.writeFile(path.join(root, "small.ts"), "export {};\n");
  });

  afterAll(async () => {
    await fs.rm(root, { recursive: true, force: true });
  });

  it("collects detector warnings via context.addWarning, de-duplicated, in order", async () => {
    const registry = new DetectorRegistry();
    registry.register(new WarningDetector());
    const res = await new ScannerPipeline(registry).scan({
      rootPath: root,
      useConfigFile: false,
      targetFiles: ["small.ts"],
    });
    expect(res.warnings).toEqual([
      "Lockfile could not be parsed; dependency checks are partial.",
      "Second notice.",
    ]);
  });

  it("reads lockfiles up to MAX_LOCKFILE_SIZE_BYTES and other files up to MAX_FILE_SIZE_BYTES", async () => {
    const registry = new DetectorRegistry();
    const reader = new ReadSizesDetector();
    registry.register(reader);
    const res = await new ScannerPipeline(registry).scan({ rootPath: root, useConfigFile: false });
    expect(reader.sizes["package-lock.json"]).toBe(MAX_FILE_SIZE_BYTES + 10);
    expect(reader.sizes["apps/web/yarn.lock"]).toBe(0);
    expect(reader.sizes["big.json"]).toBe(0);
    expect(reader.sizes["small.ts"]).toBe(11);
    const skipped = (res.warnings ?? []).find((w) => w.startsWith("Skipped 2 file(s)"));
    expect(skipped).toBeDefined();
    expect(skipped).toContain("big.json");
    expect(skipped).toContain("yarn.lock");
    expect(skipped).not.toContain("package-lock.json");
  });

  it("ScanConfig.online is typed but config files cannot enable it", () => {
    const config: ScanConfig = { rootPath: root, online: true };
    expect(config.online).toBe(true);
    expect(validateUserConfig({ online: true }).join()).toMatch(/unknown option "online"/);
  });
});
