import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { DetectorRegistry } from "../../src/scanner/detector-registry.js";
import { ScannerPipeline } from "../../src/scanner/pipeline.js";
import { mergeConfig } from "../../src/config/defaults.js";
import { validateUserConfig } from "../../src/config/schema.js";

/** Records the `online` value each scan hands to detectors. */
class OnlineProbe implements Detector {
  id = "online-probe-detector";
  name = "Online probe";
  category = "dependency" as const;
  description = "Records config.online";
  seen: (boolean | undefined)[] = [];
  async detect(context: ScanContext): Promise<Finding[]> {
    this.seen.push(context.config.online);
    return [];
  }
}

let root: string;

beforeAll(async () => {
  root = await fs.mkdtemp(path.join(os.tmpdir(), "vibesafe-online-"));
  await fs.writeFile(path.join(root, "package.json"), JSON.stringify({ name: "x" }));
});

afterAll(async () => {
  await fs.rm(root, { recursive: true, force: true });
});

async function scanWith(options: Record<string, unknown>): Promise<boolean | undefined> {
  const probe = new OnlineProbe();
  const registry = new DetectorRegistry();
  registry.register(probe);
  await new ScannerPipeline(registry).scan({ rootPath: root, ...options });
  return probe.seen[0];
}

describe("online (network egress) configuration", () => {
  it("is off unless the caller passes exactly true", () => {
    expect(mergeConfig(root, {}).online).toBeUndefined();
    expect(mergeConfig(root, { online: false }).online).toBeUndefined();
    expect(mergeConfig(root, { online: true }).online).toBe(true);
  });

  it("reaches detectors only from an explicit scan option", async () => {
    expect(await scanWith({})).toBeUndefined();
    expect(await scanWith({ online: false })).toBeUndefined();
    expect(await scanWith({ online: true })).toBe(true);
  });

  it("can never be enabled from a config file", async () => {
    expect(validateUserConfig({ online: true }).join()).toMatch(/unknown option "online"/);
    const configPath = path.join(root, ".vibesafe.config.json");
    await fs.writeFile(configPath, JSON.stringify({ online: true }));
    try {
      await expect(scanWith({})).rejects.toThrow(/online/);
    } finally {
      await fs.rm(configPath, { force: true });
    }
  });
});
