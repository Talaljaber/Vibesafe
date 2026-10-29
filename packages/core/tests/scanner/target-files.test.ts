import { describe, it, expect } from "vitest";
import { mergeConfig } from "../../src/config/defaults.js";
import { ScannerPipeline } from "../../src/scanner/pipeline.js";
import { DetectorRegistry } from "../../src/scanner/detector-registry.js";
import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";

class FilesSeenDetector implements Detector {
  id = "files-seen";
  name = "Files Seen";
  category = "secret" as const;
  description = "Records the files it was asked to scan";
  seen: string[] = [];

  async detect(context: ScanContext): Promise<Finding[]> {
    this.seen = [...context.files];
    return [];
  }
}

describe("targetFiles", () => {
  it("mergeConfig keeps targetFiles", () => {
    expect(mergeConfig("/x", { targetFiles: ["a.ts"] }).targetFiles).toEqual(["a.ts"]);
    expect("targetFiles" in mergeConfig("/x")).toBe(false);
  });

  it("a targeted scan only sees the target file", async () => {
    const detector = new FilesSeenDetector();
    const registry = new DetectorRegistry();
    registry.register(detector);
    const pipeline = new ScannerPipeline(registry);

    await pipeline.scan({
      rootPath: process.cwd(),
      targetFiles: ["package.json"],
    });
    expect(detector.seen).toEqual(["package.json"]);
  });
});
