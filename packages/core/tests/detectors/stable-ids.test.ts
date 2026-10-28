import { describe, it, expect } from "vitest";
import { HardcodedLocalhostDetector } from "../../src/detectors/hardcoded-localhost-detector";
import { CodebaseMessDetector } from "../../src/detectors/codebase-mess-detector";
import type { ScanContext } from "@vibesafe/shared";

const createContext = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake/path",
  projectContext: {} as any,
  files: Object.keys(files),
  config: {} as any,
  readFile: async (file) => files[file] || "",
});

describe("stable finding ids", () => {
  it("produces identical, unique ids across repeated scans", async () => {
    const files = {
      "src/a.ts": `const a = "http://localhost:3000";\nconsole.log("x");\nconsole.log("y");`,
      "src/b.ts": `const b = "http://127.0.0.1:8080";`,
    };
    const detectors = [new HardcodedLocalhostDetector(), new CodebaseMessDetector()];
    const run = async () =>
      (await Promise.all(detectors.map((d) => d.detect(createContext(files))))).flat();

    const first = await run();
    const second = await run();

    expect(first.length).toBeGreaterThan(2);
    expect(first.map((f) => f.id)).toEqual(second.map((f) => f.id));
    expect(new Set(first.map((f) => f.id)).size).toBe(first.length);
    for (const f of first) expect(f.id).toMatch(/^[A-Z]+-[0-9a-f]{10}$/);
  });
});
