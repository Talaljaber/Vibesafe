import { describe, it, expect } from "vitest";
import { DependencyDetector } from "../../src/detectors/dependency-detector";
import type { ScanContext } from "@vibesafe/shared";

describe("DependencyDetector", () => {
  const detector = new DependencyDetector();

  const createContext = (files: Record<string, string>): ScanContext => ({
    rootPath: "/fake/path",
    projectContext: {} as any,
    files: Object.keys(files),
    config: {} as any,
    readFile: async (file) => files[file] || "",
  });

  it("should detect risky install scripts", async () => {
    const context = createContext({
      "package.json": JSON.stringify({
        scripts: {
          postinstall: "node install.js"
        }
      }),
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("dependency/risky-install-script");
  });

  it("ignores nested package.json files when there is no root one", async () => {
    const context = createContext({
      "fixtures/app/package.json": JSON.stringify({ scripts: { postinstall: "x" } }),
    });
    expect(await detector.detect(context)).toHaveLength(0);
  });

  it("lowers install script severity for private packages", async () => {
    const run = async (pkg: object) =>
      (await detector.detect(createContext({ "package.json": JSON.stringify(pkg) })))[0]?.severity;
    expect(await run({ private: true, scripts: { postinstall: "x" } })).toBe("low");
    expect(await run({ scripts: { postinstall: "x" } })).toBe("high");
  });

  it("should detect excessive dependencies", async () => {
    const deps: Record<string, string> = {};
    for (let i = 0; i < 85; i++) {
      deps["dep-" + i] = "1.0.0";
    }
    const context = createContext({
      "package.json": JSON.stringify({
        dependencies: deps
      }),
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("dependency/excessive-dependencies");
  });

  it("should return empty if clean", async () => {
    const context = createContext({
      "package.json": JSON.stringify({
        scripts: { dev: "next dev" },
        dependencies: { "react": "18.0.0" }
      }),
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(0);
  });
});
