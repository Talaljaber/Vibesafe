import { describe, it, expect } from "vitest";
import { DependencyDetector } from "../../src/detectors/dependency-detector";
import type { ScanContext } from "@vibeguard/shared";

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
