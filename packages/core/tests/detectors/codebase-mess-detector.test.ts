import { describe, it, expect } from "vitest";
import { CodebaseMessDetector } from "../../src/detectors/codebase-mess-detector";
import type { ScanContext } from "@vibeguard/shared";

describe("CodebaseMessDetector", () => {
  const detector = new CodebaseMessDetector();

  const createContext = (files: Record<string, string>): ScanContext => ({
    rootPath: "/fake/path",
    projectContext: {} as any,
    files: Object.keys(files),
    config: {} as any,
    readFile: async (file) => files[file] || "",
  });

  it("should detect huge files", async () => {
    let content = "";
    for (let i = 0; i < 505; i++) content += "const a = 1;\n";
    
    const context = createContext({
      "app/page.tsx": content,
    });
    const findings = await detector.detect(context);
    expect(findings.some(f => f.ruleId === "code_quality/huge-file")).toBe(true);
  });

  it("should detect empty catch blocks", async () => {
    const context = createContext({
      "app/page.tsx": `
        try {
          doSomething();
        } catch (e) {
        }
      `,
    });
    const findings = await detector.detect(context);
    expect(findings.some(f => f.ruleId === "code_quality/empty-catch")).toBe(true);
  });

  it("should detect leftover console.log", async () => {
    const context = createContext({
      "app/page.tsx": `console.log("hello");`,
    });
    const findings = await detector.detect(context);
    expect(findings.some(f => f.ruleId === "code_quality/console-log")).toBe(true);
  });
});
