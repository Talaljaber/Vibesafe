import { describe, it, expect } from "vitest";
import { ProjectStructureDetector } from "../../src/detectors/project-structure-detector";
import type { ScanContext } from "@vibeguard/shared";

describe("ProjectStructureDetector", () => {
  const detector = new ProjectStructureDetector();

  const createContext = (hasGitignore: boolean, hasReadme: boolean, hasTests: boolean): ScanContext => ({
    rootPath: "/fake/path",
    projectContext: {
      hasGitignore,
      hasReadme,
      hasTests
    } as any,
    files: [],
    config: {} as any,
    readFile: async () => "",
  });

  it("should detect missing standard files", async () => {
    const context = createContext(false, false, false);
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(3);
    expect(findings.some(f => f.ruleId === "structure/missing-gitignore")).toBe(true);
    expect(findings.some(f => f.ruleId === "structure/missing-readme")).toBe(true);
    expect(findings.some(f => f.ruleId === "structure/missing-tests")).toBe(true);
  });

  it("should not detect if files are present", async () => {
    const context = createContext(true, true, true);
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(0);
  });
});
