import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { ConsoleLogFixer } from "../../src/fixers/console-log-fixer";
import type { Finding } from "@vibeguard/shared";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

describe("ConsoleLogFixer", () => {
  const fixer = new ConsoleLogFixer();
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-test-"));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  const finding: Finding = {
    id: "test",
    ruleId: "code_quality/console-log",
    title: "Test",
    severity: "low",
    category: "code_quality",
    deployBlocking: false,
    confidence: "high",
    plainEnglishProblem: "Test",
    whyItMatters: "Test",
    fixSteps: [],
    autoFixAvailable: true,
    file: "index.js",
    line: 2
  };

  it("should comment out console.log", async () => {
    await fs.writeFile(path.join(tempDir, "index.js"), "const a = 1;\nconsole.log(a);\nconst b = 2;");
    
    const preview = await fixer.preview(finding, tempDir);
    expect(preview.filesToModify).toContain("index.js");
    expect(preview.diff).toContain("/* console.log */");

    const result = await fixer.apply(finding, tempDir);
    expect(result.success).toBe(true);

    const content = await fs.readFile(path.join(tempDir, "index.js"), "utf-8");
    expect(content).toContain("/* console.log */(a);");
  });

  it("should fail gracefully if file doesn't exist", async () => {
    const result = await fixer.apply(finding, tempDir);
    expect(result.success).toBe(false);
  });
});
