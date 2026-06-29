import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { EnvExampleFixer } from "../../src/fixers/env-example-fixer";
import type { Finding } from "@vibesafe/shared";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

describe("EnvExampleFixer", () => {
  const fixer = new EnvExampleFixer();
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "vibesafe-test-"));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  const finding: Finding = {
    id: "test",
    ruleId: "structure/missing-env-example",
    title: "Test",
    severity: "low",
    category: "structure",
    deployBlocking: false,
    confidence: "high",
    plainEnglishProblem: "Test",
    whyItMatters: "Test",
    fixSteps: [],
    autoFixAvailable: true
  };

  it("should create .env.example with stripped values", async () => {
    await fs.writeFile(path.join(tempDir, ".env"), "API_KEY=supersecret\n# Comment\nDB_PASS=12345");
    
    const preview = await fixer.preview(finding, tempDir);
    expect(preview.filesToCreate).toContain(".env.example");

    const result = await fixer.apply(finding, tempDir);
    expect(result.success).toBe(true);

    const content = await fs.readFile(path.join(tempDir, ".env.example"), "utf-8");
    expect(content).toContain("API_KEY=\n# Comment\nDB_PASS=");
    expect(content).not.toContain("supersecret");
    expect(content).not.toContain("12345");
  });

  it("should fail gracefully if .env doesn't exist", async () => {
    const result = await fixer.apply(finding, tempDir);
    expect(result.success).toBe(false);
  });
});
