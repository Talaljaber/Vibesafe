import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { GitignoreEnvFixer } from "../../src/fixers/gitignore-env-fixer";
import type { Finding } from "@vibeguard/shared";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

describe("GitignoreEnvFixer", () => {
  const fixer = new GitignoreEnvFixer();
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-test-"));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  const finding: Finding = {
    id: "test",
    ruleId: "secret/env-not-ignored",
    title: "Test",
    severity: "critical",
    category: "secret",
    deployBlocking: true,
    confidence: "high",
    plainEnglishProblem: "Test",
    whyItMatters: "Test",
    fixSteps: [],
    autoFixAvailable: true
  };

  it("should create .gitignore if it doesn't exist", async () => {
    const preview = await fixer.preview(finding, tempDir);
    expect(preview.filesToCreate).toContain(".gitignore");

    const result = await fixer.apply(finding, tempDir);
    expect(result.success).toBe(true);
    
    const content = await fs.readFile(path.join(tempDir, ".gitignore"), "utf-8");
    expect(content).toContain("node_modules");
    expect(content).toContain(".env");
  });

  it("should append .env to existing .gitignore", async () => {
    await fs.writeFile(path.join(tempDir, ".gitignore"), "node_modules\n");
    
    const preview = await fixer.preview(finding, tempDir);
    expect(preview.filesToModify).toContain(".gitignore");

    const result = await fixer.apply(finding, tempDir);
    expect(result.success).toBe(true);

    const content = await fs.readFile(path.join(tempDir, ".gitignore"), "utf-8");
    expect(content).toContain("node_modules\n.env\n.env.*");
  });

  it("should not append .env if it already exists", async () => {
    await fs.writeFile(path.join(tempDir, ".gitignore"), "node_modules\n.env\n");
    
    const result = await fixer.apply(finding, tempDir);
    expect(result.success).toBe(true);
    expect(result.message).toContain("already in");

    const content = await fs.readFile(path.join(tempDir, ".gitignore"), "utf-8");
    expect(content).toBe("node_modules\n.env\n"); // unchanged
  });
});
