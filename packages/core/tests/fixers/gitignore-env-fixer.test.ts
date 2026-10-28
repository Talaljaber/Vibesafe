import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { GitignoreEnvFixer } from "../../src/fixers/gitignore-env-fixer";
import type { Finding } from "@vibesafe/shared";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

describe("GitignoreEnvFixer", () => {
  const fixer = new GitignoreEnvFixer();
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "vibesafe-test-"));
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
    autoFixAvailable: true,
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

  it("adds !.env.example so the example file stays tracked", async () => {
    await fs.writeFile(path.join(tempDir, ".gitignore"), "node_modules");
    await fixer.apply(finding, tempDir);
    expect(await fs.readFile(path.join(tempDir, ".gitignore"), "utf-8")).toBe(
      "node_modules\n.env\n.env.*\n!.env.example\n",
    );
  });

  it("adds the negation when .env.* is already ignored, and is idempotent", async () => {
    await fs.writeFile(path.join(tempDir, ".gitignore"), ".env\n.env.*\n");
    await fixer.apply(finding, tempDir);
    await fixer.apply(finding, tempDir);
    expect(await fs.readFile(path.join(tempDir, ".gitignore"), "utf-8")).toBe(
      ".env\n.env.*\n!.env.example\n",
    );
  });

  it("does not overwrite or follow a symlinked .gitignore", async (ctx) => {
    const target = path.join(tempDir, "..", `target-${path.basename(tempDir)}`);
    await fs.writeFile(target, "orig\n");
    try {
      await fs.symlink(target, path.join(tempDir, ".gitignore"), "file");
    } catch {
      await fs.rm(target, { force: true });
      ctx.skip();
      return;
    }
    const result = await fixer.apply(finding, tempDir);
    expect(result.success).toBe(false);
    expect(await fs.readFile(target, "utf-8")).toBe("orig\n");
    await fs.rm(target, { force: true });
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
