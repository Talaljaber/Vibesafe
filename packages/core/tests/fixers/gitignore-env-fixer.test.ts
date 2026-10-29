import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { GitignoreEnvFixer } from "../../src/fixers/gitignore-env-fixer";
import type { Finding } from "@talaljaber/vibesafe-shared";
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

  it("adds .env.* when only .env is ignored, so .env.local stops being committable", async () => {
    await fs.writeFile(path.join(tempDir, ".gitignore"), "node_modules\n.env\n");

    const preview = await fixer.preview(finding, tempDir);
    expect(preview.filesToModify).toEqual([".gitignore"]);
    expect(preview.diff).toBe("+ .env.*\n+ !.env.example\n");

    const result = await fixer.apply(finding, tempDir);
    expect(result.success).toBe(true);
    expect(result.filesModified).toEqual([".gitignore"]);
    expect(await fs.readFile(path.join(tempDir, ".gitignore"), "utf-8")).toBe(
      "node_modules\n.env\n.env.*\n!.env.example\n",
    );
  });

  it("previews the full block for an empty .gitignore (never an empty diff)", async () => {
    await fs.writeFile(path.join(tempDir, ".gitignore"), "");
    const preview = await fixer.preview(finding, tempDir);
    expect(preview.filesToModify).toEqual([".gitignore"]);
    expect(preview.diff).toBe("+ .env\n+ .env.*\n+ !.env.example\n");
    await fixer.apply(finding, tempDir);
    expect(await fs.readFile(path.join(tempDir, ".gitignore"), "utf-8")).toBe(
      ".env\n.env.*\n!.env.example\n",
    );
  });

  it("previews the new file's content when .gitignore is missing", async () => {
    const preview = await fixer.preview(finding, tempDir);
    expect(preview.filesToCreate).toEqual([".gitignore"]);
    expect(preview.diff).toContain("+ .env.*");
  });

  it("reports nothing to change, with no diff, when env files are already covered", async () => {
    for (const content of [".env\n.env.*\n!.env.example\n", "/.env*\n!/.env.example\n"]) {
      await fs.writeFile(path.join(tempDir, ".gitignore"), content);
      const preview = await fixer.preview(finding, tempDir);
      expect(preview.filesToModify).toEqual([]);
      expect(preview.diff).toBeUndefined();
      expect(preview.description).toContain("nothing to change");
      const result = await fixer.apply(finding, tempDir);
      expect(result.filesModified).toEqual([]);
      expect(result.message).toContain("already in");
      expect(await fs.readFile(path.join(tempDir, ".gitignore"), "utf-8")).toBe(content);
    }
  });

  it("treats .env* as covering both .env and .env.*, adding only the negation", async () => {
    await fs.writeFile(path.join(tempDir, ".gitignore"), ".env*\n");
    const preview = await fixer.preview(finding, tempDir);
    expect(preview.diff).toBe("+ !.env.example\n");
  });
});

describe("GitignoreEnvFixer for security_config/gitignore-env-variants", () => {
  const ruleId = "security_config/gitignore-env-variants";
  const fixer = new GitignoreEnvFixer(ruleId);

  it("handles the variants rule and appends the wildcard and negation", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "vibesafe-test-"));
    try {
      await fs.writeFile(path.join(dir, ".gitignore"), ".env\n");
      const finding = { ruleId } as Finding;
      expect(fixer.canFix(finding)).toBe(true);
      const preview = await fixer.preview(finding, dir);
      expect(preview.diff).toContain(".env.*");
      expect(preview.diff).toContain("!.env.example");
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it("resolves through the default fix registry", async () => {
    const { createDefaultFixRegistry } = await import("../../src/fixers/auto-fix-registry.js");
    const reg = createDefaultFixRegistry();
    expect(reg.getFixer(ruleId)).toBeDefined();
    expect(reg.getFixer("secret/env-not-ignored")).toBeDefined();
  });
});
