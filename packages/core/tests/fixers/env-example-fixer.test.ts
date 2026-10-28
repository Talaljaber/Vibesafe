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
    autoFixAvailable: true,
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

  it("does not leak values from CRLF files, comments or multi-line values", async () => {
    const env =
      'API_KEY=sk_live_abc\r\n# OLD_KEY=sk_live_old\r\n# plain note\r\nexport TOKEN=tok_123\r\nPEM="-----BEGIN KEY-----\r\nMIIEsecret\r\n-----END KEY-----"\r\nlast=1\r\njunk line sk_live_zzz\r\n';
    await fs.writeFile(path.join(tempDir, ".env"), env);

    const result = await fixer.apply(finding, tempDir);
    expect(result.success).toBe(true);

    const content = await fs.readFile(path.join(tempDir, ".env.example"), "utf-8");
    expect(content).toBe("API_KEY=\r\n# plain note\r\nexport TOKEN=\r\nPEM=\r\nlast=\r\n");
    for (const leaked of ["sk_live", "tok_123", "MIIE", "BEGIN", "junk"]) {
      expect(content).not.toContain(leaked);
    }
  });

  it("falls back to .env.local", async () => {
    await fs.writeFile(path.join(tempDir, ".env.local"), "SECRET=abc\n");
    const result = await fixer.apply(finding, tempDir);
    expect(result.success).toBe(true);
    expect(await fs.readFile(path.join(tempDir, ".env.example"), "utf-8")).toBe("SECRET=\n");
  });

  it("refuses to overwrite an existing .env.example", async () => {
    await fs.writeFile(path.join(tempDir, ".env"), "A=secret\n");
    await fs.writeFile(path.join(tempDir, ".env.example"), "HAND_WRITTEN=\n");
    const preview = await fixer.preview(finding, tempDir);
    expect(preview.filesToCreate).toEqual([]);
    const result = await fixer.apply(finding, tempDir);
    expect(result.success).toBe(false);
    expect(await fs.readFile(path.join(tempDir, ".env.example"), "utf-8")).toBe("HAND_WRITTEN=\n");
  });

  it("does not write through a symlinked .env.example", async (ctx) => {
    await fs.writeFile(path.join(tempDir, ".env"), "A=secret\n");
    const target = path.join(tempDir, "..", `target-${path.basename(tempDir)}`);
    await fs.writeFile(target, "orig");
    try {
      await fs.symlink(target, path.join(tempDir, ".env.example"), "file");
    } catch {
      await fs.rm(target, { force: true });
      ctx.skip();
      return;
    }
    const result = await fixer.apply(finding, tempDir);
    expect(result.success).toBe(false);
    expect(await fs.readFile(target, "utf-8")).toBe("orig");
    await fs.rm(target, { force: true });
  });

  it("should fail gracefully if .env doesn't exist", async () => {
    const result = await fixer.apply(finding, tempDir);
    expect(result.success).toBe(false);
  });
});
