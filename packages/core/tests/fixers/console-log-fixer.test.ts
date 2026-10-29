import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { ConsoleLogFixer } from "../../src/fixers/console-log-fixer";
import type { Finding } from "@talaljaber/vibesafe-shared";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

describe("ConsoleLogFixer", () => {
  const fixer = new ConsoleLogFixer();
  let base: string;
  let tempDir: string;

  beforeEach(async () => {
    base = await fs.mkdtemp(path.join(os.tmpdir(), "vibesafe-test-"));
    tempDir = path.join(base, "project");
    await fs.mkdir(tempDir);
  });

  afterEach(async () => {
    await fs.rm(base, { recursive: true, force: true });
  });

  const at = (line: number, file = "index.js"): Finding => ({
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
    file,
    line,
  });

  const write = (src: string) => fs.writeFile(path.join(tempDir, "index.js"), src);
  const read = () => fs.readFile(path.join(tempDir, "index.js"), "utf-8");

  it("comments out a standalone statement", async () => {
    await write("const a = 1;\nconsole.log(a);\nconst b = 2;");

    const preview = await fixer.preview(at(2), tempDir);
    expect(preview.filesToModify).toContain("index.js");
    expect(preview.diff).toContain("// console.log(a);");

    const result = await fixer.apply(at(2), tempDir);
    expect(result.success).toBe(true);
    expect(await read()).toBe("const a = 1;\n// console.log(a);\nconst b = 2;");
  });

  it("leaves arrow-function bodies unchanged", async () => {
    const src = "app.listen(3000, () => console.log('x'));\n";
    await write(src);
    expect(fixer.canFix(at(1))).toBe(true);
    expect((await fixer.preview(at(1), tempDir)).filesToModify).toEqual([]);
    const result = await fixer.apply(at(1), tempDir);
    expect(result.success).toBe(false);
    expect(await read()).toBe(src);
  });

  it("is safe for missing-semicolon (ASI) code", async () => {
    const src = "const x = foo()\nconsole.log('hi')\n[1, 2].forEach(f)\n";
    await write(src);
    const result = await fixer.apply(at(2), tempDir);
    // Either left untouched or turned into a plain comment: never `foo()/* */(...)`.
    const out = await read();
    expect(out).not.toMatch(/\/\*/);
    if (result.success)
      expect(out).toBe("const x = foo()\n// console.log('hi')\n[1, 2].forEach(f)\n");
    else expect(out).toBe(src);
  });

  it("handles multi-line calls and preserves line count", async () => {
    await write("a();\nconsole.log(\n  'x',\n  fn(1, ')')\n);\nb();\n");
    const result = await fixer.apply(at(2), tempDir);
    expect(result.success).toBe(true);
    expect(await read()).toBe("a();\n// console.log(\n  // 'x',\n  // fn(1, ')')\n// );\nb();\n");
  });

  it("fixes consecutive semicolon-less console.log lines", async () => {
    await write("const x = 1\nconsole.log(a)\nconsole.log(b)\nexport {}\n");
    expect((await fixer.apply(at(2), tempDir)).success).toBe(true);
    expect((await fixer.apply(at(3), tempDir)).success).toBe(true);
    expect(await read()).toBe("const x = 1\n// console.log(a)\n// console.log(b)\nexport {}\n");
  });

  it("still refuses a control statement separated by a comment line", async () => {
    await write("if (x)\n// note\nconsole.log(a)\n");
    expect((await fixer.apply(at(3), tempDir)).success).toBe(false);
  });

  it("is idempotent", async () => {
    await write("a();\nconsole.log(a);\nb();\n");
    expect((await fixer.apply(at(2), tempDir)).success).toBe(true);
    const once = await read();
    const second = await fixer.apply(at(2), tempDir);
    expect(second.success).toBe(false);
    expect(await read()).toBe(once);
  });

  it("fails on a stale line", async () => {
    await write("a();\nb();\n");
    const result = await fixer.apply(at(2), tempDir);
    expect(result.success).toBe(false);
    expect(await read()).toBe("a();\nb();\n");
    expect((await fixer.apply(at(99), tempDir)).success).toBe(false);
  });

  it("does not touch strings, braceless control bodies or larger expressions", async () => {
    for (const src of [
      'const s = "console.log(1)";\n',
      "if (x)\n  console.log(1);\n",
      "foo(console.log(1));\n",
      "console.log(1), other();\n",
      "const t = `\nconsole.log(1);\n`;\n",
    ]) {
      await write(src);
      const line = src.split("\n").findIndex((l) => l.includes("console.log")) + 1;
      expect((await fixer.apply(at(line), tempDir)).success).toBe(false);
      expect(await read()).toBe(src);
    }
  });

  it("preserves CRLF line endings", async () => {
    await write("a();\r\nconsole.log(a);\r\nb();\r\n");
    expect((await fixer.apply(at(2), tempDir)).success).toBe(true);
    expect(await read()).toBe("a();\r\n// console.log(a);\r\nb();\r\n");
  });

  it("should fail gracefully if file doesn't exist", async () => {
    const result = await fixer.apply(at(2), tempDir);
    expect(result.success).toBe(false);
  });

  it("rejects traversal and absolute paths", async () => {
    const outsideFile = path.join(base, "outside.js");
    await fs.writeFile(outsideFile, "console.log(1);\n");
    for (const file of ["../outside.js", "../../x.js", outsideFile]) {
      expect(fixer.canFix(at(1, file))).toBe(false);
      const result = await fixer.apply(at(1, file), tempDir);
      expect(result.success).toBe(false);
      expect((await fixer.preview(at(1, file), tempDir)).filesToModify).toEqual([]);
    }
    expect(await fs.readFile(outsideFile, "utf-8")).toBe("console.log(1);\n");
  });

  it("does not follow symlinks", async (ctx) => {
    const outsideFile = path.join(base, "outside.js");
    await fs.writeFile(outsideFile, "console.log(1);\n");
    try {
      await fs.symlink(outsideFile, path.join(tempDir, "link.js"), "file");
    } catch {
      ctx.skip();
      return;
    }
    const result = await fixer.apply(at(1, "link.js"), tempDir);
    expect(result.success).toBe(false);
    expect(await fs.readFile(outsideFile, "utf-8")).toBe("console.log(1);\n");
  });
});
