import { describe, it, expect } from "vitest";
import { CodebaseMessDetector } from "../../src/detectors/codebase-mess-detector";
import { ConsoleLogFixer } from "../../src/fixers/console-log-fixer";
import type { Finding, ScanContext } from "@vibesafe/shared";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

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

  it("ignores console.log lines that are already commented out", async () => {
    const context = createContext({
      "app/page.tsx": `// console.log("a");\n  /* console.log("b"); */\n/**\n * console.log("c")\n */\nconst z = 1;`,
    });
    const findings = await detector.detect(context);
    expect(findings.some(f => f.ruleId === "code_quality/console-log")).toBe(false);
  });

  it("still flags live code that follows a leading block comment", async () => {
    const context = createContext({
      "app/page.tsx": `/* tmp */ console.log(user.token);\n/* a */ /* b */ console.log(2);`,
    });
    const findings = await detector.detect(context);
    expect(findings.filter(f => f.ruleId === "code_quality/console-log").map(f => f.line)).toEqual([1, 2]);
  });

  it("does not re-flag lines rewritten by ConsoleLogFixer", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "vibesafe-mess-"));
    try {
      await fs.writeFile(path.join(dir, "index.js"), "const a = 1;\nconsole.log(a);\n");
      const finding = { ruleId: "code_quality/console-log", file: "index.js", line: 2 } as Finding;
      const res = await new ConsoleLogFixer().apply(finding, dir);
      expect(res.success).toBe(true);
      const src = await fs.readFile(path.join(dir, "index.js"), "utf-8");
      expect(src).toContain("// console.log(a)");
      const findings = await detector.detect(createContext({ "index.js": src }));
      expect(findings.some(f => f.ruleId === "code_quality/console-log")).toBe(false);
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });
});
