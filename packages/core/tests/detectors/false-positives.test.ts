import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { ErrorBoundaryDetector } from "../../src/detectors/error-boundary-detector.js";
import { HardcodedLocalhostDetector } from "../../src/detectors/hardcoded-localhost-detector.js";
import { DangerousHtmlDetector } from "../../src/detectors/dangerous-html-detector.js";
import { CodebaseMessDetector } from "../../src/detectors/codebase-mess-detector.js";

const ctx = (files: Record<string, string>): ScanContext =>
  ({
    rootPath: "/fake",
    projectContext: {},
    files: Object.keys(files),
    config: {},
    readFile: async (f: string) => files[f] ?? "",
  }) as unknown as ScanContext;

describe("error boundary: Next.js conventions (#41)", () => {
  const d = new ErrorBoundaryDetector();
  it("treats app/**/error.tsx and global-error as boundaries", async () => {
    expect(await d.detect(ctx({ "app/page.tsx": "x", "app/dash/error.tsx": "x" }))).toHaveLength(0);
    expect(
      await d.detect(ctx({ "src/app/page.tsx": "x", "src/app/global-error.jsx": "x" })),
    ).toHaveLength(0);
    expect(await d.detect(ctx({ "app/page.tsx": "x" }))).toHaveLength(1);
  });
});

describe("error boundary: root package.json only (#47)", () => {
  const d = new ErrorBoundaryDetector();
  it("ignores react in a nested package.json for non-JSX projects", async () => {
    const f = await d.detect(
      ctx({ "pkg/package.json": JSON.stringify({ dependencies: { react: "1" } }), "a.ts": "x" }),
    );
    expect(f).toHaveLength(0);
  });
  it("uses the root package.json react dependency", async () => {
    const f = await d.detect(
      ctx({ "package.json": JSON.stringify({ dependencies: { react: "1" } }), "a.tsx": "x" }),
    );
    expect(f).toHaveLength(1);
  });
});

describe("hardcoded localhost false positives (#41)", () => {
  const d = new HardcodedLocalhostDetector();
  it("skips env fallbacks, comments and config files", async () => {
    const findings = await d.detect(
      ctx({
        "src/a.ts": `const u = process.env.API_URL ?? "http://localhost:3000";\n// http://localhost:3000\nconst v = import.meta.env.X || "http://127.0.0.1";\n`,
        "vite.config.ts": `proxy: "http://localhost:3000"`,
      }),
    );
    expect(findings).toHaveLength(0);
  });
  it("still flags a bare hardcoded host", async () => {
    expect(await d.detect(ctx({ "src/a.ts": `fetch("http://localhost:3000/api");` }))).toHaveLength(
      1,
    );
  });
});

describe("dangerous html false positives (#41)", () => {
  const d = new DangerousHtmlDetector();
  it("flags raw usage with medium confidence", async () => {
    const f = await d.detect(
      ctx({ "a.tsx": `<div dangerouslySetInnerHTML={{ __html: html }} />` }),
    );
    expect(f).toHaveLength(1);
    expect(f[0]?.confidence).toBe("medium");
  });
  it("skips sanitized values and JSON-LD", async () => {
    const f = await d.detect(
      ctx({
        "a.tsx": `<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />`,
        "b.tsx": `<script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }} />`,
      }),
    );
    expect(f).toHaveLength(0);
  });
});

describe("codebase mess false positives (#41)", () => {
  const d = new CodebaseMessDetector();
  it("counts any only in type positions of TS files", async () => {
    const prose = "// any any any any any\nconst s = 'anything any';\n".repeat(30);
    const f = await d.detect(ctx({ "a.ts": prose, "b.js": "const x: any = 1;\n".repeat(30) }));
    expect(f.find((x) => x.ruleId === "code_quality/excessive-any")).toBeUndefined();
    const typed = await d.detect(
      ctx({ "a.ts": "let a: any; let b = c as any; let d: any[];\n".repeat(10) }),
    );
    expect(typed.find((x) => x.ruleId === "code_quality/excessive-any")).toBeDefined();
  });
  it("detects only genuinely empty catch blocks", async () => {
    const f = await d.detect(
      ctx({
        "a.ts": [
          "try { a() } catch {}",
          "try { a() } catch (e) {}",
          "try { a() } catch (e) {\n\n}",
          "p.catch(handler);",
          "p.catch(() => {});",
          "try { a() } catch (e) {\n  log(e);\n}",
        ].join("\n"),
      }),
    );
    expect(f.filter((x) => x.ruleId === "code_quality/empty-catch").map((x) => x.line)).toEqual([
      1, 2, 3,
    ]);
  });
});
