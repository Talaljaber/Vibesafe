import { describe, it, expect } from "vitest";
import { DangerousHtmlDetector } from "../../src/detectors/dangerous-html-detector";
import type { ScanContext } from "@vibesafe/shared";

describe("DangerousHtmlDetector", () => {
  const detector = new DangerousHtmlDetector();

  const createContext = (files: Record<string, string>): ScanContext => ({
    rootPath: "/fake/path",
    projectContext: {} as any,
    files: Object.keys(files),
    config: {} as any,
    readFile: async (file) => files[file] || "",
  });

  it("should detect dangerouslySetInnerHTML in JSX props", async () => {
    const context = createContext({
      "app/page.tsx": `const Page = () => (
  <div dangerouslySetInnerHTML={{ __html: userContent }} />
);`,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("xss/dangerously-set-inner-html");
    expect(findings[0].severity).toBe("high");
    expect(findings[0].line).toBe(2);
  });

  it("should detect dangerouslySetInnerHTML in plain .js files", async () => {
    const context = createContext({
      "lib/render.js": `function render(content) {
  return React.createElement("div", { dangerouslySetInnerHTML: { __html: content } });
}`,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(1);
    expect(findings[0].file).toBe("lib/render.js");
  });

  it("should flag multiple usages across files", async () => {
    const context = createContext({
      "app/a.tsx": `<p dangerouslySetInnerHTML={{ __html: a }} />`,
      "app/b.tsx": `<span dangerouslySetInnerHTML={{ __html: b }} />`,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(2);
  });

  it("should not flag files without usage", async () => {
    const context = createContext({
      "app/safe.tsx": `const Page = () => <div>{userContent}</div>;`,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(0);
  });

  it("should not scan non-source files", async () => {
    const context = createContext({
      "notes.md": "mentions dangerouslySetInnerHTML in docs",
      "data.json": `{"prop": "dangerouslySetInnerHTML"}`,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(0);
  });
});
