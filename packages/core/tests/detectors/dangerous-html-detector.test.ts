import { describe, it, expect } from "vitest";
import { DangerousHtmlDetector } from "../../src/detectors/dangerous-html-detector";
import type { ScanContext } from "@talaljaber/vibesafe-shared";

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

  describe("sanitizer tracing", () => {
    const run = async (src: string) =>
      detector.detect(createContext({ "components/Rich.tsx": src }));

    it("traces __html to a multi-line useMemo that calls DOMPurify.sanitize", async () => {
      const src = `'use client';
import DOMPurify from 'isomorphic-dompurify';
import { useMemo } from 'react';

export default function Rich({ html }: { html: string }) {
  const clean = useMemo(
    () =>
      DOMPurify.sanitize(html, {
        USE_PROFILES: { html: true },
        FORBID_TAGS: ['style', 'form', 'iframe'],
        FORBID_ATTR: ['style'],
      }),
    [html]
  );

  return <div className="prose" dangerouslySetInnerHTML={{ __html: clean }} />;
}`;
      expect(await run(src)).toEqual([]);
    });

    it("accepts sanitize-html and a named sanitize import from dompurify", async () => {
      expect(
        await run(`import sanitizeHtml from "sanitize-html";
const safe = sanitizeHtml(input, { allowedTags: ["b"] });
export const A = () => <p dangerouslySetInnerHTML={{ __html: safe }} />;`),
      ).toEqual([]);
      expect(
        await run(`import { sanitize as purify } from "dompurify";
export const B = ({ md }) => <p dangerouslySetInnerHTML={{ __html: purify(md) }} />;`),
      ).toEqual([]);
    });

    it("follows a chain of variables to the sanitizer", async () => {
      const src = `import DOMPurify from "dompurify";
const rendered = DOMPurify.sanitize(marked.parse(md));
const html = rendered;
export const C = () => <div dangerouslySetInnerHTML={{ __html: html as string }} />;`;
      expect(await run(src)).toEqual([]);
    });

    it("still flags Markdown rendered with marked.parse alone", async () => {
      const src = `import { marked } from 'marked';
export default function Msg({ message }) {
  const html = marked.parse(message.content, { async: false }) as string;
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}`;
      const findings = await run(src);
      expect(findings).toHaveLength(1);
      expect(findings[0]!.line).toBe(4);
    });

    it("flags a nearby sanitize call that is not what gets rendered", async () => {
      const src = `import DOMPurify from "dompurify";
export const D = ({ bio, title }) => {
  const safeTitle = DOMPurify.sanitize(title);
  return <div title={safeTitle} dangerouslySetInnerHTML={{ __html: bio }} />;
};`;
      expect(await run(src)).toHaveLength(1);
    });

    it("flags raw database values and unsanitized props", async () => {
      expect(
        await run(`export const E = ({ p }) => (
  <div
    className="prose"
    dangerouslySetInnerHTML={{ __html: p.description ?? '' }}
  />
);`),
      ).toHaveLength(1);
    });

    it("keeps the id of an unchanged finding", async () => {
      const src = `<div dangerouslySetInnerHTML={{ __html: userContent }} />`;
      const [a] = await run(src);
      const [b] = await run(src);
      expect(a!.id).toBe(b!.id);
      expect(a!.evidence).toBe("dangerouslySetInnerHTML");
    });
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
