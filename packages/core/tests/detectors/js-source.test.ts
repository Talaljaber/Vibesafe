import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import {
  createJsSource,
  createLineIndex,
  findMatchingBrace,
  getJsSource,
  isJsxPath,
  lineAt,
  lineText,
  maskCode,
  matchOf,
} from "../../src/detectors/utils/js-source.js";
import { maskCode as routeAnalyzerMaskCode } from "../../src/detectors/utils/route-analyzer.js";

/** Asserts the masking invariants: same length, same newline offsets, balanced brackets. */
function expectInvariants(text: string, jsx: boolean): string {
  const src = createJsSource(text, { jsx });
  expect(src.code.length).toBe(text.length);
  for (let i = 0; i < text.length; i++) expect(src.code[i] === "\n").toBe(text[i] === "\n");
  for (let i = 0; i < src.code.length; i++) {
    const c = src.code[i]!;
    if ("([{".includes(c) || ")]}".includes(c)) {
      const m = src.matchOf(i);
      expect(m, `bracket ${c} at ${i} is unbalanced`).toBeGreaterThanOrEqual(0);
      expect(src.matchOf(m)).toBe(i);
    }
  }
  return src.code;
}

describe("maskCode (non-JSX)", () => {
  it("is the same function route-analyzer re-exports", () => {
    expect(routeAnalyzerMaskCode).toBe(maskCode);
  });

  it("blanks comments, strings, regex literals and template text but keeps ${} code", () => {
    const text = [
      "const a = 'x(y'; // call() here",
      "/* block { */ const r = /[)]+/g;",
      "const t = `a ${b(1)} c(`;",
    ].join("\n");
    const code = maskCode(text);
    expect(code.length).toBe(text.length);
    expect(code).not.toContain("call");
    expect(code).not.toContain("block");
    expect(code).toContain("b(1)");
    const first = text.split("\n")[0]!;
    expect(code.split("\n")[0]).toBe("const a = '   ';".padEnd(first.length));
    expectInvariants(text, false);
  });

  it("treats a `<` in .ts code as an operator", () => {
    const text = "const x = a < b ? <Foo>bar : c;";
    expect(maskCode(text)).toBe(text);
  });
});

describe("maskCode (JSX)", () => {
  it("blanks text children with apostrophes and brackets", () => {
    const text = [
      "export default function Page() {",
      '  return <p className="x(y">Don\'t (really) do it {name}</p>;',
      "}",
    ].join("\n");
    const code = expectInvariants(text, true);
    expect(code).not.toContain("Don");
    expect(code).not.toContain("really");
    expect(code).toContain("{name}");
    expect(code).toContain("<p className=");
  });

  it("does not treat // or :// in JSX text as a comment", () => {
    const text = [
      "const A = () => (",
      '  <a href="https://example.com">Visit https://example.com // docs</a>',
      ");",
      "const after = run(1);",
    ].join("\n");
    const code = expectInvariants(text, true);
    expect(code).toContain("const after = run(1);");
    expect(code).not.toContain("docs");
  });

  it("handles closing tags, fragments, self-closing tags and nested containers", () => {
    const text = [
      "function List({ items }) {",
      "  return (",
      "    <>",
      "      {items.map((i) => <li key={i.id}>{i.name}'s item</li>)}",
      "      {ok ? <A x={1} /> : <B>no (way</B>}",
      "    </>",
      "  );",
      "}",
    ].join("\n");
    const code = expectInvariants(text, true);
    expect(code).toContain("items.map((i) =>");
    expect(code).toContain("{i.name}");
    expect(code).not.toContain("item<");
    expect(code).not.toContain("way");
  });

  it("keeps .tsx generics and comparisons as code", () => {
    const text = [
      "const id = <T,>(x: T) => x;",
      "const g = <T extends object>(x: T) => x;",
      "const lt = a < b && c > d;",
      "const [s, setS] = useState<string | null>(null);",
    ].join("\n");
    expect(expectInvariants(text, true)).toBe(text);
  });

  it("falls back to an operator when a `<` cannot be closed as an element", () => {
    const text = "const f = <T>(x: T): T => x;\nconst y = call(1);";
    const code = expectInvariants(text, true);
    expect(code).toContain("call(1)");
    expect(code).toContain("=> x;");
  });

  it("masks attribute strings but keeps attribute expressions", () => {
    const text = '<Link href="/a{b" onClick={() => go("x")} data-x=\'(\' />';
    const code = expectInvariants(`const el = ${text};`, true);
    expect(code).toContain("onClick={() => go(");
    expect(code).not.toContain("/a{b");
  });
});

describe("createLineIndex", () => {
  it("maps offsets to lines and back", () => {
    const text = "a\nbc\n\nd";
    const idx = createLineIndex(text);
    expect(idx.lineCount).toBe(4);
    expect(idx.lineAt(0)).toBe(1);
    expect(idx.lineAt(1)).toBe(1);
    expect(idx.lineAt(2)).toBe(2);
    expect(idx.lineAt(5)).toBe(3);
    expect(idx.lineAt(6)).toBe(4);
    expect(idx.lineAt(999)).toBe(4);
    expect(idx.lineStart(2)).toBe(2);
    expect(idx.lineEnd(2)).toBe(4);
    expect(idx.lineEnd(4)).toBe(text.length);
  });
});

describe("JsSource helpers", () => {
  it("lineAt/lineText/matchOf work as functions and methods", () => {
    const text = "const a = 1;\r\nfoo(bar[0], { x: 1 });\r\n";
    const src = createJsSource(text);
    const open = text.indexOf("(");
    const close = text.lastIndexOf(")");
    expect(matchOf(src, open)).toBe(close);
    expect(src.matchOf(close)).toBe(open);
    expect(matchOf(src, 0)).toBe(-1);
    expect(matchOf(src, -1)).toBe(-1);
    expect(lineAt(src, open)).toBe(2);
    expect(lineText(src, 2)).toBe("foo(bar[0], { x: 1 });");
    expect(src.lineText(1)).toBe("const a = 1;");
  });

  it("reports -1 for unbalanced brackets", () => {
    const src = createJsSource("function f() { if (x) {\n  return 1;\n}");
    expect(src.matchOf(src.text.indexOf("{"))).toBe(-1);
    expect(src.matchOf(src.text.indexOf("(x)"))).toBe(src.text.indexOf(")", 18));
  });

  it("ignores brackets inside comments and strings", () => {
    const src = createJsSource('f("(", /* ) */ g(1));');
    expect(src.matchOf(1)).toBe(src.text.length - 2);
  });

  it("isJsxPath covers jsx, tsx and plain js but not ts", () => {
    expect(isJsxPath("a/b.tsx")).toBe(true);
    expect(isJsxPath("a/b.jsx")).toBe(true);
    expect(isJsxPath("pages/index.js")).toBe(true);
    expect(isJsxPath("a/b.ts")).toBe(false);
    expect(isJsxPath("a/b.mts")).toBe(false);
  });
});

describe("findMatchingBrace", () => {
  it("finds the closing bracket in raw text, skipping strings and comments", () => {
    const text = 'console.log("a)", {\n  b: [1, ")"], // )\n});';
    const open = text.indexOf("(");
    expect(findMatchingBrace(text, open)).toBe(text.lastIndexOf(")"));
    expect(findMatchingBrace(text, text.indexOf("{"))).toBe(text.lastIndexOf("}"));
  });

  it("returns -1 for non-brackets, mismatches and unclosed brackets", () => {
    expect(findMatchingBrace("abc", 0)).toBe(-1);
    expect(findMatchingBrace("( ]", 0)).toBe(-1);
    expect(findMatchingBrace("f(a, b", 1)).toBe(-1);
  });

  it("accepts pre-masked code", () => {
    const text = "f('(')";
    expect(findMatchingBrace(text, 1, maskCode(text))).toBe(5);
  });
});

describe("getJsSource", () => {
  function contextOf(files: Record<string, string>): ScanContext & { reads: string[] } {
    const reads: string[] = [];
    return {
      reads,
      rootPath: "/project",
      files: Object.keys(files),
      projectContext: {} as ScanContext["projectContext"],
      config: {} as ScanContext["config"],
      readFile: (p: string) => {
        reads.push(p);
        const v = files[p];
        return v === undefined ? Promise.reject(new Error("missing")) : Promise.resolve(v);
      },
    };
  }

  it("reads once per file and context and picks JSX mode from the extension", async () => {
    const ctx = contextOf({ "a.tsx": "const x = <p>it's</p>;", "b.ts": "const y = 1;" });
    const a1 = await getJsSource(ctx, "a.tsx");
    const a2 = await getJsSource(ctx, "a.tsx");
    expect(a1).toBe(a2);
    expect(a1.jsx).toBe(true);
    expect(a1.file).toBe("a.tsx");
    expect(a1.code).not.toContain("it's");
    const b = await getJsSource(ctx, "b.ts");
    expect(b.jsx).toBe(false);
    expect(ctx.reads).toEqual(["a.tsx", "b.ts"]);
    const other = contextOf({ "a.tsx": "x" });
    expect(await getJsSource(other, "a.tsx")).not.toBe(a1);
  });

  it("never rejects: a failed read yields an empty source", async () => {
    const ctx = contextOf({});
    const src = await getJsSource(ctx, "missing.ts");
    expect(src.text).toBe("");
    expect(src.code).toBe("");
  });
});
