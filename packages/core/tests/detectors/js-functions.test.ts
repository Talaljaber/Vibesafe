import { describe, it, expect } from "vitest";
import { createJsSource, type JsSource } from "../../src/detectors/utils/js-source.js";
import {
  enclosingFunction,
  expressionEnd,
  extractFunctions,
  handlerSpans,
  moduleSpan,
  patternBindings,
  type FunctionSpan,
} from "../../src/detectors/utils/js-functions.js";
import type { FileKind } from "../../src/detectors/utils/file-kind.js";

function spansOf(
  text: string,
  kind?: FileKind,
  jsx = false,
): { src: JsSource; spans: FunctionSpan[] } {
  const src = createJsSource(text, { jsx });
  return { src, spans: extractFunctions(src, kind === undefined ? undefined : { kind }) };
}

function body(src: JsSource, s: FunctionSpan): string {
  return src.text.slice(s.bodyStart, s.bodyEnd);
}

describe("extractFunctions: declarations", () => {
  it("finds function declarations with params, body and export", () => {
    const text = [
      "export async function POST(req: Request): Promise<{ ok: boolean }> {",
      "  return Response.json({ ok: true });",
      "}",
      "function helper<T>(a: T, { b = 1, ...rest }: Opts = {}) { return a; }",
    ].join("\n");
    const { src, spans } = spansOf(text);
    expect(spans).toHaveLength(2);
    const [post, helper] = spans as [FunctionSpan, FunctionSpan];
    expect(post).toMatchObject({
      name: "POST",
      kind: "function",
      async: true,
      exported: true,
      exportName: "POST",
      startLine: 1,
      endLine: 3,
      truncated: false,
    });
    expect(post.params.map((p) => p.names)).toEqual([["req"]]);
    expect(body(src, post)).toMatch(/^\{[\s\S]*\}$/);
    expect(post.start).toBe(text.indexOf("async"));
    expect(helper.name).toBe("helper");
    expect(helper.exported).toBe(false);
    expect(helper.params.map((p) => p.names)).toEqual([["a"], ["b", "rest"]]);
  });

  it("skips overload signatures and `.function` members", () => {
    const { spans } = spansOf(
      "function f(a: string): void;\nfunction f(a: unknown) { return a; }\nobj.function(1);",
    );
    expect(spans).toHaveLength(1);
    expect(spans[0]!.startLine).toBe(2);
  });
});

describe("extractFunctions: arrows", () => {
  it("finds block and expression arrows with their names", () => {
    const text = [
      "const handler = async (req, res) => {",
      "  res.send(1);",
      "};",
      "const double = x => x * 2",
      "const next = 1",
      "const typed = async (req: Request): Promise<Response> => {",
      "  return new Response();",
      "};",
    ].join("\n");
    const { src, spans } = spansOf(text);
    expect(spans.map((s) => s.name)).toEqual(["handler", "double", "typed"]);
    const [h, d, t] = spans as [FunctionSpan, FunctionSpan, FunctionSpan];
    expect(h.async).toBe(true);
    expect(h.params.map((p) => p.pattern)).toEqual(["req", "res"]);
    expect(d.expressionBody).toBe(true);
    expect(body(src, d)).toBe("x * 2");
    expect(d.params[0]!.names).toEqual(["x"]);
    expect(t.params.map((p) => p.names[0])).toEqual(["req"]);
    expect(t.expressionBody).toBe(false);
  });

  it("skips arrows inside type annotations", () => {
    const text = [
      "const f: (x: number) => void = (x) => { use(x); };",
      "const g = (cb: () => void) => cb();",
      "interface Props { onClick: (e: Event) => void; render(): string }",
      "type Fn = (a: string) => number;",
      "type Obj = { run: (a: string) => void };",
      "function h(): (x: number) => void { return (x) => use(x); }",
    ].join("\n");
    const { spans } = spansOf(text);
    const arrows = spans.filter((s) => s.kind === "arrow");
    expect(arrows.map((s) => s.startLine)).toEqual([1, 2, 6]);
    expect(arrows[0]!.params[0]!.names).toEqual(["x"]);
    expect(arrows[1]!.params[0]!.names).toEqual(["cb"]);
    expect(spans.some((s) => s.name === "render")).toBe(false);
  });

  it("keeps arrows that are object property values, ternary branches and call arguments", () => {
    const text = [
      "const o = { run: (x) => x + 1, nested: { go: async () => { await x(); } } };",
      "const t = ok ? (a) => a : (b) => b;",
      "items.forEach((item) => console.log(item));",
      "export default (req, res) => res.end();",
    ].join("\n");
    const { spans } = spansOf(text);
    const arrows = spans.filter((s) => s.kind === "arrow");
    expect(arrows).toHaveLength(6);
    expect(arrows[0]!.name).toBe("run");
    expect(arrows[1]!.name).toBe("go");
    const def = arrows[5]!;
    expect(def.exported).toBe(true);
    expect(def.exportName).toBe("default");
  });

  it("ends expression bodies at the statement boundary (ASI)", () => {
    const text = [
      "const a = (x) =>",
      "  x",
      "    .trim()",
      "    .toLowerCase()",
      "const b = 2",
    ].join("\n");
    const { src, spans } = spansOf(text);
    expect(body(src, spans[0]!)).toBe("x\n    .trim()\n    .toLowerCase()");
  });
});

describe("extractFunctions: methods", () => {
  it("finds class and object methods but not control statements", () => {
    const text = [
      "class Repo {",
      "  constructor(private readonly db: Db) {}",
      "  async findById(id: string): Promise<User | null> {",
      "    if (id) { return this.db.get(id); }",
      "    for (const x of y) {}",
      "    return null;",
      "  }",
      "  get size() { return 1; }",
      "}",
      "const api = { async GET(req) { return req; } };",
    ].join("\n");
    const { spans } = spansOf(text);
    expect(spans.map((s) => s.name)).toEqual(["constructor", "findById", "size", "GET"]);
    expect(spans.every((s) => s.kind === "method")).toBe(true);
    expect(spans[1]!.async).toBe(true);
    expect(spans[1]!.start).toBe(text.indexOf("async findById"));
    expect(spans[0]!.params[0]!.names).toEqual(["db"]);
  });
});

describe("extractFunctions: exports and wrappers", () => {
  it("records wrapper calls and the binding they are exported as", () => {
    const text = [
      "export const POST = withAuth(withRateLimit(async (req) => {",
      "  return Response.json({});",
      "}));",
      "export const PUT = withRole('admin', async (req) => new Response());",
    ].join("\n");
    const { spans } = spansOf(text, "next-app-route");
    expect(spans[0]).toMatchObject({
      name: "POST",
      exported: true,
      exportName: "POST",
      wrappers: ["withAuth", "withRateLimit"],
      role: "app-route-handler",
      httpMethod: "POST",
    });
    expect(spans[1]).toMatchObject({ name: "PUT", wrappers: ["withRole"], httpMethod: "PUT" });
  });

  it("maps export lists, export default identifiers and module.exports", () => {
    const route = spansOf(
      "async function handler(req) { return new Response(); }\nexport { handler as GET, handler as POST };",
      "next-app-route",
    ).spans[0]!;
    expect(route.exportNames).toEqual(["GET", "POST"]);
    expect(route.role).toBe("app-route-handler");
    expect(route.httpMethod).toBe("POST");

    const pages = spansOf(
      "async function handler(req, res) { res.end(); }\nexport default withAuth(handler);",
      "next-pages-api",
    ).spans[0]!;
    expect(pages).toMatchObject({ exportName: "default", role: "pages-api-handler" });
    expect(pages.wrappers).toEqual(["withAuth"]);

    const cjs = spansOf("const run = (a) => a;\nmodule.exports = run;").spans[0]!;
    expect(cjs).toMatchObject({ exported: true, exportName: "default" });
  });
});

describe("extractFunctions: roles", () => {
  it("assigns App Router handlers only to HTTP method exports", () => {
    const { spans } = spansOf(
      [
        "export async function GET() { return new Response(); }",
        "export async function helper() {}",
        "async function local() {}",
      ].join("\n"),
      "next-app-route",
    );
    expect(spans.map((s) => s.role)).toEqual(["app-route-handler", "other", "other"]);
    expect(spans[0]!.httpMethod).toBe("GET");
  });

  it("assigns pages API, server action, middleware and page roles", () => {
    expect(
      spansOf("export default async function handler(req, res) {}", "next-pages-api").spans[0]!
        .role,
    ).toBe("pages-api-handler");
    expect(
      spansOf('"use server";\nexport async function save(formData) {}', "next-server-action")
        .spans[0]!.role,
    ).toBe("server-action");
    expect(
      spansOf("export function middleware(request) {}", "next-middleware").spans[0]!.role,
    ).toBe("middleware");
    expect(
      spansOf("export default async function Page({ params }) {}", "next-server-component")
        .spans[0]!.role,
    ).toBe("page");
    expect(
      spansOf("export async function getServerSideProps(ctx) {}", "next-pages-page").spans[0]!.role,
    ).toBe("page");
  });

  it('recognises an inline "use server" function in any file', () => {
    const text = [
      "export default function Page() {",
      "  async function save(data) {",
      '    "use server";',
      "    await db.insert(data);",
      "  }",
      "}",
    ].join("\n");
    const { spans } = spansOf(text);
    expect(spans.find((s) => s.name === "save")!.role).toBe("server-action");
  });

  it("maps Express routes to their final handler and inline middleware", () => {
    const text = [
      "const express = require('express');",
      "const router = express.Router();",
      "router.post('/users', auth, (req, res, next) => { next(); }, async (req, res) => {",
      "  res.json(req.body);",
      "});",
      "router.get('/users/:id', listUser);",
      "async function listUser(req, res) { res.json({}); }",
      "const client = { get: (u) => fetch(u) };",
    ].join("\n");
    const { spans } = spansOf(text, "express-server");
    const roles = spans.map((s) => [s.name ?? s.startLine, s.role, s.httpMethod]);
    expect(roles).toEqual([
      [3, "express-middleware", undefined],
      [3, "express-handler", "POST"],
      ["listUser", "express-handler", "GET"],
      ["get", "other", undefined],
    ]);
  });

  it("handlerSpans returns only request entry points", () => {
    const src = createJsSource(
      "export async function POST(req) { const f = () => 1; return f(); }\nfunction util() {}",
    );
    const handlers = handlerSpans(src, { kind: "next-app-route" });
    expect(handlers.map((s) => s.name)).toEqual(["POST"]);
  });
});

describe("extractFunctions: nesting and truncation", () => {
  it("links parents and finds the enclosing function of an offset", () => {
    const text = [
      "export async function POST(req) {",
      "  const rows = items.map((it) => {",
      "    return db.query(it);",
      "  });",
      "}",
    ].join("\n");
    const { spans } = spansOf(text, "next-app-route");
    const [outer, inner] = spans as [FunctionSpan, FunctionSpan];
    expect(inner.parent).toBe(outer);
    expect(enclosingFunction(spans, text.indexOf("db.query"))).toBe(inner);
    expect(enclosingFunction(spans, text.indexOf("const rows"))).toBe(outer);
    expect(enclosingFunction(spans, text.length)).toBeUndefined();
  });

  it("marks a body whose braces never close as truncated", () => {
    const text = "export async function POST(req) {\n  if (x) {\n    run();\n";
    const { spans } = spansOf(text, "next-app-route");
    expect(spans[0]).toMatchObject({
      truncated: true,
      end: text.length,
      role: "app-route-handler",
    });
  });

  it("never throws on garbage and caches per source and kind", () => {
    const src = createJsSource("=> ) ( => { function ( => } class { a( {");
    expect(() => extractFunctions(src)).not.toThrow();
    const ok = createJsSource("function a() {}");
    expect(extractFunctions(ok)).toBe(extractFunctions(ok));
    expect(extractFunctions(ok, { kind: "js-module" })).not.toBe(extractFunctions(ok));
  });

  it("recognises functions in JSX files without tripping on JSX text", () => {
    const text = [
      "export default function Card({ user }) {",
      "  const onClick = () => alert(user.name);",
      "  return <div onClick={onClick}>Don't click (here) => now</div>;",
      "}",
    ].join("\n");
    const { spans } = spansOf(text, undefined, true);
    expect(spans.map((s) => s.name)).toEqual(["Card", "onClick"]);
    expect(spans[0]!.truncated).toBe(false);
  });
});

describe("helpers", () => {
  it("patternBindings lists bound names", () => {
    expect(patternBindings("req")).toEqual(["req"]);
    expect(patternBindings("{ id, body: payload, ...rest }")).toEqual(["id", "payload", "rest"]);
    expect(patternBindings("{ a = 1, b: { c } }")).toEqual(["a", "c"]);
    expect(patternBindings("[first, , [second], ...others]")).toEqual([
      "first",
      "second",
      "others",
    ]);
    expect(patternBindings("this")).toEqual([]);
  });

  it("expressionEnd stops at commas, closers and statement ends", () => {
    const text = "f(a + b, c); const x = y\n  + z\nnext()";
    const src = createJsSource(text);
    expect(text.slice(2, expressionEnd(src, 2))).toBe("a + b");
    const at = text.indexOf("y");
    expect(text.slice(at, expressionEnd(src, at))).toBe("y\n  + z");
  });

  it("moduleSpan covers the whole file", () => {
    const src = createJsSource("const a = 1;\nrun(a);\n");
    expect(moduleSpan(src)).toMatchObject({ kind: "module", start: 0, end: src.text.length });
  });
});
