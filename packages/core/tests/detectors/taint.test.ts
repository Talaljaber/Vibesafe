import { describe, it, expect } from "vitest";
import { createJsSource, type JsSource } from "../../src/detectors/utils/js-source.js";
import {
  extractFunctions,
  moduleSpan,
  type FunctionSpan,
} from "../../src/detectors/utils/js-functions.js";
import {
  analyzeTaint,
  capSeverityForTrust,
  taintConfidence,
  type TaintHit,
  type TaintOptions,
  type TaintState,
} from "../../src/detectors/utils/taint.js";
import {
  CLIENT_SOURCES,
  SCRIPT_SOURCES,
  SERVER_SOURCES,
  sourcesForRuntime,
  type TaintRuntime,
} from "../../src/detectors/patterns/taint-sources.js";
import type { FileKind } from "../../src/detectors/utils/file-kind.js";

interface Fixture {
  src: JsSource;
  spans: FunctionSpan[];
  state: TaintState;
  /** Taint of the argument list of the last call to `callee` in the file. */
  sink(callee: string): TaintHit | undefined;
}

function analyze(
  text: string,
  kind: FileKind = "next-app-route",
  pick: (spans: FunctionSpan[], src: JsSource) => FunctionSpan = (s) => s[0]!,
  opts: TaintOptions = {},
): Fixture {
  const src = createJsSource(text);
  const spans = extractFunctions(src, { kind });
  const span = pick(spans, src);
  const state = analyzeTaint(src, span, opts);
  return {
    src,
    spans,
    state,
    sink(callee: string) {
      const open = text.lastIndexOf(`${callee}(`) + callee.length;
      const close = src.matchOf(open);
      return state.exprTaint(open + 1, close);
    },
  };
}

describe("analyzeTaint: request sources", () => {
  it("flags a source inside the sink as direct (high confidence)", () => {
    const f = analyze(
      "export async function GET(req) {\n  return db.query(`SELECT * FROM t WHERE id = ${req.query.id}`);\n}",
    );
    const hit = f.sink("db.query")!;
    expect(hit).toMatchObject({ path: "direct", trust: "remote", via: undefined });
    expect(hit.source.id).toBe("request-query");
    expect(taintConfidence(hit)).toBe("high");
  });

  it("follows const, destructuring and alias bindings (binding path)", () => {
    const f = analyze(
      [
        "export async function POST(req: Request) {",
        "  const body = await req.json();",
        "  const { filter } = body;",
        "  const where = filter;",
        "  return sql.unsafe('SELECT * FROM t WHERE ' + where);",
        "}",
      ].join("\n"),
    );
    const hit = f.sink("sql.unsafe")!;
    expect(hit).toMatchObject({ path: "binding", via: "where" });
    expect(hit.source.id).toBe("request-payload");
    expect(taintConfidence(hit)).toBe("high");
  });

  it("seeds App Router route params from the second handler argument", () => {
    const f = analyze(
      [
        "export async function DELETE(_req: Request, { params }: { params: { id: string } }) {",
        "  const id = params.id;",
        "  await db.execute(`DELETE FROM t WHERE id = ${id}`);",
        "}",
      ].join("\n"),
    );
    const hit = f.sink("db.execute")!;
    expect(hit.source.id).toBe("route-params");
    expect(hit.path).toBe("binding");
  });

  it("treats server action arguments as tainted", () => {
    const f = analyze(
      [
        '"use server";',
        "export async function rename(formData: FormData) {",
        "  const name = formData.get('name');",
        "  exec(`mv a ${name}`);",
        "}",
      ].join("\n"),
      "next-server-action",
    );
    const hit = f.sink("exec")!;
    expect(hit.source.id).toBe("server-action-argument");
    expect(hit.path).toBe("binding");
  });

  it("uses the handler's own request parameter name", () => {
    const f = analyze(
      [
        "const app = express();",
        "app.post('/run', (r, res) => {",
        "  exec(r.body.cmd);",
        "});",
      ].join("\n"),
      "express-server",
    );
    expect(f.sink("exec")!.source.id).toBe("request-param");
  });

  it("seeds page params and searchParams", () => {
    const f = analyze(
      [
        "export default async function Page({ searchParams }) {",
        "  const q = searchParams.q;",
        "  redirect(q);",
        "}",
      ].join("\n"),
      "next-server-component",
    );
    expect(f.sink("redirect")!.source.id).toBe("page-props");
  });

  it("taints for-of loop variables over tainted collections", () => {
    const f = analyze(
      [
        "export async function POST(req) {",
        "  for (const item of req.body.items) {",
        "    await fs.readFile(item.path);",
        "  }",
        "}",
      ].join("\n"),
    );
    expect(f.sink("fs.readFile")).toMatchObject({ path: "binding", via: "item" });
  });

  it("follows += concatenation and push() into a collection", () => {
    const f = analyze(
      [
        "export async function GET(req) {",
        "  let sql = 'SELECT * FROM t';",
        "  sql += ` WHERE a = '${req.query.a}'`;",
        "  const parts = [];",
        "  parts.push(`b = ${req.query.b}`);",
        "  const where = parts.join(' AND ');",
        "  run1(sql);",
        "  run2(where);",
        "}",
      ].join("\n"),
    );
    expect(f.sink("run1")).toMatchObject({ path: "binding", via: "sql" });
    expect(f.sink("run2")).toMatchObject({ path: "binding", via: "where" });
  });
});

describe("analyzeTaint: negatives and cleaning", () => {
  const handler = (lines: string[]): string =>
    ["export async function GET(req) {", ...lines.map((l) => `  ${l}`), "}"].join("\n");

  it("ignores sources in comments and strings", () => {
    const f = analyze(handler(["// req.body.x", "db.query('req.query.id', /* req.body */ 1);"]));
    expect(f.sink("db.query")).toBeUndefined();
  });

  it("numeric coercions clean taint", () => {
    const f = analyze(
      handler([
        "const id = Number(req.query.id);",
        "const page = parseInt(req.query.page, 10);",
        "db.query(`SELECT ${id} ${page} ${Math.max(1, req.query.n)}`);",
      ]),
    );
    expect(f.sink("db.query")).toBeUndefined();
  });

  it("boolean and length expressions are clean", () => {
    const f = analyze(
      handler([
        "const ok = ALLOWED.includes(req.query.table);",
        "const isAdmin = req.body.role === 'admin';",
        "const dir = req.query.dir === 'asc' ? 'ASC' : 'DESC';",
        "const n = req.body.items.length;",
        "const flag = !req.query.x;",
        "db.query(`SELECT ${ok} ${isAdmin} ${dir} ${n} ${flag}`);",
      ]),
    );
    expect(f.sink("db.query")).toBeUndefined();
  });

  it("keeps a ternary branch that returns the tainted value", () => {
    const f = analyze(handler(["const v = req.query.v ? req.query.v : 'x';", "run(v);"]));
    expect(f.sink("run")).toMatchObject({ path: "binding", via: "v" });
  });

  it("does not propagate through awaited unknown calls (I/O results)", () => {
    const f = analyze(
      handler([
        "const user = await db.user.findUnique({ where: { id: req.query.id } });",
        "redirect(user.url);",
      ]),
    );
    expect(f.sink("redirect")).toBeUndefined();
  });

  it("marks a non-awaited unknown call as a boundary (indirect, medium)", () => {
    const f = analyze(handler(["const q = buildQuery(req.body.filter);", "db.raw(q);"]));
    const hit = f.sink("db.raw")!;
    expect(hit.path).toBe("indirect");
    expect(taintConfidence(hit)).toBe("medium");
  });

  it("propagates through pass-through calls without a boundary", () => {
    const f = analyze(
      handler([
        "const file = path.join(ROOT, String(req.query.file).trim());",
        "fs.readFileSync(file);",
      ]),
    );
    expect(f.sink("fs.readFileSync")).toMatchObject({ path: "binding", cleanedBy: [] });
  });

  it("records non-numeric cleaners on the hit", () => {
    const f = analyze(
      handler([
        "const name = path.basename(req.query.file);",
        "const q = encodeURIComponent(req.query.q);",
        "a(name);",
        "b(q);",
      ]),
    );
    expect(f.sink("a")!.cleanedBy).toEqual(["path"]);
    expect(f.sink("b")!.cleanedBy).toEqual(["url-encode"]);
  });

  it("member names and object keys are not binding uses", () => {
    const f = analyze(
      handler(["const id = req.query.id;", "const x = other.id;", "run({ id: 1 }, x, typeof id);"]),
    );
    expect(f.sink("run")).toBeUndefined();
  });

  it("a clean reassignment replaces the taint", () => {
    const f = analyze(handler(["let q = req.query.q;", "q = 'fixed';", "run(q);"]));
    expect(f.sink("run")).toBeUndefined();
  });

  it("a function value is not tainted data", () => {
    const f = analyze(handler(["const go = () => req.query.x;", "run(go);"]));
    expect(f.sink("run")).toBeUndefined();
  });

  it("server sources do not apply to client analysis and vice versa", () => {
    const text = "function f() { run(req.body.x); other(window.location.search); }";
    const server = analyze(text, "js-module");
    expect(server.sink("other")).toBeUndefined();
    const client = analyze(text, "js-module", (s) => s[0]!, { runtime: "client" });
    expect(client.sink("run")).toBeUndefined();
    expect(client.sink("other")!.source.id).toBe("location");
  });
});

describe("analyzeTaint: callbacks, closures and scopes", () => {
  it("taints callback parameters of tainted collections as indirect", () => {
    const f = analyze(
      [
        "export async function POST(req) {",
        "  await Promise.all(req.body.ids.map(async (id) => {",
        "    await db.query(`DELETE FROM t WHERE id = ${id}`);",
        "  }));",
        "}",
      ].join("\n"),
    );
    expect(f.sink("db.query")).toMatchObject({ path: "indirect", via: "id" });
  });

  it("closures see outer bindings as indirect", () => {
    const f = analyze(
      [
        "export async function GET(req) {",
        "  const id = req.query.id;",
        "  const run = () => db.query(`SELECT ${id}`);",
        "  return run();",
        "}",
      ].join("\n"),
    );
    expect(f.sink("db.query")).toMatchObject({ path: "indirect", via: "id" });
  });

  it("a callback parameter shadows an outer tainted name only inside the callback", () => {
    const text = [
      "export async function GET(req) {",
      "  const id = req.query.id;",
      "  safeList.forEach((id) => inner(id));",
      "  outer(id);",
      "}",
    ].join("\n");
    const f = analyze(text);
    expect(f.sink("inner")).toBeUndefined();
    expect(f.sink("outer")).toMatchObject({ path: "binding", via: "id" });
  });
});

describe("analyzeTaint: options and memoization", () => {
  const helper = "function run(code, label) {\n  return eval(code + label);\n}";

  it("seedParams taints chosen parameters (indirect) and is not memoized", () => {
    const seeded = analyze(helper, "js-module", (s) => s[0]!, { seedParams: [0] });
    const hit = seeded.sink("eval")!;
    expect(hit).toMatchObject({ path: "indirect", via: "code" });
    expect(hit.source.id).toBe("parameter");
    const plain = analyzeTaint(seeded.src, seeded.spans[0]!);
    expect(plain).not.toBe(seeded.state);
    const open = helper.indexOf("eval(") + 4;
    expect(plain.exprTaint(open + 1, seeded.src.matchOf(open))).toBeUndefined();
  });

  it("inherited (closure) names are tainted as indirect; parameters shadow them", () => {
    const base = analyze(
      "export async function GET(req) { return req.query.x; }",
      "next-app-route",
    );
    const inheritedHit = base.state.exprTaint(0, base.src.text.length)!;
    const inherited = new Map([["label", inheritedHit]]);
    const free = analyze(
      "function run(code) {\n  return eval(code + label);\n}",
      "js-module",
      (s) => s[0]!,
      {
        inherited,
      },
    );
    expect(free.sink("eval")).toMatchObject({ path: "indirect", via: "label" });
    const shadowed = analyze(helper, "js-module", (s) => s[0]!, { inherited });
    expect(shadowed.sink("eval")).toBeUndefined();
  });

  it("memoizes default-option calls per source, span and runtime", () => {
    const f = analyze("export async function GET(req) { run(req.body); }");
    const span = f.spans[0]!;
    expect(analyzeTaint(f.src, span)).toBe(f.state);
    expect(analyzeTaint(f.src, span, { runtime: "server" })).toBe(f.state);
    expect(analyzeTaint(f.src, span, { runtime: "client" })).not.toBe(f.state);
    expect(analyzeTaint(f.src, span, { sources: SERVER_SOURCES })).not.toBe(f.state);
  });

  it("analyses top-level script code with local trust", () => {
    const text = "const target = process.argv[2];\nexecSync(`deploy ${target}`);\n";
    const src = createJsSource(text);
    const state = analyzeTaint(src, moduleSpan(src), { runtime: "script" });
    const open = text.indexOf("execSync(") + 8;
    const hit = state.exprTaint(open + 1, src.matchOf(open))!;
    expect(hit).toMatchObject({ trust: "local", path: "binding", via: "target" });
    expect(capSeverityForTrust("critical", hit.trust)).toBe("high");
    expect(capSeverityForTrust("critical", "remote")).toBe("critical");
    expect(capSeverityForTrust("medium", "local")).toBe("medium");
  });

  it("exposes bindings and bindingAt", () => {
    const f = analyze(
      "export async function GET(req) {\n  const a = req.query.a;\n  const b = 1;\n  run(a, b);\n}",
    );
    const at = f.src.text.indexOf("run(");
    expect(f.state.bindingAt("a", at)?.hit?.source.id).toBe("request-query");
    expect(f.state.bindingAt("b", at)).toBeUndefined();
    expect(f.state.bindingAt("a", f.src.text.indexOf("const a"))).toBeUndefined();
    expect(f.state.bindings.map((b) => [b.name, b.hit !== undefined])).toEqual([
      ["req", false],
      ["a", true],
      ["b", false],
    ]);
  });

  it("never throws on garbage", () => {
    const src = createJsSource("const = = ( req.body => { let [ = ");
    expect(() => analyzeTaint(src, moduleSpan(src)).exprTaint(0, src.text.length)).not.toThrow();
  });
});

describe("guardBefore", () => {
  const text = [
    "export async function GET(req) {",
    "  const table = req.query.table;",
    "  const name = req.query.name;",
    "  const file = req.query.file;",
    "  const kind = req.query.kind;",
    "  const loose = req.query.loose;",
    "  if (!ALLOWED_TABLES.includes(table)) return new Response('no', { status: 400 });",
    "  if (!/^[a-z]+$/.test(name)) {",
    "    throw new Error('bad');",
    "  }",
    "  if (file.includes('..')) return notFound();",
    "  if (kind !== 'a') return;",
    "  if (!loose) console.log('missing');",
    "  sink(table, name, file, kind, loose);",
    "}",
  ].join("\n");
  const f = analyze(text);
  const at = text.indexOf("sink(");

  it("recognises allowlist, regex, contains and equality guards that exit early", () => {
    expect(f.state.guardBefore("table", at)?.kind).toBe("allowlist");
    expect(f.state.guardBefore("name", at)?.kind).toBe("regex");
    expect(f.state.guardBefore("file", at)?.kind).toBe("contains-check");
    expect(f.state.guardBefore("kind", at)?.kind).toBe("allowlist");
  });

  it("ignores checks that do not exit and guards after the offset", () => {
    expect(f.state.guardBefore("loose", at)).toBeUndefined();
    expect(f.state.guardBefore("table", text.indexOf("if (!ALLOWED"))).toBeUndefined();
  });
});

describe("taint sources", () => {
  it("selects sources per runtime", () => {
    const runtimes: [TaintRuntime, unknown][] = [
      ["server", SERVER_SOURCES],
      ["client", CLIENT_SOURCES],
      ["script", SCRIPT_SOURCES],
    ];
    for (const [r, expected] of runtimes) expect(sourcesForRuntime(r)).toBe(expected);
  });

  it("source patterns carry no g/y flag and match their examples", () => {
    for (const s of [...SERVER_SOURCES, ...CLIENT_SOURCES, ...SCRIPT_SOURCES])
      expect(s.pattern.flags).not.toMatch(/[gy]/);
    const any = (code: string, list = SERVER_SOURCES): string | undefined =>
      list.find((s) => s.pattern.test(code))?.id;
    expect(any("req.body.x")).toBe("request-body");
    expect(any("await request.formData()")).toBe("request-payload");
    expect(any("(await headers()).get('x')")).toBe("next-headers");
    expect(any("res.headers()")).toBeUndefined();
    expect(any("ctx.querystring")).toBe("koa-request");
    expect(any("c.req.param('id')")).toBe("hono-request");
    expect(any("event.queryStringParameters.id")).toBe("lambda-event");
    expect(any("prequest.body")).toBeUndefined();
    expect(any("new URLSearchParams(window.location.search)", CLIENT_SOURCES)).toBe("location");
    expect(any("useSearchParams()", CLIENT_SOURCES)).toBe("router-params");
    expect(any("mylocation.search", CLIENT_SOURCES)).toBeUndefined();
  });
});
