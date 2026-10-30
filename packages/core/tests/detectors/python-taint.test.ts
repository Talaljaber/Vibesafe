import { describe, it, expect } from "vitest";
import { pythonStatements, scanPythonLines } from "../../src/detectors/utils/python-source.js";
import {
  analyzeFunction,
  maskPython,
  nonConstant,
  pythonFunctions,
  splitCallArgs,
} from "../../src/detectors/utils/python-taint.js";

const fnOf = (src: string, name: string) => {
  const stmts = pythonStatements(scanPythonLines(src));
  return pythonFunctions(stmts).find((f) => f.name === name);
};
const m = maskPython;

describe("python-taint: functions and masking", () => {
  it("finds def spans by indentation, including async and nested defs", () => {
    const src =
      "def a(x):\n    y = 1\n    def inner():\n        pass\nasync def b():\n    return 2\nz = 3\n";
    const funcs = pythonFunctions(pythonStatements(scanPythonLines(src)));
    expect(funcs.map((f) => f.name)).toEqual(["a", "inner", "b"]);
    expect(funcs[0]).toMatchObject({ start: 0, end: 3 });
    expect(funcs[2]).toMatchObject({ start: 4, end: 5 });
  });

  it("masks plain strings and keeps f-string fields", () => {
    expect(m('x = "os.system(a)"')).toBe('x = "~~~~~~~~~~~~"');
    expect(m('x = f"a {b} {{c}}"')).toContain("⟦b⟧");
    expect(m('x = f"a {b} {{c}}"')).not.toContain("c}");
    expect(m('"""doc os.system(x)"""')).not.toContain("os");
    expect(m('x = f"{a}"').length).toBe('x = f"{a}"'.length);
  });

  it("splits top-level call arguments", () => {
    const t = m('run(f"a {b, c}", shell=True, env={"a": 1, "b": 2})');
    expect(splitCallArgs(t, 3).length).toBe(3);
  });
});

describe("python-taint: sources and propagation", () => {
  const taintedAt = (src: string, expr: string) => {
    const fn = fnOf(src, "v");
    return analyzeFunction(fn).isTainted(m(expr), fn!.end + 1);
  };

  it("tracks Django, DRF and Flask sources", () => {
    for (const s of [
      'request.GET["a"]',
      'request.POST.get("a")',
      "request.data",
      "request.query_params",
      "request.FILES",
      "request.body",
      "request.headers",
      "request.COOKIES",
      "request.META",
      'request.args.get("a")',
      "request.form",
      "request.json",
      "request.values",
      "request.files",
      "request.get_json()",
    ]) {
      expect(taintedAt("def v(request):\n    pass\n", s), s).toBe(true);
    }
    expect(taintedAt("def v(request):\n    pass\n", "request.user.org_id")).toBe(false);
  });

  it("propagates through assignment, f-strings, %, format, + and os.path.join, depth <= 5", () => {
    const src = [
      "def v(request):",
      '    a = request.GET["a"]',
      '    b = f"x{a}"',
      '    c = "%s" % b',
      '    d = "{}".format(c)',
      '    e = "p" + d',
      "    f = os.path.join(BASE, e)",
      "    g = f",
      "",
    ].join("\n");
    expect(taintedAt(src, "b")).toBe(true);
    expect(taintedAt(src, "e")).toBe(true);
    expect(taintedAt(src, "g")).toBe(false); // depth 6 from the source
    expect(taintedAt(src, "BASE")).toBe(false);
  });

  it("follows tuple unpacking and for loops", () => {
    const src =
      'def v(request):\n    a, b = request.GET["a"], 1\n    for k in request.POST:\n        pass\n';
    expect(taintedAt(src, "a")).toBe(true);
    expect(taintedAt(src, "k")).toBe(true);
  });

  it("treats validated_data of a serializer built from request data as tainted", () => {
    const src =
      'def v(request):\n    ser = S(data=request.data)\n    ser.is_valid()\n    n = ser.validated_data["n"]\n';
    expect(taintedAt(src, "n")).toBe(true);
    const other = 'def v(request):\n    ser = S(data={"a": 1})\n    n = ser.validated_data["n"]\n';
    expect(taintedAt(other, "n")).toBe(false);
  });

  it("stops at cleaners and allowlist guards", () => {
    const src = [
      "def v(request):",
      '    n = int(request.GET["n"])',
      '    p = os.path.basename(request.GET["p"])',
      '    q = shlex.quote(request.GET["q"])',
      '    u = uuid.UUID(request.GET["u"])',
      '    c = request.GET["c"]',
      "    if c not in ALLOWED:",
      "        return None",
      '    d = request.GET["d"]',
      "    if d in ALLOWED:",
      "        use(d)",
      "",
    ].join("\n");
    for (const n of ["n", "p", "q", "u"]) expect(taintedAt(src, n), n).toBe(false);
    expect(taintedAt(src, "c")).toBe(false);
    const t = analyzeFunction(fnOf(src, "v"));
    expect(t.isTainted(m("d"), 10)).toBe(false); // inside the `if d in ALLOWED` block
    expect(t.isTainted(m("d"), 11)).toBe(true); // after the block
  });

  it("is bounded: functions over 200 statements do not throw", () => {
    const body = Array.from({ length: 400 }, (_, i) => `    v${i} = request.GET["a"]`).join("\n");
    const fn = fnOf(`def v(request):\n${body}\n`, "v");
    expect(() => analyzeFunction(fn).isTainted(m("v1"), 500)).not.toThrow();
  });
});

describe("python-taint: nonConstant", () => {
  it("is true for f-string fields, % operands, .format args and + concatenation", () => {
    expect(nonConstant('f"select {a}"')).toBe(true);
    expect(nonConstant('"select %s" % a')).toBe(true);
    expect(nonConstant('"select {}".format(a)')).toBe(true);
    expect(nonConstant('"select " + a')).toBe(true);
  });

  it("is false for literals, constants and cleaned values", () => {
    expect(nonConstant('"select 1"')).toBe(false);
    expect(nonConstant('f"select {TABLE}"')).toBe(false);
    expect(nonConstant('f"select {int(a)}"')).toBe(false);
    expect(nonConstant('f"x {shlex.quote(a)}"')).toBe(false);
    expect(nonConstant('"a" + "b"')).toBe(false);
    expect(nonConstant('"a %s"')).toBe(false);
  });
});
