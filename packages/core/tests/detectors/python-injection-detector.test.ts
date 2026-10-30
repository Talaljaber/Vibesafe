import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { PythonInjectionDetector } from "../../src/detectors/python-injection-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const ctx = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake",
  projectContext: {} as never,
  files: Object.keys(files),
  config: { targetFiles: Object.keys(files) } as never,
  readFile: async (f) => files[f] ?? "",
});
const run = (src: string, file = "app/views.py") =>
  new PythonInjectionDetector().detect(ctx({ [file]: src }));
const rules = (f: { ruleId: string }[]) => f.map((x) => x.ruleId);
const lines = (...l: string[]) => l.join("\n") + "\n";

describe("python-injection-detector: shell command", () => {
  it("flags subprocess shell=True with an f-string (non-tainted: high/medium)", async () => {
    const f = await run(
      lines(
        "import subprocess",
        "def convert(path):",
        "    subprocess.run(",
        '        f"soffice --convert-to pdf {path}",',
        "        shell=True,",
        "    )",
      ),
    );
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({
      ruleId: "injection/python-shell-command",
      severity: "high",
      confidence: "medium",
      line: 3,
      endLine: 6,
    });
    expectRubric(f);
  });

  it("flags request-tainted os.system as critical/high, through tuple unpacking and format", async () => {
    const f = await run(
      lines(
        "import os",
        "def view(request):",
        '    host, port = request.GET.get("h"), 1',
        '    cmd = "ping -c1 {}".format(host)',
        "    os.system(cmd)",
      ),
    );
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "critical", confidence: "high", line: 5 });
    expectRubric(f);
  });

  it("is silent for literal commands, list form, shlex.quote and comments", async () => {
    const f = await run(
      lines(
        "import subprocess, shlex, os",
        "def a():",
        '    subprocess.run("ls -la /tmp", shell=True)',
        "def b(name):",
        '    subprocess.run(["convert", name, "out.png"])',
        "def c(name):",
        '    subprocess.run(f"convert {shlex.quote(name)} out.png", shell=True)',
        "def d(name):",
        '    # os.system(f"rm {name}")',
        '    """os.system(f"rm {name}")"""',
        "    subprocess.run(f'echo {name}', shell=False)",
      ),
    );
    expect(f).toHaveLength(0);
  });

  it("is silent for an int-coerced request value", async () => {
    const f = await run(
      lines(
        "import os",
        "def v(request):",
        '    n = int(request.GET["n"])',
        '    os.system(f"sleep {n}")',
      ),
    );
    expect(f).toHaveLength(0);
  });
});

describe("python-injection-detector: sql", () => {
  it("flags an f-string passed to cursor.execute", async () => {
    const f = await run(
      lines("def report(cursor, table):", '    cursor.execute(f"SELECT * FROM {table}")'),
    );
    expect(rules(f)).toEqual(["injection/python-sql-interpolation"]);
    expect(f[0]).toMatchObject({ severity: "high", confidence: "medium" });
    expectRubric(f);
  });

  it("flags queryset.extra(where=[f...]) fed by validated_data as critical", async () => {
    const f = await run(
      lines(
        "def post(self, request):",
        "    ser = QuerySerializer(data=request.data)",
        "    ser.is_valid(raise_exception=True)",
        '    flt = ser.validated_data.get("filter")',
        '    qs = Shipment.objects.all().extra(where=[f"({flt})"])',
      ),
    );
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "critical", confidence: "high", line: 5 });
  });

  it("flags % formatting into objects.raw and a built sql variable", async () => {
    const f = await run(
      lines(
        "def a(request):",
        '    q = request.GET["q"]',
        "    return Item.objects.raw(\"SELECT * FROM item WHERE n = '%s'\" % q)",
        "def b(cursor, col):",
        '    sql = "SELECT " + col + " FROM t"',
        "    cursor.execute(sql)",
      ),
    );
    expect(rules(f)).toEqual([
      "injection/python-sql-interpolation",
      "injection/python-sql-interpolation",
    ]);
    expect(f[0]!.severity).toBe("critical");
  });

  it("is silent for parameterized queries, params-based extra and constant SQL", async () => {
    const f = await run(
      lines(
        "def a(cursor, org):",
        '    cursor.execute("SELECT * FROM t WHERE org = %s", [org])',
        '    cursor.executemany("INSERT INTO t VALUES (%s, %s)", rows)',
        "def b(qs, v):",
        '    return qs.extra(where=["x = %s"], params=[v])',
        "def c(cursor):",
        '    sql = "SELECT 1"',
        "    cursor.execute(sql)",
      ),
    );
    expect(f).toHaveLength(0);
  });

  it("is silent for an allowlist-guarded f-string column (decoy shape)", async () => {
    const f = await run(
      lines(
        'COLUMNS = {"status", "origin"}',
        "def rollup(request, cursor):",
        '    col = request.GET.get("by", "status")',
        "    if col not in COLUMNS:",
        '        return {"error": "unsupported"}',
        '    sql = f"SELECT {col}, COUNT(*) FROM shipments GROUP BY {col}"',
        "    cursor.execute(sql)",
      ),
    );
    expect(f).toHaveLength(0);
  });
});

describe("python-injection-detector: yaml", () => {
  it("flags Loader=yaml.Loader, unsafe_load and load without a loader", async () => {
    const f = await run(
      lines(
        "import yaml",
        "a = yaml.load(raw, Loader=yaml.Loader)",
        "b = yaml.unsafe_load(raw)",
        "c = yaml.load(raw)",
        "d = yaml.load_all(raw, Loader=yaml.FullLoader)",
      ),
    );
    expect(f).toHaveLength(4);
    expect(new Set(rules(f))).toEqual(new Set(["injection/python-unsafe-yaml-load"]));
    expect(f.every((x) => x.severity === "high" && x.confidence === "high")).toBe(true);
    expectRubric(f);
  });

  it("is critical when the YAML comes from the request", async () => {
    const f = await run(
      lines("def v(request):", "    return yaml.load(request.body, Loader=yaml.UnsafeLoader)"),
    );
    expect(f[0]).toMatchObject({ severity: "critical", confidence: "high" });
  });

  it("is silent for safe_load and safe loaders", async () => {
    const f = await run(
      lines(
        "import yaml",
        "a = yaml.safe_load(raw)",
        "b = yaml.load(raw, Loader=yaml.SafeLoader)",
        "c = yaml.load(raw, Loader=yaml.CSafeLoader)",
        "d = yaml.load(raw, yaml.BaseLoader)",
        "# yaml.load(raw)",
      ),
    );
    expect(f).toHaveLength(0);
  });
});

describe("python-injection-detector: deserialization", () => {
  it("flags pickle.loads on a parameter and marshal.loads", async () => {
    const f = await run(
      lines(
        "import pickle, marshal",
        "def load(blob):",
        "    return pickle.loads(blob)",
        "def m(blob):",
        "    return marshal.loads(blob)",
      ),
    );
    expect(f).toHaveLength(2);
    expect(f[0]).toMatchObject({ severity: "high", confidence: "medium" });
    expectRubric(f);
  });

  it("is critical for request bytes and shelve/jsonpickle sinks", async () => {
    const f = await run(
      lines(
        "def v(request):",
        "    obj = pickle.loads(request.body)",
        "    s = shelve.open(request.GET['p'])",
        "    j = jsonpickle.decode(request.data)",
      ),
    );
    expect(f).toHaveLength(3);
    expect(f.every((x) => x.severity === "critical")).toBe(true);
  });

  it("is silent for dumps, literal files and comments", async () => {
    const f = await run(
      lines(
        "import pickle",
        "def a(obj):",
        "    return pickle.dumps(obj)",
        "def b():",
        '    with open("model.pkl", "rb") as fh:',
        "        return pickle.load(fh)",
        "def c():",
        '    return pickle.load(open("model.pkl", "rb"))',
        "    # pickle.loads(blob)",
      ),
    );
    expect(f).toHaveLength(0);
  });
});

describe("python-injection-detector: xxe", () => {
  it("flags lxml XMLParser with entity resolution and SAX external entities", async () => {
    const f = await run(
      lines(
        "from lxml import etree",
        "p = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)",
        "q = etree.XMLParser(no_network=False)",
        "import xml.sax",
        "r = xml.sax.make_parser()",
        "r.setFeature(xml.sax.handler.feature_external_ges, True)",
      ),
    );
    expect(f).toHaveLength(3);
    expect(f.every((x) => x.ruleId === "injection/python-xxe-parser")).toBe(true);
    expectRubric(f);
  });

  it("is silent for safe parsers, defusedxml and stdlib ElementTree", async () => {
    const f = await run(
      lines(
        "from lxml import etree",
        "from defusedxml import ElementTree as SafeET",
        "a = etree.XMLParser(resolve_entities=False)",
        "b = etree.XMLParser(no_network=True, load_dtd=False)",
        "c = SafeET.fromstring(raw)",
        "d = r.setFeature(xml.sax.handler.feature_external_ges, False)",
        "# etree.XMLParser(resolve_entities=True)",
      ),
    );
    expect(f).toHaveLength(0);
  });
});

describe("python-injection-detector: path traversal", () => {
  it("flags open() of a request-derived join, anchored where the path is built", async () => {
    const f = await run(
      lines(
        "import os",
        "def get(self, request):",
        '    name = request.query_params.get("name")',
        "    full = os.path.join(BASE, name)",
        "    x = 1",
        "    y = 2",
        "    z = 3",
        '    return FileResponse(open(full, "rb"))',
      ),
    );
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({
      ruleId: "injection/python-path-traversal",
      severity: "high",
      confidence: "high",
      line: 4,
      endLine: 8,
    });
    expectRubric(f);
  });

  it("flags send_file and os.remove on request data", async () => {
    const f = await run(
      lines(
        "from flask import request, send_file",
        "def dl():",
        '    p = request.args["f"]',
        "    os.remove(p)",
        "    return send_file(p)",
      ),
    );
    expect(f).toHaveLength(2);
  });

  it("is silent for basename, realpath+startswith, allowlists and non-request paths", async () => {
    const f = await run(
      lines(
        "def a(request):",
        '    name = request.GET["n"]',
        "    return open(os.path.join(BASE, os.path.basename(name)))",
        "def b(request):",
        '    p = os.path.realpath(os.path.join(BASE, request.GET["n"]))',
        "    if not p.startswith(BASE):",
        "        raise Http404",
        "    return open(p)",
        "def c(request):",
        '    n = request.GET["n"]',
        "    if n not in ALLOWED:",
        "        raise Http404",
        "    return open(os.path.join(BASE, n))",
        "def d(path):",
        "    return open(path)",
      ),
    );
    expect(f).toHaveLength(0);
  });
});

describe("python-injection-detector: scoping", () => {
  const bad = lines("def f(x):", '    os.system(f"rm {x}")', "    yaml.load(x)");

  it("ignores .ts files, tests and migrations", async () => {
    expect(await run(bad, "src/app.ts")).toHaveLength(0);
    expect(await run(bad, "app/tests/test_x.py")).toHaveLength(0);
    expect(await run(bad, "app/migrations/0001_x.py")).toHaveLength(0);
  });

  it("has stable ids across runs and never throws on odd input", async () => {
    const a = await run(bad);
    const b = await run(bad);
    expect(a.map((x) => x.id)).toEqual(b.map((x) => x.id));
    expect(a.length).toBeGreaterThan(0);
    expect(await run('def f(:\n    """unterminated\n os.system(')).toBeDefined();
  });

  it("caps findings per rule per file with a summary", async () => {
    const src = lines(...Array.from({ length: 40 }, (_, i) => `yaml.load(raw${i})`));
    const f = await run(src);
    expect(f.length).toBeLessThanOrEqual(26);
    expect(f.length).toBeGreaterThan(20);
  });
});
