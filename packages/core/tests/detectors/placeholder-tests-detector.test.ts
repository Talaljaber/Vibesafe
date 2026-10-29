import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import {
  PlaceholderTestsDetector,
  classifyTestFile,
  isEchoOnlyScript,
} from "../../src/detectors/placeholder-tests-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const detector = new PlaceholderTestsDetector();

const createContext = (files: Record<string, string>, includeTests = false): ScanContext => ({
  rootPath: "/fake/path",
  projectContext: {} as ScanContext["projectContext"],
  files: Object.keys(files),
  config: { rootPath: "/fake/path", includeTests },
  readFile: async (file) => files[file] ?? "",
});

const pkg = (test: string | undefined): string =>
  JSON.stringify({ name: "app", scripts: { dev: "next dev", ...(test ? { test } : {}) } }, null, 2);

async function run(files: Record<string, string>, includeTests = false) {
  const findings = await detector.detect(createContext(files, includeTests));
  expectRubric(findings);
  return findings;
}

const TODO_ONLY = `import { describe, it } from "vitest";

describe("app", () => {
  it.todo("add tests");
});
`;

const TRIVIAL = `import { test, expect } from "vitest";
test("works", () => {
  expect(true).toBe(true);
  expect(1).toEqual(1);
});
`;

const REAL = `import { describe, it, expect } from "vitest";
import { add } from "../src/math";
describe("add", () => {
  it("adds", () => {
    expect(add(1, 2)).toBe(3);
  });
  it.todo("handles overflow");
});
`;

describe("PlaceholderTestsDetector (package.json only, default mode)", () => {
  it("flags an echo placeholder test script", async () => {
    const findings = await run({
      "package.json": pkg('echo "Error: no test specified" && exit 1'),
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe("structure/placeholder-only-tests");
    expect(findings[0]!.confidence).toBe("high");
    expect(findings[0]!.severity).toBe("low");
    expect(findings[0]!.line).toBe(5);
  });

  it("flags --passWithNoTests at medium confidence", async () => {
    for (const test of ["vitest run --passWithNoTests", "jest --passWithNoTests --ci"]) {
      const findings = await run({ "package.json": pkg(test) });
      expect(findings).toHaveLength(1);
      expect(findings[0]!.title).toContain("--passWithNoTests");
      expect(findings[0]!.confidence).toBe("medium");
    }
  });

  it("does not flag real test commands, missing scripts or other scripts", async () => {
    expect(await run({ "package.json": pkg("vitest run") })).toEqual([]);
    expect(await run({ "package.json": pkg("jest --coverage") })).toEqual([]);
    expect(await run({ "package.json": pkg(undefined) })).toEqual([]);
    expect(
      await run({
        "package.json": JSON.stringify({ scripts: { lint: "echo lint", test: "node --test" } }),
      }),
    ).toEqual([]);
    expect(await run({ "package.json": "{ broken" })).toEqual([]);
  });

  it("does not flag an echo that precedes a real test runner", async () => {
    for (const test of [
      "echo running && vitest run",
      "echo 'unit tests'; jest --ci",
      'echo "a && b" && node --test',
      "echo start || exit 1 && mocha",
      "echo hi | tee log.txt",
    ]) {
      expect(await run({ "package.json": pkg(test) }), test).toEqual([]);
    }
  });

  it("locates the test script in a one-line scripts block", async () => {
    const text = [
      "{",
      '  "name": "app",',
      '  "scripts": { "dev": "next dev", "test": "echo \\"no tests\\" && exit 1" }',
      "}",
    ].join("\n");
    const findings = await run({ "package.json": text });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.line).toBe(3);
  });

  it("reads a package.json that starts with a UTF-8 BOM", async () => {
    const findings = await run({ "package.json": "﻿" + pkg("echo none && exit 1") });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.line).toBe(5);
  });

  it("does not read test files unless includeTests is set", async () => {
    const files = { "package.json": pkg("vitest run"), "tests/app.test.ts": TODO_ONLY };
    expect(await run(files)).toEqual([]);
  });
});

describe("PlaceholderTestsDetector (includeTests)", () => {
  it("flags a test file that only holds todo tests, on the placeholder line", async () => {
    const findings = await run(
      { "package.json": pkg("vitest run --passWithNoTests"), "tests/app.test.ts": TODO_ONLY },
      true,
    );
    const file = findings.find((f) => f.file === "tests/app.test.ts")!;
    expect(file.line).toBe(4);
    expect(file.title).toContain("todo");
    expect(findings.some((f) => f.file === "package.json")).toBe(true);
  });

  it("flags a test file whose only assertions compare constants", async () => {
    const findings = await run({ "src/__tests__/smoke.spec.tsx": TRIVIAL }, true);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.title).toContain("constants");
    expect(findings[0]!.line).toBe(3);
  });

  it("does not flag real tests and drops --passWithNoTests once a real test exists", async () => {
    const findings = await run(
      {
        "package.json": pkg("vitest run --passWithNoTests"),
        "tests/math.test.ts": REAL,
        "tests/app.test.ts": TODO_ONLY,
      },
      true,
    );
    expect(findings.map((f) => f.file)).toEqual(["tests/app.test.ts"]);
  });

  it("ignores placeholders inside comments and non-test files", async () => {
    const commented = `import { it, expect } from "vitest";
// it.todo("later")
it("real", () => { expect(sum(2, 2)).toBe(4); });
`;
    expect(await run({ "tests/a.test.ts": commented }, true)).toEqual([]);
    expect(await run({ "tests/helpers.ts": TODO_ONLY, "docs/notes.md": TODO_ONLY }, true)).toEqual(
      [],
    );
  });
});

describe("classifyTestFile", () => {
  it("returns null for a file with no tests at all", () => {
    expect(classifyTestFile("export const x = 1;")).toBeNull();
  });
  it("counts it.each / test.each as real tests", () => {
    const code = `it.each([[1, 2, 3]])("adds %i + %i", (a, b, c) => { expect(add(a, b)).toBe(c); });
test.each\`a | b\`("t", () => { expect(sum()).toBe(0); });
it.todo("overflow");`;
    expect(classifyTestFile(code)?.placeholderOnly).toBe(false);
    const skipped = `it.todo("x");\ntest.skip.each([1])("y", () => {});`;
    expect(classifyTestFile(skipped)?.placeholderOnly).toBe(true);
  });
  it("isEchoOnlyScript accepts npm's default placeholder and plain echoes only", () => {
    expect(isEchoOnlyScript('echo "Error: no test specified" && exit 1')).toBe(true);
    expect(isEchoOnlyScript("echo 'no tests'")).toBe(true);
    expect(isEchoOnlyScript("echo skip; exit 0")).toBe(true);
    expect(isEchoOnlyScript("exit 0")).toBe(false);
    expect(isEchoOnlyScript("echo running && vitest run")).toBe(false);
    expect(isEchoOnlyScript("vitest run && echo done")).toBe(false);
  });
  it("treats supertest-style .expect(...) as a real assertion", () => {
    const code = `it("ok", async () => { await request(app).get("/").expect(200); });`;
    expect(classifyTestFile(code)?.placeholderOnly).toBe(false);
  });
});

describe("PlaceholderTestsDetector with context.testFiles (default mode)", () => {
  const ctx = (files: Record<string, string>, testFiles?: string[]): ScanContext => ({
    ...createContext(files, false),
    testFiles,
  });
  const run2 = async (files: Record<string, string>, testFiles?: string[]) => {
    const findings = await detector.detect(ctx(files, testFiles));
    expectRubric(findings);
    return findings;
  };

  it("flags a todo-only test file", async () => {
    const f = await run2({ "package.json": pkg("vitest run"), "tests/a.test.ts": TODO_ONLY }, [
      "tests/a.test.ts",
    ]);
    expect(f.map((x) => x.file)).toEqual(["tests/a.test.ts"]);
    expect(f[0]?.line).toBe(4);
  });

  it("flags a constant-assertion-only test file", async () => {
    const f = await run2({ "package.json": pkg("vitest run"), "a.spec.ts": TRIVIAL }, [
      "a.spec.ts",
    ]);
    expect(f).toHaveLength(1);
    expect(f[0]?.file).toBe("a.spec.ts");
  });

  it("is silent for a real test and suppresses --passWithNoTests", async () => {
    const real = `import { it, expect } from "vitest";\nit("adds", () => { expect(sum(1, 2)).toBe(3); });\n`;
    const f = await run2(
      { "package.json": pkg("vitest run --passWithNoTests"), "a.test.ts": real },
      ["a.test.ts"],
    );
    expect(f).toEqual([]);
  });

  it("keeps package.json findings only when testFiles is undefined", async () => {
    const f = await run2(
      { "package.json": pkg("vitest run --passWithNoTests"), "a.test.ts": TODO_ONLY },
      undefined,
    );
    expect(f.map((x) => x.file)).toEqual(["package.json"]);
  });

  it("is silent for a comment-only todo", async () => {
    const f = await run2({ "package.json": pkg("vitest run"), "a.test.ts": `// it.todo("x")\n` }, [
      "a.test.ts",
    ]);
    expect(f).toEqual([]);
  });

  it("has stable ids across two runs", async () => {
    const files = { "package.json": pkg("vitest run"), "a.test.ts": TODO_ONLY };
    const a = await run2(files, ["a.test.ts"]);
    const b = await run2(files, ["a.test.ts"]);
    expect(a.map((x) => x.id)).toEqual(b.map((x) => x.id));
  });

  it("only this detector reads testFiles", async () => {
    const fsm = await import("node:fs");
    const pth = await import("node:path");
    const dir = pth.resolve(__dirname, "../../src/detectors");
    const hits: string[] = [];
    const walk = (d: string): void => {
      for (const e of fsm.readdirSync(d, { withFileTypes: true })) {
        const p = pth.join(d, e.name);
        if (e.isDirectory()) walk(p);
        else if (p.endsWith(".ts") && fsm.readFileSync(p, "utf8").includes("testFiles")) {
          hits.push(e.name);
        }
      }
    };
    walk(dir);
    expect(hits).toEqual(["placeholder-tests-detector.ts"]);
  });
});
