import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import {
  PlaceholderTestsDetector,
  classifyTestFile,
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
  it("treats supertest-style .expect(...) as a real assertion", () => {
    const code = `it("ok", async () => { await request(app).get("/").expect(200); });`;
    expect(classifyTestFile(code)?.placeholderOnly).toBe(false);
  });
});
