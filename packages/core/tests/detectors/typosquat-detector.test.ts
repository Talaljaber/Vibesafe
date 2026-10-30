import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import {
  TyposquatDetector,
  lookAlikeTarget,
  withinOneEdit,
} from "../../src/detectors/typosquat-detector.js";
import {
  KNOWN_TYPOSQUATS,
  LEGITIMATE_NEIGHBOURS,
  POPULAR_PACKAGES,
} from "../../src/detectors/patterns/npm-typosquats.js";
import { expectRubric } from "../helpers/rubric.js";

const detector = new TyposquatDetector();

const createContext = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake/path",
  projectContext: {} as ScanContext["projectContext"],
  files: Object.keys(files),
  config: { rootPath: "/fake/path" },
  readFile: async (file) => files[file] ?? "",
});

const pkg = (deps: Record<string, string>, devDeps: Record<string, string> = {}): string =>
  JSON.stringify({ name: "app", dependencies: deps, devDependencies: devDeps }, null, 2);

async function run(files: Record<string, string>) {
  const findings = await detector.detect(createContext(files));
  expectRubric(findings);
  return findings;
}

describe("withinOneEdit", () => {
  it("counts insertions, deletions, substitutions and adjacent swaps as one edit", () => {
    expect(withinOneEdit("lodash", "lodahs")).toBe(true); // swap
    expect(withinOneEdit("lodash", "lodas")).toBe(true); // delete
    expect(withinOneEdit("lodash", "llodash")).toBe(true); // insert
    expect(withinOneEdit("lodash", "lodesh")).toBe(true); // substitute
    expect(withinOneEdit("lodash", "loadsh")).toBe(true); // swap "da" -> "ad"
    expect(withinOneEdit("lodash", "ladosh")).toBe(false); // two substitutions
    expect(withinOneEdit("lodash", "lodashes")).toBe(false);
  });
});

describe("typosquat data", () => {
  it("never lists a popular or allow-listed name as a known typosquat", () => {
    for (const name of Object.keys(KNOWN_TYPOSQUATS)) {
      expect(POPULAR_PACKAGES, name).not.toContain(name);
      expect(LEGITIMATE_NEIGHBOURS, name).not.toContain(name);
    }
    expect(new Set(POPULAR_PACKAGES).size).toBe(POPULAR_PACKAGES.length);
  });

  it("no popular package is flagged as a look-alike of another", () => {
    for (const name of POPULAR_PACKAGES) expect(lookAlikeTarget(name), name).toBeUndefined();
    for (const name of LEGITIMATE_NEIGHBOURS) expect(lookAlikeTarget(name), name).toBeUndefined();
  });
});

describe("TyposquatDetector", () => {
  it("flags a known malicious typosquat as critical, also in devDependencies", async () => {
    const findings = await run({
      "package.json": pkg({ react: "^18.2.0" }, { crossenv: "^7.0.3" }),
    });
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.ruleId).toBe("dependency/typosquat-package");
    expect(f.severity).toBe("critical");
    expect(f.confidence).toBe("high");
    expect(f.deployBlocking).toBe(true);
    expect(f.title).toContain('"cross-env"');
    expect(f.line).toBe(7);
    expect(f.evidence).toContain('"crossenv"');
  });

  it("flags other deny-listed names", async () => {
    const findings = await run({ "package.json": pkg({ "jquery.js": "1.0.0", mongose: "1.0.0" }) });
    expect(findings.map((f) => f.severity)).toEqual(["critical", "critical"]);
  });

  it("hints at a one-edit look-alike of a popular package at medium/low", async () => {
    const findings = await run({ "package.json": pkg({ lodesh: "^4.17.21", expresz: "^4.0.0" }) });
    expect(findings.map((f) => f.title).sort()).toEqual([
      '"expresz" looks like a misspelling of "express"',
      '"lodesh" looks like a misspelling of "lodash"',
    ]);
    for (const f of findings) {
      expect(f.severity).toBe("medium");
      expect(f.confidence).toBe("low");
      expect(f.deployBlocking).toBe(false);
    }
  });

  it("does not flag popular packages, legitimate neighbours, short or scoped names", async () => {
    const findings = await run({
      "package.json": pkg({
        react: "18.2.0",
        preact: "10.0.0",
        "cross-env": "7.0.3",
        mysql2: "3.0.0",
        ws: "8.0.0",
        ms: "2.0.0",
        nest: "1.0.0",
        yup: "1.0.0",
        vuex: "4.0.0",
        "@types/react": "18.0.0",
        "@scope/lodas": "1.0.0",
        "my-internal-lib": "1.0.0",
      }),
    });
    expect(findings).toEqual([]);
  });

  it("does not flag real published packages one edit away from a popular name", async () => {
    const real = [
      "server",
      "openapi",
      "mkdir",
      "classname",
      "globs",
      "colour",
      "jslint",
      "scrypt",
      "graphiql",
      "csv-parser",
      "axiom",
      "uuid4",
      "react-icon",
    ];
    for (const name of real) expect(lookAlikeTarget(name), name).toBeUndefined();
    const findings = await run({
      "package.json": pkg(Object.fromEntries(real.map((n) => [n, "1.0.0"]))),
    });
    expect(findings).toEqual([]);
  });

  it("ignores scripts, nested node_modules manifests and unparseable files", async () => {
    expect(
      await run({
        "package.json": JSON.stringify({ scripts: { crossenv: "echo" } }),
        "node_modules/a/package.json": pkg({ crossenv: "1.0.0" }),
      }),
    ).toEqual([]);
    expect(await run({ "package.json": "{ not json" })).toEqual([]);
  });

  it("produces stable ids", async () => {
    const files = { "package.json": pkg({}, { crossenv: "^7.0.3" }) };
    const a = await run(files);
    const b = await run(files);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });
});
