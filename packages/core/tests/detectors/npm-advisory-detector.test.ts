import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { NpmAdvisoryDetector } from "../../src/detectors/npm-advisory-detector.js";
import { NPM_ADVISORIES, DATASET_DATE } from "../../src/detectors/patterns/npm-advisories.js";
import { parseRange, satisfies } from "../../src/detectors/utils/semver.js";
import { expectRubric } from "../helpers/rubric.js";

const detector = new NpmAdvisoryDetector();

function createContext(
  files: Record<string, string>,
  opts: { listed?: string[]; warnings?: string[] } = {},
): ScanContext {
  return {
    rootPath: "/fake/path",
    projectContext: {} as ScanContext["projectContext"],
    files: opts.listed ?? Object.keys(files),
    config: { rootPath: "/fake/path" },
    readFile: async (file) => files[file] ?? "",
    addWarning: (m) => opts.warnings?.push(m),
  };
}

const pkg = (
  deps: Record<string, string>,
  devDeps: Record<string, string> = {},
  extra: Record<string, unknown> = {},
): string =>
  JSON.stringify(
    { name: "app", version: "1.0.0", ...extra, dependencies: deps, devDependencies: devDeps },
    null,
    2,
  );

const byName = async (ctx: ScanContext) => {
  const findings = await detector.detect(ctx);
  expectRubric(findings);
  return findings;
};

describe("advisory dataset", () => {
  it("has at most 15 entries, CVE ids only, valid ranges and fixed versions outside them", () => {
    expect(NPM_ADVISORIES.length).toBeLessThanOrEqual(15);
    expect(DATASET_DATE).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    for (const a of NPM_ADVISORIES) {
      expect(a.cve, a.name).toMatch(/^CVE-\d{4}-\d{4,}$/);
      expect(parseRange(a.affected), a.name).not.toBeNull();
      expect(a.fixed.length, a.name).toBeGreaterThan(0);
      for (const f of a.fixed) expect(satisfies(f, a.affected), `${a.name} ${f}`).toBe(false);
    }
  });

  it("covers the Next.js middleware bypass (CVE-2025-29927) exactly", () => {
    const next = NPM_ADVISORIES.find((a) => a.cve === "CVE-2025-29927")!;
    expect(next.affected).toBe(
      ">=11.1.4 <12.3.5 || >=13.0.0 <13.5.9 || >=14.0.0 <14.2.25 || >=15.0.0 <15.2.3",
    );
    expect(next.severity).toBe("critical");
  });
});

describe("NpmAdvisoryDetector", () => {
  it("flags exact pins at high confidence, on the dependency's line", async () => {
    const findings = await byName(
      createContext({ "package.json": pkg({ next: "13.4.0", lodash: "4.17.15" }) }),
    );
    const next = findings.find((f) => f.title.startsWith("next"))!;
    expect(next.ruleId).toBe("dependency/known-vulnerable-version");
    expect(next.severity).toBe("critical");
    expect(next.confidence).toBe("high");
    expect(next.deployBlocking).toBe(true);
    expect(next.line).toBe(5);
    expect(next.evidence).toContain('"next": "13.4.0"');
    expect(next.fixSteps[0]).toContain("13.5.9");
    const lodash = findings.find((f) => f.title.startsWith("lodash"))!;
    expect(lodash.severity).toBe("high");
    expect(lodash.title).toContain("CVE-2021-23337");
  });

  it("uses the lockfile resolution: a caret range resolved to a fixed version is not flagged", async () => {
    const lock = JSON.stringify(
      {
        lockfileVersion: 3,
        packages: {
          "": {},
          "node_modules/next": { version: "13.5.11" },
          "node_modules/axios": { version: "0.21.1" },
        },
      },
      null,
      2,
    );
    const findings = await byName(
      createContext({
        "package.json": pkg({ next: "^13.4.0", axios: "^0.21.0" }),
        "package-lock.json": lock,
      }),
    );
    expect(findings.map((f) => f.title)).toEqual(["axios 0.21.1 is affected by CVE-2021-3749"]);
    expect(findings[0]!.confidence).toBe("high");
    expect(findings[0]!.plainEnglishProblem).toContain("per the lockfile");
  });

  it("reports an open range whose lowest version is affected at medium confidence, capped at high", async () => {
    const findings = await byName(createContext({ "package.json": pkg({ next: "^13.4.0" }) }));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.confidence).toBe("medium");
    expect(findings[0]!.severity).toBe("high");
    expect(findings[0]!.deployBlocking).toBe(false);
  });

  it("drops range findings to low confidence and warns when the lockfile cannot be read", async () => {
    const warnings: string[] = [];
    const findings = await byName(
      createContext(
        { "package.json": pkg({ next: "^13.4.0", lodash: "4.17.15" }), "package-lock.json": "" },
        { listed: ["package.json", "package-lock.json"], warnings },
      ),
    );
    const next = findings.find((f) => f.title.startsWith("next"))!;
    expect(next.confidence).toBe("low");
    expect(next.severity).toBe("medium");
    // An exact pin is what gets installed, whatever the lockfile says.
    expect(findings.find((f) => f.title.startsWith("lodash"))!.confidence).toBe("high");
    expect(warnings.join("\n")).toContain("package-lock.json");
  });

  it("lowers devDependencies by one severity, except build tooling", async () => {
    const findings = await byName(
      createContext({
        "package.json": pkg({}, { lodash: "4.17.15", "@babel/traverse": "7.22.0" }),
      }),
    );
    expect(findings.find((f) => f.title.startsWith("lodash"))!.severity).toBe("medium");
    expect(findings.find((f) => f.title.startsWith("@babel/traverse"))!.severity).toBe("high");
  });

  it("reports vulnerable transitive packages on the lockfile line, one level lower", async () => {
    const lock = [
      "lodash@^4.17.15:",
      '  version "4.17.21"',
      "",
      "minimist@^1.2.0:",
      '  version "1.2.5"',
    ].join("\n");
    const findings = await byName(
      createContext({ "package.json": pkg({ lodash: "^4.17.15" }), "yarn.lock": lock }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.file).toBe("yarn.lock");
    expect(findings[0]!.line).toBe(4);
    expect(findings[0]!.severity).toBe("medium");
    expect(findings[0]!.title).toContain("minimist 1.2.5");
  });

  it("reports a nested vulnerable copy of a package that is also a direct dependency", async () => {
    const lock = JSON.stringify(
      {
        lockfileVersion: 3,
        packages: {
          "": { dependencies: { minimist: "^1.2.6", mkdirp: "0.5.1" } },
          "node_modules/minimist": { version: "1.2.8" },
          "node_modules/mkdirp": { version: "0.5.1" },
          "node_modules/mkdirp/node_modules/minimist": { version: "0.0.8" },
        },
      },
      null,
      2,
    );
    const findings = await byName(
      createContext({
        "package.json": pkg({ minimist: "^1.2.6", mkdirp: "0.5.1" }),
        "package-lock.json": lock,
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.file).toBe("package-lock.json");
    const nestedLine =
      lock.split("\n").findIndex((l) => l.includes('"node_modules/mkdirp/node_modules/minimist"')) +
      1;
    expect(nestedLine).toBeGreaterThan(0);
    expect(findings[0]!.line).toBe(nestedLine);
    expect(findings[0]!.title).toContain("minimist 0.0.8");
    expect(findings[0]!.severity).toBe("medium");
  });

  it("does not report a direct dependency's own resolved version a second time", async () => {
    const lock = JSON.stringify(
      {
        lockfileVersion: 3,
        packages: {
          "": {},
          "node_modules/minimist": { version: "1.2.5" },
          "node_modules/mkdirp/node_modules/minimist": { version: "1.2.8" },
        },
      },
      null,
      2,
    );
    const findings = await byName(
      createContext({ "package.json": pkg({ minimist: "^1.2.0" }), "package-lock.json": lock }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.file).toBe("package.json");
    expect(findings[0]!.confidence).toBe("high");
    expect(findings[0]!.title).toContain("minimist 1.2.5");

    // A stale lockfile (no version fits the spec) is judged from the spec alone, once.
    const stale = JSON.stringify({
      lockfileVersion: 3,
      packages: { "": {}, "node_modules/minimist": { version: "1.2.5" } },
    });
    const staleFindings = await byName(
      createContext({ "package.json": pkg({ minimist: "^1.2.6" }), "package-lock.json": stale }),
    );
    expect(staleFindings).toEqual([]);
  });

  it("reads lockfiles and manifests that start with a UTF-8 BOM, and one-line blocks", async () => {
    const lock =
      "﻿" +
      JSON.stringify({
        lockfileVersion: 3,
        packages: { "": {}, "node_modules/next": { version: "14.1.0" } },
      });
    const manifest = '﻿{\n  "name": "app",\n  "dependencies": { "next": "^14.0.0" }\n}\n';
    const findings = await byName(
      createContext({ "package.json": manifest, "package-lock.json": lock }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.confidence).toBe("high");
    expect(findings[0]!.title).toBe("next 14.1.0 is affected by CVE-2025-29927");
    expect(findings[0]!.line).toBe(3);
  });

  it("matches exact package names only and ignores non-registry specs", async () => {
    const findings = await byName(
      createContext({
        "package.json": pkg({
          "eslint-config-next": "13.4.0",
          "lodash-es": "4.17.15",
          "@types/lodash": "4.14.0",
          next: "github:vercel/next.js#v13.4.0",
          axios: "npm:axios@0.21.1",
          lodash: "file:../lodash",
          express: "latest",
        }),
      }),
    );
    expect(findings).toEqual([]);
  });

  it("does not flag fixed versions or the first fixed release", async () => {
    const findings = await byName(
      createContext({
        "package.json": pkg({
          next: "14.2.25",
          axios: "^1.7.0",
          jsonwebtoken: "9.0.2",
          lodash: "4.17.21",
          ws: "8.17.1",
        }),
      }),
    );
    expect(findings).toEqual([]);
  });

  it("checks workspace manifests against the root lockfile", async () => {
    const lock = JSON.stringify({
      lockfileVersion: 3,
      packages: { "": {}, "node_modules/next": { version: "14.1.0" } },
    });
    const findings = await byName(
      createContext({
        "package.json": pkg({}),
        "apps/web/package.json": pkg({ next: "^14.0.0" }),
        "package-lock.json": lock,
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.file).toBe("apps/web/package.json");
    expect(findings[0]!.confidence).toBe("high");
    expect(findings[0]!.title).toBe("next 14.1.0 is affected by CVE-2025-29927");
  });

  it("never throws on broken input and produces stable ids", async () => {
    const ctx = createContext({ "package.json": "{ broken", "pnpm-lock.yaml": "::::" });
    expect(await detector.detect(ctx)).toEqual([]);
    const good = createContext({ "package.json": pkg({ next: "13.4.0" }) });
    const a = await detector.detect(good);
    const b = await detector.detect(good);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
    expect(a[0]!.id).toMatch(/^DEP-[0-9a-f]{10}$/);
  });

  it("ignores package.json files under node_modules", async () => {
    const findings = await byName(
      createContext({ "node_modules/x/package.json": pkg({ next: "13.4.0" }) }),
    );
    expect(findings).toEqual([]);
  });
});
