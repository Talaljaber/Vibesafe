import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { TyposquatDetector, topLookAlikeTarget } from "../../src/detectors/typosquat-detector.js";
import { POPULAR_PACKAGES, TOP_PACKAGES } from "../../src/detectors/patterns/npm-typosquats.js";
import { expectRubric } from "../helpers/rubric.js";

const scan = async (deps: Record<string, string>) => {
  const ctx: ScanContext = {
    rootPath: "/f",
    projectContext: {} as ScanContext["projectContext"],
    files: ["package.json"],
    config: { rootPath: "/f" },
    readFile: async () => JSON.stringify({ name: "a", dependencies: deps }, null, 2),
  };
  const findings = await new TyposquatDetector().detect(ctx);
  expectRubric(findings);
  return findings;
};

describe("TOP_PACKAGES tier", () => {
  it("is a subset of POPULAR_PACKAGES without duplicates", () => {
    for (const n of TOP_PACKAGES) expect(POPULAR_PACKAGES, n).toContain(n);
    expect(new Set(TOP_PACKAGES).size).toBe(TOP_PACKAGES.length);
  });

  it("reports a transposed, doubled or dropped letter of a top package at high/medium", async () => {
    const findings = await scan({
      lodahs: "1.0.0",
      expresss: "1.0.0",
      axioos: "1.0.0",
      expres: "1",
    });
    expect(findings.map((f) => [f.severity, f.confidence]).every((x) => x[0] === "high")).toBe(
      true,
    );
    expect(findings).toHaveLength(4);
    for (const f of findings) expect(f.confidence).toBe("medium");
  });

  it("keeps other distance-1 hits at medium/low", async () => {
    const findings = await scan({ lodesh: "1.0.0", expresz: "1.0.0" });
    expect(findings.map((f) => [f.severity, f.confidence])).toEqual([
      ["medium", "low"],
      ["medium", "low"],
    ]);
  });

  it("stays silent for real neighbours, popular, short and scoped names", async () => {
    expect(topLookAlikeTarget("lodahs")).toBe("lodash");
    for (const n of ["preact", "react-dom", "chai", "chalk", "@scope/lodahs", "lodash", "mysql2"]) {
      expect(topLookAlikeTarget(n), n).toBeUndefined();
    }
    expect(await scan({ preact: "1", "react-dom": "1", chai: "1", dayjs: "1" })).toEqual([]);
  });
});
