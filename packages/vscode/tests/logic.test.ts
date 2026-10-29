import { describe, it, expect } from "vitest";
import { diagnosticRangeCoords } from "../src/util/range.js";
import { readScanOptions } from "../src/util/scanOptions.js";
import { findFindingInResults } from "../src/util/findings.js";
import type { Finding, ScanResult } from "@talaljaber/vibesafe-shared";

describe("diagnosticRangeCoords", () => {
  it("uses the real line length when text is known", () => {
    expect(diagnosticRangeCoords(3, "  const x = 1;")).toEqual([2, 2, 2, 14]);
  });
  it("extends to end of line when the document is not open", () => {
    expect(diagnosticRangeCoords(1)).toEqual([0, 0, 0, Number.MAX_SAFE_INTEGER]);
  });
});

describe("readScanOptions", () => {
  const cfg = (v: Record<string, unknown>) => ({ get: <T>(k: string) => v[k] as T | undefined });
  it("passes severity and non-empty categories", () => {
    expect(readScanOptions(cfg({ minSeverity: "high", enabledCategories: ["secret"] }))).toEqual({
      minSeverity: "high",
      enabledCategories: ["secret"],
    });
  });
  it("omits empty categories and invalid severity", () => {
    expect(readScanOptions(cfg({ minSeverity: "bogus", enabledCategories: [] }))).toEqual({});
  });
});

describe("findFindingInResults", () => {
  const mk = (id: string, root: string) =>
    ({ projectPath: root, findings: [{ id } as unknown as Finding] }) as unknown as ScanResult;
  it("finds the finding and the result it belongs to", () => {
    const found = findFindingInResults([mk("a", "/r1"), mk("b", "/r2")], "b");
    expect(found?.result.projectPath).toBe("/r2");
    expect(findFindingInResults([mk("a", "/r1")], "zz")).toBeUndefined();
  });
});
