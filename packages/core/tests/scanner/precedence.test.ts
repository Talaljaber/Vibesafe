import { describe, it, expect } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { Detector, Finding, FindingCategory, Severity } from "@talaljaber/vibesafe-shared";
import {
  applyPrecedence,
  matchesRulePattern,
  patternsOverlap,
  validatePrecedenceRules,
  type PrecedenceRule,
} from "../../src/scanner/precedence.js";
import { DetectorRegistry } from "../../src/scanner/detector-registry.js";
import { ScannerPipeline } from "../../src/scanner/pipeline.js";

let n = 0;
function finding(
  ruleId: string,
  loc: { file?: string; line?: number; endLine?: number } = {},
  severity: Severity = "high",
): Finding {
  const category = ruleId.split("/")[0] as FindingCategory;
  return {
    id: `T-${(n++).toString(16).padStart(10, "0")}`,
    ruleId,
    title: ruleId,
    severity,
    category,
    deployBlocking: false,
    confidence: "high",
    ...loc,
    plainEnglishProblem: "p",
    whyItMatters: "w",
    fixSteps: ["f"],
    autoFixAvailable: false,
  };
}

const ENCLOSING: PrecedenceRule = {
  winner: "injection/*",
  losers: ["validation/missing-body-validation"],
  scope: "enclosing",
  reason: "A concrete injection sink is the real problem in that handler.",
};
const LINE: PrecedenceRule = {
  winner: "injection/sql-built-from-input",
  losers: ["validation/missing-body-validation"],
  scope: "line",
  reason: "Same line.",
};

describe("rule patterns", () => {
  it("matches exact ids and category wildcards", () => {
    expect(matchesRulePattern("injection/a", "injection/*")).toBe(true);
    expect(matchesRulePattern("injection/a", "injection/a")).toBe(true);
    expect(matchesRulePattern("injection/ab", "injection/a")).toBe(false);
    expect(matchesRulePattern("injectionx/a", "injection/*")).toBe(false);
    expect(matchesRulePattern("xss/a", "injection/*")).toBe(false);
  });

  it("detects overlapping patterns", () => {
    expect(patternsOverlap("injection/*", "injection/a")).toBe(true);
    expect(patternsOverlap("injection/a", "injection/*")).toBe(true);
    expect(patternsOverlap("injection/*", "injection/*")).toBe(true);
    expect(patternsOverlap("injection/a", "injection/a")).toBe(true);
    expect(patternsOverlap("injection/a", "injection/b")).toBe(false);
    expect(patternsOverlap("injection/*", "validation/*")).toBe(false);
  });
});

describe("applyPrecedence", () => {
  it("enclosing: hides a loser whose [line, endLine] contains the winner", () => {
    const loser = finding("validation/missing-body-validation", {
      file: "a.ts",
      line: 10,
      endLine: 30,
    });
    const winner = finding("injection/sql-built-from-input", { file: "a.ts", line: 20 });
    const res = applyPrecedence([loser, winner], [ENCLOSING]);
    expect(res.findings).toEqual([winner]);
    expect(res.suppressed).toBe(1);
  });

  it("enclosing: inclusive bounds", () => {
    for (const line of [10, 30]) {
      const loser = finding("validation/missing-body-validation", {
        file: "a.ts",
        line: 10,
        endLine: 30,
      });
      const winner = finding("injection/x", { file: "a.ts", line });
      expect(applyPrecedence([loser, winner], [ENCLOSING]).suppressed).toBe(1);
    }
  });

  it("enclosing: keeps the loser when the winner is outside the span, in another file, or the loser has no endLine", () => {
    const loser = finding("validation/missing-body-validation", {
      file: "a.ts",
      line: 10,
      endLine: 30,
    });
    const noEnd = finding("validation/missing-body-validation", { file: "a.ts", line: 10 });
    const outside = finding("injection/x", { file: "a.ts", line: 31 });
    const otherFile = finding("injection/x", { file: "b.ts", line: 20 });
    const noLine = finding("injection/x", { file: "a.ts" });
    const res = applyPrecedence([loser, noEnd, outside, otherFile, noLine], [ENCLOSING]);
    expect(res.suppressed).toBe(0);
    expect(res.findings).toHaveLength(5);
    const res2 = applyPrecedence(
      [noEnd, finding("injection/x", { file: "a.ts", line: 10 })],
      [ENCLOSING],
    );
    expect(res2.suppressed).toBe(0);
  });

  it("line: needs the same file and the same line", () => {
    const loser = finding("validation/missing-body-validation", {
      file: "a.ts",
      line: 5,
      endLine: 50,
    });
    const sameLine = finding("injection/sql-built-from-input", { file: "a.ts", line: 5 });
    const nextLine = finding("injection/sql-built-from-input", { file: "a.ts", line: 6 });
    expect(applyPrecedence([loser, nextLine], [LINE]).suppressed).toBe(0);
    expect(applyPrecedence([loser, sameLine], [LINE]).findings).toEqual([sameLine]);
    const noFile = finding("validation/missing-body-validation", { line: 5 });
    const noFileWinner = finding("injection/sql-built-from-input", { line: 5 });
    expect(applyPrecedence([noFile, noFileWinner], [LINE]).suppressed).toBe(0);
  });

  it("does not inherit severity or deployBlocking", () => {
    const loser = finding(
      "validation/missing-body-validation",
      { file: "a.ts", line: 1, endLine: 9 },
      "critical",
    );
    loser.deployBlocking = true;
    const winner = finding("injection/x", { file: "a.ts", line: 2 }, "medium");
    const [kept] = applyPrecedence([loser, winner], [ENCLOSING]).findings;
    expect(kept).toBe(winner);
    expect(kept!.severity).toBe("medium");
    expect(kept!.deployBlocking).toBe(false);
  });

  it("only a surviving winner hides: a winner that is itself a loser somewhere never hides", () => {
    // A chain (rejected by validatePrecedenceRules) must still not cascade.
    const rules: PrecedenceRule[] = [
      { winner: "injection/a", losers: ["injection/b"], scope: "line", reason: "r" },
      { winner: "injection/b", losers: ["injection/c"], scope: "line", reason: "r" },
    ];
    const a = finding("injection/a", { file: "f", line: 1 });
    const b = finding("injection/b", { file: "f", line: 1 });
    const c = finding("injection/c", { file: "f", line: 1 });
    const res = applyPrecedence([c, b, a], rules);
    expect(res.findings.map((f) => f.ruleId)).toEqual(["injection/c", "injection/a"]);
    expect(applyPrecedence([a, b, c], rules).findings.map((f) => f.ruleId)).toEqual([
      "injection/a",
      "injection/c",
    ]);
  });

  it("collapses identical ids only, keeping the first, without counting them as suppressed", () => {
    const a = finding("code_quality/x", { file: "f", line: 1 });
    const dup = { ...a, title: "second copy" };
    const sameLineOtherId = finding("code_quality/x", { file: "f", line: 1 });
    const res = applyPrecedence([a, dup, sameLineOtherId], []);
    expect(res.findings).toEqual([a, sameLineOtherId]);
    expect(res.suppressed).toBe(0);
  });

  it("keeps finding order and returns everything when nothing matches", () => {
    const fs1 = [
      finding("xss/a", { file: "f", line: 1 }),
      finding("auth/b", { file: "f", line: 2 }),
    ];
    expect(applyPrecedence(fs1, [ENCLOSING]).findings).toEqual(fs1);
  });
});

describe("validatePrecedenceRules", () => {
  it("accepts the planned cross-owner pairs", () => {
    expect(
      validatePrecedenceRules([
        ENCLOSING,
        {
          winner: "validation/client-trusted-price",
          losers: ["validation/missing-body-validation"],
          scope: "enclosing",
          reason: "r",
        },
      ]),
    ).toEqual([]);
  });

  it("rejects malformed patterns, unknown categories, empty losers or reason", () => {
    const problems = validatePrecedenceRules([
      { winner: "injection", losers: ["validation/x"], scope: "line", reason: "r" },
      { winner: "nope/x", losers: ["validation/x"], scope: "line", reason: "r" },
      { winner: "injection/x", losers: [], scope: "line", reason: "r" },
      { winner: "injection/y", losers: ["validation/*x"], scope: "line", reason: " " },
    ]);
    expect(problems.join("\n")).toMatch(/not "category\/slug"/);
    expect(problems.join("\n")).toMatch(/unknown category/);
    expect(problems.join("\n")).toMatch(/no losers/);
    expect(problems.join("\n")).toMatch(/empty reason/);
  });

  it("rejects a winner overlapping its own loser", () => {
    expect(
      validatePrecedenceRules([
        { winner: "injection/*", losers: ["injection/sql"], scope: "line", reason: "r" },
      ]).join(),
    ).toMatch(/overlaps its own loser/);
  });

  it("rejects chains", () => {
    expect(
      validatePrecedenceRules([
        { winner: "injection/*", losers: ["validation/a"], scope: "line", reason: "r" },
        { winner: "xss/b", losers: ["injection/c"], scope: "line", reason: "r" },
      ]).join(),
    ).toMatch(/chain/);
  });
});

describe("pipeline integration", () => {
  class FixedDetector implements Detector {
    name = "Fixed";
    description = "Returns fixed findings";
    constructor(
      public id: string,
      public category: FindingCategory,
      private findings: Finding[],
    ) {}
    async detect(): Promise<Finding[]> {
      return this.findings;
    }
  }

  async function scan(ruleOverrides?: Record<string, "off" | Severity>) {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "vibesafe-prec-"));
    try {
      const loser = finding(
        "validation/missing-body-validation",
        { file: "a.ts", line: 1, endLine: 10 },
        "medium",
      );
      const winner = finding("injection/x", { file: "a.ts", line: 4 }, "critical");
      const registry = new DetectorRegistry();
      registry.register(new FixedDetector("v-detector", "validation", [loser]));
      registry.register(new FixedDetector("i-detector", "injection", [winner]));
      registry.registerPrecedence([ENCLOSING]);
      expect(registry.getPrecedence()).toEqual([ENCLOSING]);
      return await new ScannerPipeline(registry).scan({
        rootPath: root,
        useConfigFile: false,
        ...(ruleOverrides ? { ruleOverrides } : {}),
      });
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  }

  it("hides the loser, warns, and scores without it", async () => {
    const res = await scan();
    expect(res.findings.map((f) => f.ruleId)).toEqual(["injection/x"]);
    expect(res.warnings).toContain(
      "Precedence hid 1 generic finding(s) in favour of specific ones.",
    );
    expect(res.summary.totalFindings).toBe(1);
  });

  it("brings the loser back when the winner is turned off, without a precedence warning", async () => {
    const res = await scan({ "injection/x": "off" });
    expect(res.findings.map((f) => f.ruleId)).toEqual(["validation/missing-body-validation"]);
    expect((res.warnings ?? []).some((w) => w.startsWith("Precedence"))).toBe(false);
  });

  it("keeps the winner's overridden severity", async () => {
    const res = await scan({ "injection/x": "low" });
    expect(res.findings).toHaveLength(1);
    expect(res.findings[0]!.severity).toBe("low");
  });
});
