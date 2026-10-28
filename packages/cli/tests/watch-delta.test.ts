import { describe, it, expect } from "vitest";
import type { Finding } from "@vibesafe/shared";
import { computeDelta } from "../src/watch/delta.js";

function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: "SEC-1",
    ruleId: "secret/key",
    title: "Key",
    severity: "high",
    category: "secret",
    deployBlocking: false,
    confidence: "high",
    file: "a.ts",
    line: 1,
    evidence: "sk-xxx",
    plainEnglishProblem: "",
    whyItMatters: "",
    fixSteps: [],
    autoFixAvailable: false,
    ...over,
  };
}

const snap = (findings: Finding[], score = 100) => ({ findings, score, deployStatus: "safe" as const });

describe("computeDelta", () => {
  it("reports added findings and a negative score change", () => {
    const d = computeDelta(snap([]), { findings: [finding()], score: 80, deployStatus: "warning" });
    expect(d.added).toHaveLength(1);
    expect(d.resolved).toHaveLength(0);
    expect(d.scoreChange).toBe(-20);
    expect(d.statusAfter).toBe("warning");
  });

  it("reports resolved findings and a positive score change", () => {
    const d = computeDelta({ findings: [finding()], score: 80, deployStatus: "warning" }, snap([]));
    expect(d.resolved).toHaveLength(1);
    expect(d.added).toHaveLength(0);
    expect(d.scoreChange).toBe(20);
  });

  it("treats a finding whose line moved as unchanged", () => {
    const d = computeDelta(snap([finding({ line: 3, id: "A" })]), snap([finding({ line: 9, id: "B" })]));
    expect(d.added).toHaveLength(0);
    expect(d.resolved).toHaveLength(0);
  });

  it("counts duplicates individually", () => {
    const d = computeDelta(snap([finding()]), snap([finding(), finding({ line: 5 })]));
    expect(d.added).toHaveLength(1);
  });

  it("distinguishes findings by file and rule", () => {
    const d = computeDelta(snap([finding()]), snap([finding({ file: "b.ts" }), finding({ ruleId: "other" })]));
    expect(d.added).toHaveLength(2);
    expect(d.resolved).toHaveLength(1);
  });

  it("is empty for identical snapshots", () => {
    const d = computeDelta(snap([finding()], 90), snap([finding()], 90));
    expect(d).toMatchObject({ added: [], resolved: [], scoreChange: 0 });
  });
});
