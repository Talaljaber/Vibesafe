import { describe, it, expect } from "vitest";
import type { Finding } from "@vibesafe/shared";
import { computeDelta, mergeFindings, needsFullRescan } from "../src/watch/delta.js";

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

describe("mergeFindings", () => {
  const a = finding({ file: "a.ts" });
  const b = finding({ file: "b.ts", title: "B" });
  const project = finding({ file: undefined, title: "project" });

  it("replaces findings of rescanned files and keeps the rest", () => {
    const fresh = finding({ file: "a.ts", title: "new" });
    const merged = mergeFindings([a, b, project], ["a.ts"], [fresh]);
    expect(merged).toEqual([b, project, fresh]);
  });

  it("drops findings of deleted files (empty rescan)", () => {
    expect(mergeFindings([a, b], ["a.ts"], [])).toEqual([b]);
  });

  it("ignores rescanned findings outside the changed set or without a file", () => {
    const stray = finding({ file: "c.ts" });
    expect(mergeFindings([a], ["a.ts"], [stray, project])).toEqual([]);
  });

  it("keeps project-level findings", () => {
    expect(mergeFindings([project], ["a.ts"], [])).toEqual([project]);
  });
});

describe("needsFullRescan", () => {
  it.each(["package.json", "apps/web/package.json", ".gitignore", ".env", ".env.local", "pnpm-lock.yaml"])(
    "true for %s",
    (p) => expect(needsFullRescan([p])).toBe(true),
  );
  it.each(["src/app.ts", "src/package.json.ts", "README.md"])("false for %s", (p) =>
    expect(needsFullRescan([p])).toBe(false),
  );
  it("true if any file in the batch qualifies", () => {
    expect(needsFullRescan(["src/a.ts", ".gitignore"])).toBe(true);
  });
});
