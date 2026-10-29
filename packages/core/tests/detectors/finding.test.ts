import { describe, it, expect } from "vitest";
import { createFindingId, type Finding } from "@talaljaber/vibesafe-shared";
import {
  assertFindingRubric,
  makeFinding,
  type FindingInput,
} from "../../src/detectors/utils/finding.js";
import { expectRubric } from "../helpers/rubric.js";

const base: FindingInput = {
  category: "injection",
  ruleId: "injection/sample-rule",
  title: "Sample",
  severity: "high",
  confidence: "high",
  file: "app/api/x/route.ts",
  line: 12,
  evidence: "  db.query(`select * from t where id = ${id}`)  ",
  plainEnglishProblem: "Problem.",
  whyItMatters: "Impact.",
  fixSteps: ["Fix it."],
  aiFixPrompt: "Static prompt.",
};

describe("makeFinding", () => {
  it("builds a deterministic id from prefix, ruleId, file, line and sanitized evidence", () => {
    const f = makeFinding(base);
    expect(f.id).toBe(
      createFindingId("INJ", "injection/sample-rule", "app/api/x/route.ts", 12, f.evidence),
    );
    expect(makeFinding(base).id).toBe(f.id);
    expect(f.id).toMatch(/^INJ-[0-9a-f]{10}$/);
  });

  it("uses the discriminator instead of the evidence when given", () => {
    const a = makeFinding({ ...base, discriminator: "a" });
    const b = makeFinding({ ...base, discriminator: "b" });
    expect(a.id).not.toBe(b.id);
    expect(a.id).toBe(createFindingId("INJ", base.ruleId, base.file, base.line, "a"));
  });

  it("different lines or files give different ids", () => {
    expect(makeFinding({ ...base, line: 13 }).id).not.toBe(makeFinding(base).id);
    expect(makeFinding({ ...base, file: "b.ts" }).id).not.toBe(makeFinding(base).id);
  });

  it("sanitizes evidence (trim and secret redaction)", () => {
    const key = "sk_live_" + "51NqZk2HfR8vT3xLmPq9WcYbE4uJdKs7AeGh2Rn";
    const f = makeFinding({ ...base, evidence: `  const k = "${key}";  ` });
    expect(f.evidence).not.toContain(key);
    expect(f.evidence!.startsWith("const k")).toBe(true);
  });

  it("throws when the ruleId does not start with the category", () => {
    expect(() => makeFinding({ ...base, ruleId: "xss/sample" })).toThrow(/must start with/);
    expect(() => makeFinding({ ...base, ruleId: "injection/" })).toThrow();
    expect(() => makeFinding({ ...base, ruleId: "injectionsample" })).toThrow();
  });

  it("defaults deployBlocking to critical+high and autoFixAvailable to false", () => {
    expect(makeFinding({ ...base, severity: "critical" }).deployBlocking).toBe(true);
    expect(makeFinding(base).deployBlocking).toBe(false);
    expect(
      makeFinding({ ...base, severity: "critical", confidence: "medium" }).deployBlocking,
    ).toBe(false);
    expect(makeFinding({ ...base, deployBlocking: true }).deployBlocking).toBe(true);
    expect(makeFinding(base).autoFixAvailable).toBe(false);
    expect(makeFinding({ ...base, autoFixAvailable: true }).autoFixAvailable).toBe(true);
  });

  it("omits undefined optional fields and keeps defined ones", () => {
    const f = makeFinding({
      ...base,
      file: undefined,
      line: undefined,
      evidence: undefined,
      endLine: undefined,
    });
    expect("file" in f).toBe(false);
    expect("line" in f).toBe(false);
    expect("evidence" in f).toBe(false);
    expect("endLine" in f).toBe(false);
    expect(f.id).toBe(createFindingId("INJ", base.ruleId));
    const g = makeFinding({ ...base, endLine: 20, column: 3, learnMoreUrl: "https://x" });
    expect(g).toMatchObject({ endLine: 20, column: 3, learnMoreUrl: "https://x" });
  });

  it("passes the shared rubric helper", () => {
    expectRubric([makeFinding(base), makeFinding({ ...base, severity: "critical" })]);
  });
});

describe("assertFindingRubric", () => {
  const f = (severity: Finding["severity"], confidence: Finding["confidence"]): Finding =>
    makeFinding({ ...base, severity, confidence });

  it("requires high confidence for critical", () => {
    expect(() => assertFindingRubric(f("critical", "high"))).not.toThrow();
    expect(() => assertFindingRubric(f("critical", "medium"))).toThrow(/critical/);
    expect(() => assertFindingRubric(f("critical", "low"))).toThrow();
  });

  it("caps low confidence at medium", () => {
    expect(() => assertFindingRubric(f("high", "low"))).toThrow(/capped at medium/);
    expect(() => assertFindingRubric(f("medium", "low"))).not.toThrow();
    expect(() => assertFindingRubric(f("low", "low"))).not.toThrow();
    expect(() => assertFindingRubric(f("high", "medium"))).not.toThrow();
  });

  it("skips ruleIds in the legacy allowlist", () => {
    const legacy = new Set(["injection/sample-rule"]);
    expect(() => assertFindingRubric(f("critical", "low"), legacy)).not.toThrow();
  });
});
