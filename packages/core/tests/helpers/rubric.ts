import { expect } from "vitest";
import { CATEGORY_PREFIX, type Finding } from "@talaljaber/vibesafe-shared";
import { assertFindingRubric } from "../../src/detectors/utils/finding.js";

/**
 * Shared assertion every new detector test calls on its findings: the severity
 * rubric (critical needs high confidence, low confidence caps at medium), a
 * `category/slug` ruleId, an id of the form `<PREFIX>-<10 hex>` for the category,
 * and the translation layer (problem, why, fix steps, static AI prompt) filled in.
 */
export function expectRubric(findings: readonly Finding[]): void {
  for (const f of findings) {
    expect(() => assertFindingRubric(f), f.ruleId).not.toThrow();
    expect(f.ruleId, f.ruleId).toMatch(new RegExp(`^${f.category}/[a-z0-9][a-z0-9-]*$`));
    expect(f.ruleId.length, f.ruleId).toBeLessThanOrEqual(f.category.length + 1 + 40);
    expect(f.id, f.ruleId).toMatch(new RegExp(`^${CATEGORY_PREFIX[f.category]}-[0-9a-f]{10}$`));
    expect(f.plainEnglishProblem.trim(), f.ruleId).not.toBe("");
    expect(f.whyItMatters.trim(), f.ruleId).not.toBe("");
    expect(f.fixSteps.length, f.ruleId).toBeGreaterThan(0);
    expect((f.aiFixPrompt ?? "").trim(), f.ruleId).not.toBe("");
  }
}
