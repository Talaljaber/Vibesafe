import { describe, expect, it } from "vitest";
import {
  CATEGORY_MULTIPLIERS,
  CATEGORY_PREFIX,
  DEPLOY_STATUS_LABEL,
  SEVERITY_RANK,
  SEVERITY_WEIGHTS,
  getDeployStatus,
  isMoreSevere,
  maxSeverity,
} from "../src/index.js";

describe("severity utilities", () => {
  describe("SEVERITY_RANK", () => {
    it("critical is ranked lower (more severe) than high", () => {
      expect(SEVERITY_RANK.critical).toBeLessThan(SEVERITY_RANK.high);
    });

    it("high is ranked lower than medium", () => {
      expect(SEVERITY_RANK.high).toBeLessThan(SEVERITY_RANK.medium);
    });

    it("medium is ranked lower than low", () => {
      expect(SEVERITY_RANK.medium).toBeLessThan(SEVERITY_RANK.low);
    });
  });

  describe("isMoreSevere", () => {
    it("critical is more severe than high", () => {
      expect(isMoreSevere("critical", "high")).toBe(true);
    });

    it("high is more severe than low", () => {
      expect(isMoreSevere("high", "low")).toBe(true);
    });

    it("low is NOT more severe than critical", () => {
      expect(isMoreSevere("low", "critical")).toBe(false);
    });

    it("same severity returns false", () => {
      expect(isMoreSevere("medium", "medium")).toBe(false);
    });
  });

  describe("maxSeverity", () => {
    it("returns critical when compared to high", () => {
      expect(maxSeverity("critical", "high")).toBe("critical");
      expect(maxSeverity("high", "critical")).toBe("critical");
    });

    it("returns the more severe of medium and low", () => {
      expect(maxSeverity("medium", "low")).toBe("medium");
    });
  });

  describe("getDeployStatus", () => {
    it("returns blocker when hasCritical is true regardless of score", () => {
      expect(getDeployStatus(100, true)).toBe("blocker");
      expect(getDeployStatus(50, true)).toBe("blocker");
      expect(getDeployStatus(0, true)).toBe("blocker");
    });

    it("returns danger when score < 40 and no critical", () => {
      expect(getDeployStatus(39, false)).toBe("danger");
      expect(getDeployStatus(0, false)).toBe("danger");
    });

    it("returns warning when score is 40–69 and no critical", () => {
      expect(getDeployStatus(40, false)).toBe("warning");
      expect(getDeployStatus(69, false)).toBe("warning");
    });

    it("returns safe when score >= 70 and no critical", () => {
      expect(getDeployStatus(70, false)).toBe("safe");
      expect(getDeployStatus(100, false)).toBe("safe");
    });
  });
});

describe("constants", () => {
  describe("SEVERITY_WEIGHTS", () => {
    it("critical has the largest negative weight", () => {
      expect(SEVERITY_WEIGHTS.critical).toBeLessThan(SEVERITY_WEIGHTS.high);
      expect(SEVERITY_WEIGHTS.high).toBeLessThan(SEVERITY_WEIGHTS.medium);
      expect(SEVERITY_WEIGHTS.medium).toBeLessThan(SEVERITY_WEIGHTS.low);
    });

    it("all weights are negative", () => {
      for (const weight of Object.values(SEVERITY_WEIGHTS)) {
        expect(weight).toBeLessThan(0);
      }
    });
  });

  describe("CATEGORY_MULTIPLIERS", () => {
    it("secrets have the highest multiplier", () => {
      const secretMultiplier = CATEGORY_MULTIPLIERS.secret;
      for (const [cat, mult] of Object.entries(CATEGORY_MULTIPLIERS)) {
        if (cat !== "secret") {
          expect(secretMultiplier).toBeGreaterThanOrEqual(mult);
        }
      }
    });

    it("structure has the lowest multiplier", () => {
      const structureMultiplier = CATEGORY_MULTIPLIERS.structure;
      for (const [cat, mult] of Object.entries(CATEGORY_MULTIPLIERS)) {
        if (cat !== "structure") {
          expect(structureMultiplier).toBeLessThanOrEqual(mult);
        }
      }
    });
  });

  describe("CATEGORY_PREFIX", () => {
    it("every category has a prefix", () => {
      const categories = [
        "secret",
        "auth",
        "authorization",
        "frontend_exposure",
        "validation",
        "dependency",
        "code_quality",
        "structure",
      ] as const;

      for (const cat of categories) {
        expect(CATEGORY_PREFIX[cat]).toBeTruthy();
      }
    });

    it("SEC prefix is used for secrets", () => {
      expect(CATEGORY_PREFIX.secret).toBe("SEC");
    });

    it("AUTH prefix is used for auth", () => {
      expect(CATEGORY_PREFIX.auth).toBe("AUTH");
    });
  });

  describe("DEPLOY_STATUS_LABEL", () => {
    it("blocker shows DO NOT DEPLOY", () => {
      expect(DEPLOY_STATUS_LABEL.blocker).toContain("DO NOT DEPLOY");
    });

    it("safe shows READY TO DEPLOY", () => {
      expect(DEPLOY_STATUS_LABEL.safe).toContain("READY TO DEPLOY");
    });
  });
});
