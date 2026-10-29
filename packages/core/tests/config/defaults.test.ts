import { describe, it, expect } from "vitest";
import { ALL_CATEGORIES } from "@talaljaber/vibesafe-shared";
import { DEFAULT_CONFIG, mergeConfig } from "../../src/config/defaults.js";
import { createDefaultRegistry } from "../../src/scanner/detector-registry.js";

describe("default config categories", () => {
  it("enables every category from the shared list, including xss and security_config", () => {
    expect(DEFAULT_CONFIG.enabledCategories).toEqual(ALL_CATEGORIES);
    expect(DEFAULT_CONFIG.enabledCategories).toContain("xss");
    expect(DEFAULT_CONFIG.enabledCategories).toContain("security_config");
    expect(mergeConfig("/p").enabledCategories).toEqual(ALL_CATEGORIES);
  });

  it("does not silently disable any registered detector", () => {
    // The registry filters by enabledCategories, so a category missing from the defaults
    // would drop its detectors without any error.
    const categories = new Set(
      createDefaultRegistry()
        .getDetectors()
        .map((d) => d.category),
    );
    for (const c of categories) expect(ALL_CATEGORIES).toContain(c);
  });
});
