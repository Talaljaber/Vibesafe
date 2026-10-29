import { describe, it, expect } from "vitest";
import { z } from "zod";
import { ALL_CATEGORIES } from "@talaljaber/vibesafe-shared";
import { scanInputShape } from "../src/tools/scan.js";

// The category enum is built from ALL_CATEGORIES through a tuple cast that has no runtime guard,
// so pin the schema to the shared list here.
const schema = z.object(scanInputShape);

describe("vibesafe_scan input schema", () => {
  it("has at least one category", () => {
    expect(ALL_CATEGORIES.length).toBeGreaterThan(0);
  });

  it.each(ALL_CATEGORIES.map((c) => [c]))("accepts category %s", (category) => {
    const parsed = schema.safeParse({ path: ".", category });
    expect(parsed.success).toBe(true);
    expect(parsed.data?.category).toBe(category);
  });

  it("accepts exactly the shared categories", () => {
    expect([...scanInputShape.category.unwrap().options].sort()).toEqual(
      [...ALL_CATEGORIES].sort(),
    );
  });

  it.each([["not_a_category"], ["Secret"], [""]])("rejects unknown category %j", (category) => {
    expect(schema.safeParse({ path: ".", category }).success).toBe(false);
  });

  it("allows the category to be omitted", () => {
    expect(schema.safeParse({ path: "." }).success).toBe(true);
  });
});
