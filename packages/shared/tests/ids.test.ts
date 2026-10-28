import { describe, it, expect } from "vitest";
import { createFindingId } from "../src/ids.js";

describe("createFindingId", () => {
  it("is deterministic and prefixed with >= 8 hex chars", () => {
    const a = createFindingId("SEC", "secret/x", "a.ts", 3);
    expect(a).toBe(createFindingId("SEC", "secret/x", "a.ts", 3));
    expect(a).toMatch(/^SEC-[0-9a-f]{8,}$/);
  });

  it("differs when any input differs", () => {
    const base = createFindingId("SEC", "secret/x", "a.ts", 3, "m");
    expect(createFindingId("SEC", "secret/y", "a.ts", 3, "m")).not.toBe(base);
    expect(createFindingId("SEC", "secret/x", "b.ts", 3, "m")).not.toBe(base);
    expect(createFindingId("SEC", "secret/x", "a.ts", 4, "m")).not.toBe(base);
    expect(createFindingId("SEC", "secret/x", "a.ts", 3, "n")).not.toBe(base);
  });
});
