import { describe, it, expect } from "vitest";
import { redactSecret } from "../src/utils.js";

describe("redactSecret", () => {
  it("redacts long secrets leaving first 4 and last 4", () => {
    expect(redactSecret("sk_live_1234567890abcdef")).toBe("sk_l...cdef");
  });

  it("aggressively redacts short secrets", () => {
    expect(redactSecret("abcd")).toBe("***");
    expect(redactSecret("123")).toBe("***");
  });

  it("moderately redacts medium length secrets", () => {
    expect(redactSecret("abcdefg")).toBe("ab***g");
    expect(redactSecret("12345678")).toBe("12***8");
  });

  it("handles empty or falsy inputs", () => {
    expect(redactSecret("")).toBe("");
  });
});
