import { describe, expect, it } from "vitest";
import { normalizePattern, stableAttackId } from "../src/ids.js";

describe("stableAttackId", () => {
  it("has the ATK-<12hex> shape", () => {
    expect(stableAttackId("idor", "GET", "/api/notes/[id]")).toMatch(/^ATK-[0-9a-f]{12}$/);
  });
  it("is stable when a dynamic segment is renamed", () => {
    expect(stableAttackId("idor", "GET", "/api/notes/[id]")).toBe(
      stableAttackId("idor", "GET", "/api/notes/[noteId]"),
    );
  });
  it("normalizes method case and differs by check, method and path", () => {
    const base = stableAttackId("idor", "GET", "/api/notes/[id]");
    expect(stableAttackId("idor", "get", "/api/notes/[id]")).toBe(base);
    expect(stableAttackId("unauth-route", "GET", "/api/notes/[id]")).not.toBe(base);
    expect(stableAttackId("idor", "PATCH", "/api/notes/[id]")).not.toBe(base);
    expect(stableAttackId("idor", "GET", "/api/invoices/[id]")).not.toBe(base);
  });
  it("normalizes by position", () => {
    expect(normalizePattern("/a/[x]/b/[y]/[...rest]")).toBe("/a/:1/b/:2/*1");
    expect(normalizePattern("/a/[[...slug]]")).toBe("/a/*1");
    expect(stableAttackId("idor", "GET", "/a/[x]/[y]")).not.toBe(
      stableAttackId("idor", "GET", "/a/[x]"),
    );
  });
});
