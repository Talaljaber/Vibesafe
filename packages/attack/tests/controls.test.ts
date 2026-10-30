import { describe, expect, it } from "vitest";
import {
  buildControlSet,
  fingerprintResponse,
  fingerprintsMatch,
  normalizeBody,
  planControlRequests,
  substituteSegments,
} from "../src/controls.js";

const J = "application/json";
const H = "text/html; charset=utf-8";

describe("fingerprintResponse", () => {
  it("uses sorted top-level keys for JSON objects", () => {
    expect(fingerprintResponse(404, J, '{"b":1,"a":2}')).toEqual({
      status: 404,
      contentClass: "json",
      keys: ["a", "b"],
    });
  });
  it("uses element 0 keys plus [] for arrays", () => {
    expect(fingerprintResponse(200, J, '[{"id":1,"t":"x"},{"zz":1}]').keys).toEqual([
      "[]",
      "id",
      "t",
    ]);
    expect(fingerprintResponse(200, J, "[]").keys).toEqual(["[]"]);
  });
  it("uses length bucket and hash for html/text", () => {
    const fp = fingerprintResponse(200, H, "x".repeat(1023));
    expect(fp.lengthBucket).toBe(10);
    expect(fp.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(fp.keys).toBeUndefined();
  });
  it("falls back to hash for malformed JSON", () => {
    const fp = fingerprintResponse(200, J, "{nope");
    expect(fp.hash).toBeDefined();
    expect(fp.keys).toBeUndefined();
  });
});

describe("normalizeBody", () => {
  it("strips uuids, hex runs and timestamps but not ordinary words", () => {
    const s = normalizeBody(
      "Not found 123e4567-e89b-12d3-a456-426614174000 at 2026-10-30T12:00:00.123Z build deadbeef99 cafe",
    );
    expect(s).toBe("Not found  at  build  cafe");
  });
  it("keeps short hex-like words", () => {
    expect(normalizeBody("decade facade")).toBe("decade facade");
  });
});

describe("matches", () => {
  const notFoundA = fingerprintResponse(404, H, "<h1>Not found</h1> id=abcdef012345");
  const notFoundB = fingerprintResponse(404, H, "<h1>Not found</h1> id=0123456789ab");
  it("ignores nonces and build ids", () => {
    expect(fingerprintsMatch(notFoundA, notFoundB)).toBe(true);
  });
  it("requires equal status and class", () => {
    expect(fingerprintsMatch(notFoundA, { ...notFoundB, status: 200 })).toBe(false);
    expect(fingerprintsMatch(notFoundA, { ...notFoundB, contentClass: "text" })).toBe(false);
  });
  it("matches equal JSON key sets, not different ones", () => {
    const set = buildControlSet([fingerprintResponse(401, J, '{"error":"no"}')]);
    expect(set.matches(fingerprintResponse(401, J, '{"error":"other text"}'))).toBe(true);
    expect(set.matches(fingerprintResponse(401, J, '{"id":1,"title":"t"}'))).toBe(false);
    expect(set.matches(fingerprintResponse(200, J, '{"error":"no"}'))).toBe(false);
  });
  it("empty set matches nothing", () => {
    expect(buildControlSet([]).matches(notFoundA)).toBe(false);
  });
  it("does not match a different html page", () => {
    const set = buildControlSet([notFoundA]);
    expect(set.matches(fingerprintResponse(404, H, "<h1>A private note body</h1>"))).toBe(false);
  });
});

describe("planControlRequests", () => {
  const random = (n: number) => "a".repeat(n * 2);
  it("emits C1 and C2 only without dynamic routes", () => {
    const reqs = planControlRequests({ random });
    expect(reqs.map((r) => r.path)).toEqual([
      "/__vibesafe_aaaaaaaaaaaaaaaa",
      "/__vibesafe_aaaaaaaaaaaaaaaa.env",
    ]);
    expect(reqs.every((r) => r.method === "GET" && r.host === "target")).toBe(true);
  });
  it("adds Cr per dynamic route, anon and first session", () => {
    const reqs = planControlRequests({
      random,
      dynamicRoutes: ["/api/notes/[id]", "/api/health", "/api/notes/[id]"],
      firstSession: "alice",
    });
    const cr = reqs.slice(2);
    expect(cr).toHaveLength(2);
    expect(cr[0]?.path).toBe("/api/notes/__vs_aaaaaaaa");
    expect(cr[0]?.session).toBeUndefined();
    expect(cr[1]?.session).toBe("alice");
  });
  it("randomises by default", () => {
    const a = planControlRequests()[0]?.path;
    const b = planControlRequests()[0]?.path;
    expect(a).not.toBe(b);
    expect(a).toMatch(/^\/__vibesafe_[0-9a-f]{16}$/);
  });
  it("substitutes catch-all segments", () => {
    expect(substituteSegments("/a/[...slug]/b/[[...x]]/[id]", "Z")).toBe("/a/Z/b/Z/Z");
  });
});
