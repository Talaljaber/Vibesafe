import { describe, expect, it } from "vitest";
import { computeRetestDiff, exitCodeForRun } from "../src/diff.js";
import type { AttackOutcome, AttackResult, AttackRun, RetestState } from "../src/types.js";

function res(id: string, outcome: AttackOutcome, extra: Partial<AttackResult> = {}): AttackResult {
  return {
    attackId: id,
    checkId: "idor",
    title: id,
    outcome,
    severity: "high",
    route: `/api/${id}/[id]`,
    reasoning: "",
    shapes: [],
    curl: [],
    fixGuidance: "",
    ...extra,
  };
}

function baselineOf(...results: AttackResult[]): AttackRun {
  return {
    schemaVersion: 1,
    vibesafeVersion: "0",
    mode: "baseline",
    startedAt: "",
    finishedAt: "",
    projectPath: ".",
    targetUrl: "",
    groups: [],
    results,
    requestLog: [],
    ledger: { staticFlagged: 0, confirmed: 0, refuted: 0, untested: 0, errors: 0 },
  };
}

const routes = ["/api/a/[id]", "/api/b/[id]", "/api/c/[id]", "/api/d/[id]", "/api/e/[id]"];

function stateOf(
  was: AttackOutcome,
  now: AttackOutcome,
  extra: Partial<AttackResult> = {},
  opts: { ownerStatus?: number; routes?: string[] } = {},
): RetestState | undefined {
  const diff = computeRetestDiff({
    baseline: baselineOf(res("a", was)),
    replayed: [{ result: res("a", now, extra), ownerStatus: opts.ownerStatus }],
    fresh: [],
    freshRoutes: opts.routes ?? routes,
  });
  return diff[0]?.state;
}

describe("computeRetestDiff: the 7 states", () => {
  it("BLOCKED: was CONFIRMED, now NOT_REPRODUCED, owner still ok", () => {
    expect(stateOf("CONFIRMED", "NOT_REPRODUCED", { ownerOk: true })).toBe("BLOCKED");
  });
  it("BROKEN: attacker denied but owner not ok", () => {
    expect(stateOf("CONFIRMED", "NOT_REPRODUCED", { ownerOk: false })).toBe("BROKEN");
    expect(stateOf("CONFIRMED", "NOT_REPRODUCED")).toBe("BROKEN");
  });
  it("STILL_VULNERABLE: still CONFIRMED", () => {
    expect(stateOf("CONFIRMED", "CONFIRMED")).toBe("STILL_VULNERABLE");
  });
  it("GONE: route absent from the fresh map and owner control returns 404", () => {
    expect(
      stateOf("CONFIRMED", "NOT_REPRODUCED", { ownerOk: false }, { ownerStatus: 404, routes: [] }),
    ).toBe("GONE");
  });
  it("is not GONE when the route is still mapped or the owner control is not 404", () => {
    expect(stateOf("CONFIRMED", "NOT_REPRODUCED", { ownerOk: true }, { ownerStatus: 404 })).toBe(
      "BLOCKED",
    );
    expect(
      stateOf("CONFIRMED", "NOT_REPRODUCED", { ownerOk: false }, { ownerStatus: 500, routes: [] }),
    ).toBe("BROKEN");
  });
  it("GONE matches routes after parameter renames", () => {
    expect(
      stateOf(
        "CONFIRMED",
        "NOT_REPRODUCED",
        { ownerOk: true },
        { ownerStatus: 404, routes: ["/api/a/[noteId]"] },
      ),
    ).toBe("BLOCKED");
  });
  it("NEW: fresh CONFIRMED group absent from the baseline", () => {
    const diff = computeRetestDiff({
      baseline: baselineOf(res("a", "CONFIRMED")),
      replayed: [{ result: res("a", "CONFIRMED") }],
      fresh: [res("a", "CONFIRMED"), res("b", "CONFIRMED")],
      freshRoutes: routes,
    });
    expect(diff.map((d) => [d.attackId, d.state])).toEqual([
      ["a", "STILL_VULNERABLE"],
      ["b", "NEW"],
    ]);
    expect(diff[1]?.was).toBeUndefined();
  });
  it("NEW: baseline had it not CONFIRMED, fresh run confirms it", () => {
    expect(stateOf("INCONCLUSIVE", "CONFIRMED")).toBe("NEW");
    const diff = computeRetestDiff({
      baseline: baselineOf(res("a", "NOT_REPRODUCED")),
      replayed: [{ result: res("a", "NOT_REPRODUCED") }],
      fresh: [res("a", "CONFIRMED")],
      freshRoutes: routes,
    });
    expect(diff.map((d) => [d.state, d.was])).toEqual([["NEW", "NOT_REPRODUCED"]]);
  });
  it("ERROR: now ERROR", () => {
    expect(stateOf("CONFIRMED", "ERROR")).toBe("ERROR");
    expect(stateOf("INCONCLUSIVE", "ERROR")).toBe("ERROR");
  });
  it("UNCHANGED: everything else", () => {
    expect(stateOf("INCONCLUSIVE", "INCONCLUSIVE")).toBe("UNCHANGED");
    expect(stateOf("NOT_REPRODUCED", "NOT_REPRODUCED")).toBe("UNCHANGED");
    expect(stateOf("CONFIRMED", "INCONCLUSIVE")).toBe("UNCHANGED");
  });
  it("records was, now and ownerOk", () => {
    const diff = computeRetestDiff({
      baseline: baselineOf(res("a", "CONFIRMED")),
      replayed: [{ result: res("a", "NOT_REPRODUCED", { ownerOk: true }) }],
      fresh: [],
      freshRoutes: routes,
    });
    expect(diff[0]).toEqual({
      attackId: "a",
      was: "CONFIRMED",
      now: "NOT_REPRODUCED",
      state: "BLOCKED",
      ownerOk: true,
    });
  });
});

describe("exitCodeForRun", () => {
  const withDiff = (state: RetestState): AttackRun => ({
    ...baselineOf(res("a", "NOT_REPRODUCED")),
    mode: "retest",
    diff: [{ attackId: "a", now: "NOT_REPRODUCED", state }],
  });
  it("is 1 for CONFIRMED, STILL_VULNERABLE or NEW", () => {
    expect(exitCodeForRun(baselineOf(res("a", "CONFIRMED")))).toBe(1);
    expect(exitCodeForRun(withDiff("STILL_VULNERABLE"))).toBe(1);
    expect(exitCodeForRun(withDiff("NEW"))).toBe(1);
  });
  it("is 0 otherwise", () => {
    for (const s of ["BLOCKED", "BROKEN", "GONE", "UNCHANGED", "ERROR"] as const) {
      expect(exitCodeForRun(withDiff(s))).toBe(0);
    }
    expect(exitCodeForRun(baselineOf(res("a", "INCONCLUSIVE")))).toBe(0);
  });
});
