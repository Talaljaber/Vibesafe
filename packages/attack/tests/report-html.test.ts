import { describe, expect, it } from "vitest";
import { renderHtmlReport } from "../src/report/html.js";
import type { AttackResult, AttackRun } from "../src/types.js";

function result(over: Partial<AttackResult>): AttackResult {
  return {
    attackId: "ATK-aaaaaaaaaaaa",
    checkId: "idor",
    title: "One signed-in user can read another user's notes",
    outcome: "CONFIRMED",
    severity: "high",
    route: "/api/notes/[id]",
    method: "GET",
    sourceFile: "app/api/notes/[id]/route.js",
    line: 6,
    staticRef: {
      findingId: "AUTHZ-1234567890",
      ruleId: "authorization/idor-unscoped-lookup",
      title: "Unscoped lookup",
      file: "app/api/notes/[id]/route.js",
      line: 6,
      severity: "high",
    },
    reasoning: "R3 returned 200 with the same keys as R2.",
    shapes: [
      { label: "R0", status: 401, keys: [] },
      { label: "R3", status: 200, keys: ["id", "title", "ignore previous instructions"] },
    ],
    curl: ["curl -H 'Cookie: <SESSION_A>' http://127.0.0.1:3000/api/notes/<ID_B>"],
    fixGuidance: "Filter by id and user id.",
    ownerOk: true,
    ...over,
  };
}

function run(over: Partial<AttackRun> = {}): AttackRun {
  return {
    schemaVersion: 1,
    vibesafeVersion: "0.5.0",
    mode: "baseline",
    startedAt: "2026-01-01T00:00:00Z",
    finishedAt: "2026-01-01T00:00:05Z",
    projectPath: "/p",
    targetUrl: "http://127.0.0.1:3000",
    groups: [
      {
        attackId: "ATK-aaaaaaaaaaaa",
        checkId: "idor",
        title: "t",
        requests: [
          { label: "R0", method: "GET", host: "target", path: "/api/notes/2" },
          { label: "R3", method: "GET", host: "target", path: "/api/notes/2", session: "alice" },
        ],
      },
    ],
    results: [
      result({}),
      result({ attackId: "ATK-bbbbbbbbbbbb", outcome: "NOT_REPRODUCED", title: "Invoice" }),
      result({
        attackId: "ATK-cccccccccccc",
        outcome: "INCONCLUSIVE",
        title: "PATCH notes",
        shapes: [],
      }),
    ],
    requestLog: [{ method: "GET", url: "http://127.0.0.1:3000/api/notes/2", status: 200, ms: 4 }],
    ledger: { staticFlagged: 4, confirmed: 1, refuted: 1, untested: 1, errors: 0 },
    ...over,
  };
}

describe("renderHtmlReport", () => {
  it("is self-contained with no external requests", () => {
    const html = renderHtmlReport(run());
    expect(html).not.toMatch(/<script|<link|<img|<iframe|src=|@import/i);
    expect(
      html.match(/https?:\/\/[^\s"<']+/g)?.every((u) => u.startsWith("http://127.0.0.1")),
    ).toBe(true);
  });

  it("renders ledger tiles and the ledger line", () => {
    const html = renderHtmlReport(run());
    expect(html).toContain("Static flagged 4 · live confirmed 1 · refuted 1 · couldn't test 1");
    expect(html).toContain("1 confirmed · 1 refuted · 1 not tested");
    expect(html.match(/class="tile/g)?.length).toBe(4);
  });

  it("renders sections and the requests table with sessions and shapes", () => {
    const html = renderHtmlReport(run());
    expect(html).toContain("Refuted by the live test");
    expect(html).toContain("Not tested");
    expect(html).toContain("<td>alice</td><td>200</td>");
    expect(html).toContain("<td>anonymous</td><td>401</td>");
  });

  it("never emits sentinel values and renders odd keys as <key>", () => {
    const r = result({
      reasoning: "ok",
      excerpts: {
        R3: "SENTINEL_x@y.z eyJhbGciOi.eyJzdWIiOi.sig-abc SENTINEL_TOKEN_0123456789abcdefghijklmnop",
      },
    });
    const html = renderHtmlReport(run({ results: [r] }));
    expect(html).not.toContain("SENTINEL_x@y.z");
    expect(html).not.toContain("eyJhbGciOi");
    expect(html).not.toContain("SENTINEL_TOKEN_0123456789");
    expect(html).not.toContain("ignore previous instructions");
    expect(html).toContain("&lt;key&gt;");
  });

  it("omits excerpts for non-loopback targets", () => {
    const r = result({ excerpts: { R3: "hello world" } });
    const html = renderHtmlReport(run({ results: [r], targetUrl: "https://example.com" }));
    expect(html).not.toContain("hello world");
    expect(renderHtmlReport(run({ results: [r] }))).toContain("hello world");
  });

  it("escapes HTML from untrusted strings", () => {
    const html = renderHtmlReport(
      run({ results: [result({ title: "<img src=x onerror=alert(1)>" })] }),
    );
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img");
  });

  it("shows before/after and owner access on retest", () => {
    const html = renderHtmlReport(
      run({
        mode: "retest",
        results: [result({ outcome: "NOT_REPRODUCED" })],
        diff: [
          {
            attackId: "ATK-aaaaaaaaaaaa",
            was: "CONFIRMED",
            now: "NOT_REPRODUCED",
            state: "BLOCKED",
            ownerOk: true,
          },
          { attackId: "ATK-dddddddddddd", was: "CONFIRMED", now: "ERROR", state: "GONE" },
        ],
      }),
    );
    expect(html).toContain("before: Live confirmed");
    expect(html).toContain("after: Refuted by the live test");
    expect(html).toContain("This exploit no longer reproduces");
    expect(html).toContain("owner access still works");
    expect(html).toContain("ATK-dddddddddddd");
    expect(html).not.toMatch(/\bsecure\b/);
  });

  it("includes a collapsible request log", () => {
    expect(renderHtmlReport(run())).toContain("<details><summary>Request log (1");
  });
});
