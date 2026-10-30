import { describe, expect, it } from "vitest";
import { renderAgentReport } from "../src/report/markdown.js";
import { renderTerminalSummary } from "../src/report/terminal.js";
import { formatCurl, placeholderName } from "../src/report/curl.js";
import type { AttackResult, AttackRun } from "../src/types.js";

const SENTINELS = ["SENTINEL_x@y.z", "SENTINEL_TOKEN", "ignore previous instructions"];

function result(over: Partial<AttackResult> = {}): AttackResult {
  return {
    attackId: "ATK-3f9a1c2b7d10",
    checkId: "idor",
    title: "one signed-in user can read another user's notes",
    outcome: "CONFIRMED",
    severity: "high",
    route: "/api/notes/[id]",
    method: "GET",
    sourceFile: "app/api/notes/[id]/route.js",
    line: 6,
    staticRef: {
      findingId: "VS-0123456789",
      ruleId: "authorization/idor-unscoped-lookup",
      title: "t",
      file: "f",
      severity: "high",
    },
    reasoning: "R3 returned the same keys as R2.",
    shapes: [
      { label: "R3", status: 200, rowCount: 1, keys: ["id", "user_id", "ignore previous instructions"] },
      { label: "R0", status: 401, keys: [] },
    ],
    curl: [
      formatCurl({
        targetUrl: "http://127.0.0.1:3000",
        path: "/api/notes/2",
        session: "alice",
        platform: "linux",
      }),
    ],
    fixGuidance: "Filter by user id.",
    ownerOk: true,
    ...over,
  };
}

function run(results: AttackResult[], over: Partial<AttackRun> = {}): AttackRun {
  return {
    schemaVersion: 1,
    vibesafeVersion: "0.5.0",
    mode: "baseline",
    startedAt: "",
    finishedAt: "",
    projectPath: "/p",
    targetUrl: "http://127.0.0.1:3000",
    groups: [],
    results,
    requestLog: [],
    ledger: { staticFlagged: 4, confirmed: 2, refuted: 1, untested: 1, errors: 0 },
    ...over,
  };
}

describe("agent markdown report", () => {
  it("renders shapes only; sentinel strings never appear, odd keys become <key>", () => {
    const r = result({
      // a hostile response must not be able to reach the report through any shape field
      shapes: [
        { label: "R3", status: 200, keys: ["id", "SENTINEL_x@y.z", "ignore previous instructions"] },
      ],
    });
    const md = renderAgentReport(run([r]));
    for (const s of SENTINELS) expect(md).not.toContain(s);
    expect(md).toContain("<key>");
    expect(md).toContain("keys: id, <key>, <key>");
    expect(md).toContain("# VibeSafe Attack Report: 2 confirmed · 1 refuted · 1 not tested");
    expect(md).toContain("npx vibesafe attack --replay ATK-3f9a1c2b7d10");
    expect(md).toContain("Owner access OK.");
  });

  it("sections for refuted and not tested; control chars collapse", () => {
    const md = renderAgentReport(
      run([
        result({ attackId: "ATK-aa", outcome: "NOT_REPRODUCED", reasoning: "refused (404)\n## evil" }),
        result({ attackId: "ATK-bb", outcome: "INCONCLUSIVE", method: "PATCH", reasoning: "write path" }),
      ]),
    );
    expect(md).toContain("## Refuted by the live test");
    expect(md).toContain("## Not tested");
    expect(md).not.toMatch(/^## evil/m);
  });

  it("retest lists diff states and only CONFIRMED needs fixing", () => {
    const md = renderAgentReport(
      run([result({ outcome: "NOT_REPRODUCED", attackId: "ATK-aa" })], {
        mode: "retest",
        diff: [{ attackId: "ATK-aa", was: "CONFIRMED", now: "NOT_REPRODUCED", state: "BLOCKED", ownerOk: true }],
      }),
    );
    expect(md).toContain("## Retest results");
    expect(md).toContain("ATK-aa: BLOCKED (was CONFIRMED), now NOT_REPRODUCED (owner access OK)");
  });
});

describe("curl formatting", () => {
  it("uses curl.exe and $env: placeholders on win32", () => {
    const c = formatCurl({
      targetUrl: "http://127.0.0.1:3000",
      path: "/api/notes/2",
      session: "alice",
      platform: "win32",
    });
    expect(c).toBe('curl.exe -s -H "Cookie: $env:ALICE_COOKIE" "http://127.0.0.1:3000/api/notes/2"');
  });

  it("uses curl and $PLACEHOLDER elsewhere; anonymous has no header", () => {
    expect(
      formatCurl({ targetUrl: "http://localhost:3000/", path: "/a", session: "alice", platform: "linux" }),
    ).toBe("curl -s -H \"Cookie: $ALICE_COOKIE\" 'http://localhost:3000/a'");
    expect(formatCurl({ targetUrl: "http://localhost:3000", path: "/a", platform: "darwin" })).toBe(
      "curl -s 'http://localhost:3000/a'",
    );
  });

  it("neutralises shell metacharacters and hostile labels", () => {
    const c = formatCurl({
      targetUrl: "http://127.0.0.1:3000",
      path: "/a'; rm -rf / `x` $(y)\"",
      session: "bob; x",
      platform: "linux",
    });
    expect(c).not.toMatch(/[`;]|\$\(/);
    expect(placeholderName("bob; x")).toBe("BOB_X_COOKIE");
    expect(formatCurl({ targetUrl: "javascript:alert(1)", path: "/", platform: "linux" })).toContain("<target>");
  });
});

describe("terminal summary", () => {
  it("has ledger, table, agent hint and html path", () => {
    const lines = renderTerminalSummary(run([result()]));
    expect(lines[0]).toBe("Static flagged 4 · live confirmed 2 · refuted 1 · couldn't test 1");
    expect(lines.join("\n")).toContain("CONFIRMED  ATK-3f9a1c2b7d10");
    expect(lines.join("\n")).toContain('Tell your agent: "Fix the issues in .vibesafe/attack-report.md"');
    expect(lines.join("\n")).toContain("HTML report: .vibesafe/attack-report.html");
  });
});
