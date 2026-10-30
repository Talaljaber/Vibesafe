import { describe, expect, it } from "vitest";
import type { Finding } from "@talaljaber/vibesafe-shared";
import { buildControlSet, fingerprintResponse } from "../../src/controls.js";
import { unauthRoute } from "../../src/checks/unauth-route.js";
import { buildRouteMap } from "../../src/target/route-map.js";
import type { ControlSet, PlanContext, ProbeResponse, SessionSpec } from "../../src/types.js";

const J = "application/json";
const GET = "export async function GET() { return Response.json([]); }\n";
const sources: Record<string, string> = {
  "app/api/admin/users/route.js": GET,
  "app/api/notes/[id]/route.js": `${GET}export async function PATCH() { return 1; }\n`,
  "app/api/health-data/route.js": GET,
  "app/api/seed/route.js": GET,
  "app/api/export/route.js": "export async function POST() { return 1; }\n",
  "app/api/writes/route.js": 'export async function GET() { await db.from("a").insert({}); }\n',
};
const read = (f: string): string | undefined => sources[f];
const finding = (file: string, line: number): Finding =>
  ({
    id: `AUTH-${file.length}${line}`,
    ruleId: "auth/missing-route-auth",
    title: "Missing authentication in API Route",
    severity: "high",
    category: "auth",
    file,
    line,
  }) as unknown as Finding;

const alice: SessionSpec = {
  label: "alice",
  headers: { Cookie: "a=1" },
  resources: { "/api/notes/[id]": "n 1" },
};

function ctx(findings: Finding[], sessions: SessionSpec[] = []): PlanContext {
  return {
    findings,
    routes: buildRouteMap(Object.keys(sources), read),
    sessions,
    env: {},
    readSource: read,
  };
}
const none: ControlSet = buildControlSet([]);
const resp = (
  label: string,
  status: number,
  body = "",
  contentType = J,
  extra: Partial<ProbeResponse> = {},
): ProbeResponse => ({
  label,
  status,
  contentType,
  headers: {},
  body,
  bodyTruncated: false,
  ms: 1,
  fingerprint: fingerprintResponse(status, contentType, body),
  ...extra,
});

const adminGroup = () => unauthRoute.plan(ctx([finding("app/api/admin/users/route.js", 1)]))[0]!;
const run = (rs: ProbeResponse[], controls = none) =>
  unauthRoute.evaluate(adminGroup(), rs, controls);

describe("unauth-route.plan", () => {
  it("plans U1 anonymous and U2 as the first session", () => {
    const [g] = unauthRoute.plan(ctx([finding("app/api/admin/users/route.js", 1)], [alice]));
    expect(g?.requests.map((r) => [r.label, r.path, r.session])).toEqual([
      ["U1", "/api/admin/users", undefined],
      ["U2", "/api/admin/users", "alice"],
    ]);
    expect(g?.attackId).toMatch(/^ATK-[0-9a-f]{12}$/);
  });
  it("plans only U1 without sessions", () => {
    expect(adminGroup().requests.map((r) => r.label)).toEqual(["U1"]);
  });
  it("ignores other rules", () => {
    const f = { ...finding("app/api/admin/users/route.js", 1), ruleId: "x/y" } as Finding;
    expect(unauthRoute.plan(ctx([f]))).toEqual([]);
  });
  it("skips a non-GET enclosing handler as write path", () => {
    const [g] = unauthRoute.plan(ctx([finding("app/api/export/route.js", 1)]));
    expect(g?.skip?.reason).toMatch(/write path, not tested/);
    expect(g?.requests).toEqual([]);
  });
  it("skips when the pre-flight fails", () => {
    const [g] = unauthRoute.plan(ctx([finding("app/api/writes/route.js", 1)]));
    expect(g?.skip?.reason).toBe("handler may write");
    const [s] = unauthRoute.plan(ctx([finding("app/api/seed/route.js", 1)]));
    expect(s?.skip?.reason).toBe("handler may write");
  });
  it("skips a dynamic route with no resource id, never inventing one", () => {
    const f = finding("app/api/notes/[id]/route.js", 1);
    expect(unauthRoute.plan(ctx([f]))[0]?.skip?.reason).toBe("no test id for this route");
    expect(unauthRoute.plan(ctx([f], [{ ...alice, resources: {} }]))[0]?.skip).toBeDefined();
  });
  it("percent-encodes the resource id", () => {
    const g = unauthRoute.plan(ctx([finding("app/api/notes/[id]/route.js", 1)], [alice]))[0]!;
    expect(g.requests[0]?.path).toBe("/api/notes/n%201");
  });
  it("skips an unresolved route and dedupes findings of the same route", () => {
    const [g] = unauthRoute.plan(ctx([finding("pages/api/x.js", 1)]));
    expect(g?.skip?.reason).toMatch(/route not resolved/);
    const two = unauthRoute.plan(
      ctx([finding("app/api/admin/users/route.js", 1), finding("app/api/admin/users/route.js", 1)]),
    );
    expect(two).toHaveLength(1);
  });
});

describe("unauth-route.evaluate", () => {
  it("CONFIRMED on a sensitive route returning 200 JSON", () => {
    const r = run([resp("U1", 200, '{"users":[{"id":1}]}')]);
    expect(r.outcome).toBe("CONFIRMED");
    expect(r.title).toBe("This endpoint returns private data without logging in.");
  });
  it("CONFIRMED on sensitive body keys at depth 2 for a non-risky path", () => {
    const g = unauthRoute.plan(ctx([finding("app/api/health-data/route.js", 1)]))[0]!;
    const r = unauthRoute.evaluate(
      g,
      [resp("U1", 200, '{"data":{"items":[{"userEmail":"a@b.c"}]}}')],
      none,
    );
    expect(r.outcome).toBe("CONFIRMED");
    expect(r.shapes[0]?.keys).toEqual(["data"]);
  });
  it("NOT_REPRODUCED for public JSON without sensitive fields", () => {
    const g = unauthRoute.plan(ctx([finding("app/api/health-data/route.js", 1)]))[0]!;
    const r = unauthRoute.evaluate(g, [resp("U1", 200, '{"version":"1","ok":true}')], none);
    expect(r.outcome).toBe("NOT_REPRODUCED");
  });
  it.each([401, 403])("NOT_REPRODUCED on %i", (s) => {
    expect(run([resp("U1", s, '{"error":"no"}')]).outcome).toBe("NOT_REPRODUCED");
  });
  it("NOT_REPRODUCED on a redirect to a login page", () => {
    const r = run([resp("U1", 302, "", "text/html", { location: "/login?next=%2F" })]);
    expect(r.outcome).toBe("NOT_REPRODUCED");
  });
  it("NOT_REPRODUCED when the response matches a control (SPA fallback)", () => {
    const body = '{"error":"not found"}';
    const controls = buildControlSet([fingerprintResponse(200, J, body)]);
    expect(run([resp("U1", 200, body)], controls).outcome).toBe("NOT_REPRODUCED");
  });
  it("INCONCLUSIVE for HTML 200, empty JSON, other 3xx and 404", () => {
    expect(run([resp("U1", 200, "<html>hi</html>", "text/html")]).outcome).toBe("INCONCLUSIVE");
    expect(run([resp("U1", 200, "[]")]).outcome).toBe("INCONCLUSIVE");
    expect(run([resp("U1", 302, "", "text/html", { location: "/x" })]).outcome).toBe(
      "INCONCLUSIVE",
    );
    expect(run([resp("U1", 404, "nope", "text/plain")]).outcome).toBe("INCONCLUSIVE");
  });
  it("ERROR on status 0 and 5xx, and when U1 is missing", () => {
    expect(run([resp("U1", 0)]).outcome).toBe("ERROR");
    expect(run([resp("U1", 500, "{}")]).outcome).toBe("ERROR");
    expect(run([]).outcome).toBe("ERROR");
  });
  it("ownerOk follows U2", () => {
    const u1 = resp("U1", 200, '{"users":[1]}');
    expect(run([u1]).ownerOk).toBe(true);
    expect(run([u1, resp("U2", 403, "{}")]).ownerOk).toBe(true);
    expect(run([u1, resp("U2", 404, "{}")]).ownerOk).toBe(false);
    expect(run([u1, resp("U2", 500, "{}")]).ownerOk).toBe(false);
  });
  it("never leaks response values and uses placeholder curl lines", () => {
    const r = run([resp("U1", 200, '{"users":[{"email":"leak@example.com"}]}')]);
    expect(JSON.stringify(r)).not.toContain("leak@example.com");
    expect(r.curl).toHaveLength(1);
    expect(r.curl?.[0]).toMatch(/^curl(\.exe)? -s .*<target>\/api\/admin\/users/);
  });
  it("a skipped group evaluates to its INCONCLUSIVE reason", () => {
    const [g] = unauthRoute.plan(ctx([finding("app/api/export/route.js", 1)]));
    const r = unauthRoute.evaluate(g!, [], none);
    expect(r.outcome).toBe("INCONCLUSIVE");
    expect(r.reasoning).toMatch(/write path/);
  });
  it("error-only 200 bodies are INCONCLUSIVE, never CONFIRMED", () => {
    expect(run([resp("U1", 200, '{"error":"Unauthorized"}')]).outcome).toBe("INCONCLUSIVE");
  });
  it("U2 matching a control makes ownerOk false", () => {
    const body = '{"error":"not found"}';
    const controls = buildControlSet([fingerprintResponse(200, J, body)]);
    const r = run([resp("U1", 200, '{"users":[1]}'), resp("U2", 200, body)], controls);
    expect(r.ownerOk).toBe(false);
  });
  it("a shell metacharacter in a route segment never reaches curl unescaped", () => {
    const g = adminGroup();
    const r = unauthRoute.evaluate(
      { ...g, requests: [{ label: "U1", method: "GET", host: "target", path: "/api/$(id)`x`" }] },
      [resp("U1", 200, '{"users":[1]}')],
      none,
    );
    expect(r.curl?.join("\n")).not.toMatch(/\$\(|`/);
  });
  it("a GET finding replaces an earlier write-path skip for the same route", () => {
    const gs = unauthRoute.plan(
      ctx(
        [finding("app/api/notes/[id]/route.js", 2), finding("app/api/notes/[id]/route.js", 1)],
        [alice],
      ),
    );
    expect(gs).toHaveLength(1);
    expect(gs[0]?.skip).toBeUndefined();
  });
});
