import { describe, expect, it } from "vitest";
import type { Finding } from "@talaljaber/vibesafe-shared";
import { buildControlSet, fingerprintResponse } from "../../src/controls.js";
import { idor } from "../../src/checks/idor.js";
import type { PlanContext, ProbeGroup, ProbeResponse, SessionSpec } from "../../src/types.js";

const FILE = "app/api/notes/[id]/route.js";
const SRC = [
  "export async function GET(request, { params }) {",
  "  const row = await db.from('notes').select('*').eq('id', id).single();",
  "}",
  "export async function PATCH(request, { params }) {",
  "  await db.from('notes').update({ title }).eq('id', id);",
  "}",
  "",
].join("\n");

const alice: SessionSpec = {
  label: "alice",
  headers: { Cookie: "a=1" },
  resources: { "/api/notes/[id]": "n_alice_1" },
};
const bob: SessionSpec = {
  label: "bob",
  headers: { Cookie: "b=1" },
  resources: { "/api/notes/[id]": "n_bob_1" },
};

function finding(line: number, verb: "reads" | "changes", file = FILE): Finding {
  return {
    id: `AUTHZ-${line}`,
    ruleId: "authorization/idor-unscoped-lookup",
    title: "Record accessed by a caller-supplied id without an ownership check",
    severity: "high",
    file,
    line,
    plainEnglishProblem: `This handler ${verb} a row of "notes" by an id taken from the URL, with no ownership check.`,
  } as unknown as Finding;
}

function ctx(over: Partial<PlanContext> = {}, src = SRC): PlanContext {
  return {
    findings: [finding(2, "reads"), finding(5, "changes")],
    routes: [
      {
        pattern: "/api/notes/[id]",
        sourceFile: FILE,
        methods: ["GET", "PATCH"],
        dynamicSegments: ["[id]"],
        findingRefs: [],
      },
    ],
    sessions: [alice, bob],
    env: {},
    readSource: (f) => (f === FILE ? src : undefined),
    ...over,
  };
}

const J = "application/json";
function res(label: string, status: number, body: unknown, ct = J): ProbeResponse {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  return {
    label,
    status,
    contentType: ct,
    headers: {},
    body: text,
    bodyTruncated: false,
    ms: 1,
    fingerprint: fingerprintResponse(status, ct, text),
  };
}
const note = (id: string, owner: string) => ({ id, title: "t", body: "b", user_id: owner });
const denied = (label: string, status = 401) => res(label, status, { error: "no" });

const group = (): ProbeGroup => idor.plan(ctx())[0]!;
const run = (rs: ProbeResponse[], controls = buildControlSet([])) =>
  idor.evaluate(group(), rs, controls);

describe("idor.plan", () => {
  it("plans R0-R3 for the GET and skips the PATCH as a write path", () => {
    const groups = idor.plan(ctx());
    expect(groups).toHaveLength(2);
    const get = groups.find((g) => g.method === "GET")!;
    expect(get.skip).toBeUndefined();
    expect(get.requests.map((r) => [r.label, r.path, r.session])).toEqual([
      ["R0", "/api/notes/n_bob_1", undefined],
      ["R1", "/api/notes/n_alice_1", "alice"],
      ["R2", "/api/notes/n_bob_1", "bob"],
      ["R3", "/api/notes/n_bob_1", "alice"],
    ]);
    expect(get.ownerLabels).toEqual(["R1", "R2"]);
    expect(get.attackId).toMatch(/^ATK-[0-9a-f]{12}$/);
    const patch = groups.find((g) => g.method === "PATCH")!;
    expect(patch.skip?.reason).toMatch(/write path, not tested/);
    expect(patch.requests).toEqual([]);
    expect(patch.attackId).not.toBe(get.attackId);
  });

  it("percent-encodes resource ids", () => {
    const b2 = { ...bob, resources: { "/api/notes/[id]": "a b/../c?x" } };
    const g = idor.plan(ctx({ sessions: [alice, b2] }))[0]!;
    expect(g.requests[0]?.path).toBe("/api/notes/a%20b%2F..%2Fc%3Fx");
  });

  it("skips: route not resolved, one session, no id, may-write GET", () => {
    expect(idor.plan(ctx({ routes: [] }))[0]?.skip?.reason).toMatch(/route not resolved/);
    expect(idor.plan(ctx({ sessions: [alice] }))[0]?.skip?.reason).toMatch(/two test sessions/);
    const noId = { ...bob, resources: {} };
    expect(idor.plan(ctx({ sessions: [alice, noId] }))[0]?.skip?.reason).toMatch(
      /two test sessions/,
    );
    const writing = SRC.replace("select('*')", "update({}).select('*')");
    expect(idor.plan(ctx({}, writing))[0]?.skip?.reason).toBe("handler may write");
  });

  it("ignores other rules and dedupes the same route and method", () => {
    const other = { ...finding(2, "reads"), ruleId: "auth/missing-route-auth" } as Finding;
    expect(idor.plan(ctx({ findings: [other] }))).toEqual([]);
    expect(idor.plan(ctx({ findings: [finding(2, "reads"), finding(2, "reads")] }))).toHaveLength(
      1,
    );
  });

  it("evaluating a skipped group returns its INCONCLUSIVE reason", () => {
    const patch = idor.plan(ctx()).find((g) => g.method === "PATCH")!;
    const r = idor.evaluate(patch, [], buildControlSet([]));
    expect(r.outcome).toBe("INCONCLUSIVE");
    expect(r.reasoning).toMatch(/write path/);
  });
});

describe("idor.evaluate scenarios", () => {
  const bobsNote = note("n_bob_1", "u_bob");
  const alicesNote = note("n_alice_1", "u_alice");

  it("real exploit: alice reads bob's note", () => {
    const r = run([
      denied("R0"),
      res("R1", 200, alicesNote),
      res("R2", 200, bobsNote),
      res("R3", 200, bobsNote),
    ]);
    expect(r.outcome).toBe("CONFIRMED");
    expect(r.severity).toBe("high");
    expect(r.ownerOk).toBe(true);
    expect(r.title).toBe("One signed-in user can read another user's notes.");
    expect(JSON.stringify(r)).not.toContain("u_bob");
    expect(r.curl.join(" ")).not.toContain("b=1");
  });

  it("anonymous exploit is CONFIRMED critical", () => {
    const r = run([
      res("R0", 200, bobsNote),
      res("R1", 200, alicesNote),
      res("R2", 200, bobsNote),
      res("R3", 200, bobsNote),
    ]);
    expect(r.outcome).toBe("CONFIRMED");
    expect(r.severity).toBe("critical");
    expect(r.title).toMatch(/Anyone, even logged out/);
  });

  it("fixed: R3 404 with owners fine is NOT_REPRODUCED and ownerOk", () => {
    const r = run([
      denied("R0"),
      res("R1", 200, alicesNote),
      res("R2", 200, bobsNote),
      denied("R3", 404),
    ]);
    expect(r.outcome).toBe("NOT_REPRODUCED");
    expect(r.ownerOk).toBe(true);
  });

  it("R3 matching an SPA/control fingerprint is NOT_REPRODUCED", () => {
    const html = "<html><body>app shell</body></html>";
    const control = buildControlSet([fingerprintResponse(200, "text/html", html)]);
    const r = run(
      [
        denied("R0"),
        res("R1", 200, alicesNote),
        res("R2", 200, bobsNote),
        res("R3", 200, html, "text/html"),
      ],
      control,
    );
    expect(r.outcome).toBe("NOT_REPRODUCED");
    expect(r.reasoning).toMatch(/refused|control/);
  });

  it("soft 404 (200 with an error body) is NOT_REPRODUCED", () => {
    const r = run([
      denied("R0"),
      res("R1", 200, alicesNote),
      res("R2", 200, bobsNote),
      res("R3", 200, { error: "not found" }),
    ]);
    expect(r.outcome).toBe("NOT_REPRODUCED");
  });

  it("R3 with a different key set is NOT_REPRODUCED", () => {
    const r = run([
      denied("R0"),
      res("R1", 200, alicesNote),
      res("R2", 200, bobsNote),
      res("R3", 200, { id: "n_bob_1", redacted: true }),
    ]);
    expect(r.outcome).toBe("NOT_REPRODUCED");
  });

  it("id ignored (alice gets her own record) is NOT_REPRODUCED", () => {
    const r = run([
      denied("R0"),
      res("R1", 200, alicesNote),
      res("R2", 200, bobsNote),
      res("R3", 200, alicesNote),
    ]);
    expect(r.outcome).toBe("NOT_REPRODUCED");
    expect(r.reasoning).toMatch(/not Bob's record/);
  });

  it("no id key: identical to the user's own record is not confirmed", () => {
    const own = { title: "same", body: "x" };
    const bobs = { title: "other", body: "y" };
    const r = run([denied("R0"), res("R1", 200, own), res("R2", 200, bobs), res("R3", 200, own)]);
    expect(r.outcome).toBe("NOT_REPRODUCED");
  });

  it("no id key: indistinguishable owner records are INCONCLUSIVE", () => {
    const own = { title: "same", body: "x" };
    const r = run([denied("R0"), res("R1", 200, own), res("R2", 200, own), res("R3", 200, own)]);
    expect(r.outcome).toBe("INCONCLUSIVE");
  });

  it("refusal and control reasoning differ", () => {
    const base = [
      denied("R0"),
      res("R1", 200, note("n_alice_1", "a")),
      res("R2", 200, note("n_bob_1", "b")),
    ];
    expect(run([...base, denied("R3", 403)]).reasoning).toMatch(
      /refused to the first user \(403\)/,
    );
    const html = "<html>shell</html>";
    const control = buildControlSet([fingerprintResponse(200, "text/html", html)]);
    const r = run([...base, res("R3", 200, html, "text/html")], control);
    expect(r.reasoning).toMatch(/matches a not-found\/auth-wall control/);
  });

  it("non-JSON or truncated owner response is INCONCLUSIVE", () => {
    const base = [denied("R0"), res("R1", 200, note("n_alice_1", "a"))];
    const text = run([
      ...base,
      res("R2", 200, "plain text", "text/plain"),
      res("R3", 200, "plain text", "text/plain"),
    ]);
    expect(text.outcome).toBe("INCONCLUSIVE");
    const bob = note("n_bob_1", "b");
    const trunc = { ...res("R3", 200, bob), bodyTruncated: true };
    expect(run([...base, res("R2", 200, bob), trunc]).outcome).toBe("INCONCLUSIVE");
  });

  it("several *Id keys: the one equal to the target id is used", () => {
    const bobs = { authorId: "u_bob", noteId: "n_bob_1", title: "t" };
    const r = run([
      denied("R0"),
      res("R1", 200, { authorId: "u_alice", noteId: "n_alice_1", title: "s" }),
      res("R2", 200, bobs),
      res("R3", 200, bobs),
    ]);
    expect(r.outcome).toBe("CONFIRMED");
  });

  it("caps the stored key list", () => {
    const big = Object.fromEntries(Array.from({ length: 50 }, (_, i) => [`k${i}`, i]));
    const r = run([denied("R0"), res("R1", 200, big), res("R2", 200, big), res("R3", 200, big)]);
    expect(r.shapes.find((s) => s.label === "R2")!.keys.length).toBe(32);
  });

  it("same id for both sessions is skipped, nothing sent", () => {
    const same = { ...bob, resources: { "/api/notes/[id]": "n_alice_1" } };
    const g = idor.plan(ctx({ sessions: [alice, same] })).find((x) => x.method === "GET")!;
    expect(g.requests).toEqual([]);
    expect(g.skip?.outcome).toBe("INCONCLUSIVE");
    expect(g.skip?.reason).toMatch(/same id/);
  });

  it("skipped write group gets a neutral title", () => {
    const patch = idor.plan(ctx()).find((g) => g.method === "PATCH")!;
    expect(patch.title).toBe("Write to another user's notes (not tested).");
  });

  it("no id key: exact copy of bob's distinct record is CONFIRMED", () => {
    const r = run([
      denied("R0"),
      res("R1", 200, { title: "a", body: "x" }),
      res("R2", 200, { title: "b", body: "y" }),
      res("R3", 200, { title: "b", body: "y" }),
    ]);
    expect(r.outcome).toBe("CONFIRMED");
  });

  it("owner R2 404 is INCONCLUSIVE", () => {
    const r = run([
      denied("R0", 404),
      res("R1", 200, alicesNote),
      denied("R2", 404),
      denied("R3", 404),
    ]);
    expect(r.outcome).toBe("INCONCLUSIVE");
    expect(r.ownerOk).toBe(false);
  });

  it("owner R2 matching a control is INCONCLUSIVE", () => {
    const control = buildControlSet([fingerprintResponse(200, J, JSON.stringify(bobsNote))]);
    const r = run(
      [
        denied("R0"),
        res("R1", 200, alicesNote),
        res("R2", 200, bobsNote),
        res("R3", 200, bobsNote),
      ],
      control,
    );
    expect(r.outcome).toBe("INCONCLUSIVE");
  });

  it("R3 500 and a connection error are ERROR, never a pass", () => {
    const base = [denied("R0"), res("R1", 200, alicesNote), res("R2", 200, bobsNote)];
    expect(run([...base, res("R3", 500, "boom", "text/plain")]).outcome).toBe("ERROR");
    expect(run([...base, res("R3", 0, "", "")]).outcome).toBe("ERROR");
    expect(run([...base]).outcome).toBe("ERROR");
  });

  it("login-wall 200 matching the signed-in control is NOT_REPRODUCED", () => {
    const wall = { error: "please sign in", loginUrl: "/login" };
    const control = buildControlSet([fingerprintResponse(200, J, JSON.stringify(wall))]);
    const r = run(
      [denied("R0"), res("R1", 200, alicesNote), res("R2", 200, bobsNote), res("R3", 200, wall)],
      control,
    );
    expect(r.outcome).toBe("NOT_REPRODUCED");
  });

  it("R3 redirect to a login page is NOT_REPRODUCED", () => {
    const redirect = { ...res("R3", 302, "", "text/plain"), location: "/login?next=/x" };
    const r = run([denied("R0"), res("R1", 200, alicesNote), res("R2", 200, bobsNote), redirect]);
    expect(r.outcome).toBe("NOT_REPRODUCED");
  });

  it("returns shapes only with sanitized key names", () => {
    const r = run([
      denied("R0"),
      res("R1", 200, alicesNote),
      res("R2", 200, { "weird key!": 1, id: "n_bob_1" }),
      res("R3", 200, [bobsNote, bobsNote]),
    ]);
    const r2 = r.shapes.find((s) => s.label === "R2")!;
    expect(r2.keys).toContain("<key>");
    expect(r.shapes.find((s) => s.label === "R3")?.rowCount).toBe(2);
    expect(r.excerpts).toBeUndefined();
  });
});

describe("idor.evaluate review fixes", () => {
  const nestedFile = "app/api/projects/[id]/settings/route.js";
  const nestedSrc =
    "export async function GET(request, { params }) {\n  const r = await db.from('projects').select('*').eq('id', id).single();\n}\n";
  const nres = (p: string) => ({ ...alice, resources: { [p]: "p1" } });
  const nctx = (): PlanContext => ({
    findings: [{ ...finding(2, "reads", nestedFile) } as Finding],
    routes: [
      {
        pattern: "/api/projects/[id]/settings",
        sourceFile: nestedFile,
        methods: ["GET"],
        dynamicSegments: ["[id]"],
        findingRefs: [],
      },
    ],
    sessions: [
      nres("/api/projects/[id]/settings"),
      { ...bob, resources: { "/api/projects/[id]/settings": "p2" } },
    ],
    env: {},
    readSource: (f) => (f === nestedFile ? nestedSrc : undefined),
  });

  it("nested route: id taken from the dynamic segment, real IDOR CONFIRMED", () => {
    const g = idor.plan(nctx())[0]!;
    expect(g.skip).toBeUndefined();
    const bobs = { id: "p2", name: "x", owner: "bob" };
    const r = idor.evaluate(
      g,
      [
        denied("R0"),
        res("R1", 200, { id: "p1", name: "y", owner: "a" }),
        res("R2", 200, bobs),
        res("R3", 200, bobs),
      ],
      buildControlSet([]),
    );
    expect(r.outcome).toBe("CONFIRMED");
  });

  it("unresolved handler gets a distinct reason", () => {
    const f = { ...finding(2, "reads"), line: undefined } as unknown as Finding;
    expect(idor.plan(ctx({ findings: [f] }))[0]?.skip?.reason).toBe("handler not resolved");
  });

  it("a read finding wins over a skipped one for the same attack id", () => {
    const g = idor.plan(ctx({ findings: [finding(5, "changes"), finding(2, "reads")] }));
    expect(g.filter((x) => x.method === "GET" && !x.skip)).toHaveLength(1);
  });

  const alicesNote = note("n_alice_1", "u_alice");
  const bobsNote = note("n_bob_1", "u_bob");
  const base = () => [denied("R0"), res("R1", 200, alicesNote), res("R2", 200, bobsNote)];

  it("R3 429 / 204 / 400 are INCONCLUSIVE, not refuted", () => {
    for (const s of [429, 204, 400]) {
      expect(run([...base(), res("R3", s, "x", "text/plain")]).outcome).toBe("INCONCLUSIVE");
    }
  });

  it("no id key and a body differing from both is INCONCLUSIVE", () => {
    const r = run([
      denied("R0"),
      res("R1", 200, { title: "a", body: "x" }),
      res("R2", 200, { title: "b", body: "y" }),
      res("R3", 200, { title: "c", body: "z" }),
    ]);
    expect(r.outcome).toBe("INCONCLUSIVE");
  });

  it("anonymous 200 with no id and a different body is not CONFIRMED critical", () => {
    const r = run([
      res("R0", 200, { title: "fallback", body: "q" }),
      res("R1", 200, { title: "a", body: "x" }),
      res("R2", 200, { title: "b", body: "y" }),
      denied("R3"),
    ]);
    expect(r.severity).not.toBe("critical");
    expect(r.outcome).toBe("NOT_REPRODUCED");
  });

  it("curl lines are escaped placeholders", () => {
    const evil = { ...bob, resources: { "/api/notes/[id]": "n1" } };
    const g = idor.plan(ctx({ sessions: [alice, evil] }))[0]!;
    g.requests[0]!.path = "/api/$(id)`x`/n1";
    const r = idor.evaluate(g, base().concat(denied("R3")), buildControlSet([]));
    const joined = r.curl.join("\n");
    expect(joined).not.toMatch(/\$\(|`/);
    expect(joined).toMatch(/ALICE_COOKIE/);
  });
});

describe("idor.evaluate review round 3", () => {
  const A = { id: "u-1", slug: "n_alice_1", title: "SENTINEL_VALUE_x9", body: "b" };
  const B = { id: "u-2", slug: "n_bob_1", title: "SENTINEL_VALUE_x9", body: "c" };
  it("slug route whose body id is not the url id is not refuted", () => {
    const r = run([denied("R0"), res("R1", 200, A), res("R2", 200, B), res("R3", 200, B)]);
    expect(r.outcome).toBe("CONFIRMED");
  });
  it("a lone userId key does not refute a real IDOR", () => {
    const a = { userId: "u_alice", title: "t", body: "a" };
    const b = { userId: "u_bob", title: "t", body: "b" };
    const r = run([denied("R0"), res("R1", 200, a), res("R2", 200, b), res("R3", 200, b)]);
    expect(r.outcome).toBe("CONFIRMED");
  });
  it("empty owner response is INCONCLUSIVE", () => {
    for (const body of [[], {}]) {
      const r = run([
        denied("R0"),
        res("R1", 200, body),
        res("R2", 200, body),
        res("R3", 200, body),
      ]);
      expect(r.outcome).toBe("INCONCLUSIVE");
    }
  });
  it("a clear refusal wins over a non-JSON owner response", () => {
    const r = run([
      denied("R0"),
      res("R1", 200, "hello", "text/plain"),
      res("R2", 200, "world", "text/plain"),
      denied("R3", 404),
    ]);
    expect(r.outcome).toBe("NOT_REPRODUCED");
  });
  it("never leaks response values or session headers", () => {
    const r = run([denied("R0"), res("R1", 200, A), res("R2", 200, B), res("R3", 200, B)]);
    const j = JSON.stringify(r);
    expect(j).not.toContain("SENTINEL_VALUE_x9");
    expect(j).not.toContain("b=1");
    expect(j).not.toContain("a=1");
  });
  it("skips dot-segment resource ids", () => {
    const g = idor.plan(
      ctx({ sessions: [alice, { ...bob, resources: { "/api/notes/[id]": ".." } }] }),
    )[0]!;
    expect(g.requests).toEqual([]);
    expect(g.skip?.outcome).toBe("INCONCLUSIVE");
  });
  it("multi-segment routes get their own skip reason", () => {
    const file = "app/api/orgs/[orgId]/notes/[id]/route.js";
    const g = idor.plan(
      ctx({
        findings: [finding(2, "reads", file)],
        routes: [
          {
            pattern: "/api/orgs/[orgId]/notes/[id]",
            sourceFile: file,
            methods: ["GET"],
            dynamicSegments: ["[orgId]", "[id]"],
            findingRefs: [],
          },
        ],
        readSource: () => SRC,
      }),
    )[0]!;
    expect(g.skip?.reason).toMatch(/several id segments/);
  });
});
