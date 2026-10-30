import { describe, expect, it } from "vitest";
import type { Finding } from "@talaljaber/vibesafe-shared";
import { buildRouteMap, concretePath } from "../../src/target/route-map.js";

const GET = "export async function GET() { return 1; }\n";
const GET_PATCH = `${GET}export async function PATCH() { return 2; }\n`;

const sources: Record<string, string> = {
  "app/api/notes/[id]/route.js": GET_PATCH,
  "app/(admin)/api/admin/users/route.ts": GET,
  "app/api/docs/[...slug]/route.mjs": GET,
  "src/app/api/items/route.ts": "export const POST = async () => 1;\n",
  "app/api/auth/login/route.ts": GET,
  "app/page.tsx": "export default function P() {}",
};
const read = (f: string): string | undefined => sources[f];

describe("buildRouteMap", () => {
  const routes = buildRouteMap(Object.keys(sources), read);
  const byPattern = (p: string) => routes.find((r) => r.pattern === p);

  it("drops (group) segments and handles .js/.ts/.mjs", () => {
    expect(byPattern("/api/admin/users")?.sourceFile).toBe("app/(admin)/api/admin/users/route.ts");
    expect(byPattern("/api/docs/[...slug]")).toBeDefined();
    expect(byPattern("/api/items")?.methods).toEqual(["POST"]);
  });
  it("records [id] and [...slug] dynamic segments", () => {
    expect(byPattern("/api/notes/[id]")?.dynamicSegments).toEqual(["[id]"]);
    expect(byPattern("/api/docs/[...slug]")?.dynamicSegments).toEqual(["[...slug]"]);
    expect(byPattern("/api/admin/users")?.dynamicSegments).toEqual([]);
  });
  it("lists exported methods", () => {
    expect(byPattern("/api/notes/[id]")?.methods).toEqual(["GET", "PATCH"]);
  });
  it("excludes public routes and non-route files", () => {
    expect(byPattern("/api/auth/login")).toBeUndefined();
    expect(routes).toHaveLength(4);
  });
  it("attaches findings by file", () => {
    const f = {
      id: "IDOR-1",
      ruleId: "idor/x",
      title: "t",
      severity: "high",
      file: "app\\api\\notes\\[id]\\route.js",
      line: 3,
    } as unknown as Finding;
    const r = buildRouteMap(Object.keys(sources), read, [f]);
    expect(r.find((x) => x.pattern === "/api/notes/[id]")?.findingRefs[0]?.findingId).toBe(
      "IDOR-1",
    );
  });
});

describe("concretePath", () => {
  const session = { label: "alice", headers: {}, resources: { "/api/notes/[id]": "n1" } };
  it("fills dynamic segments from session resources", () => {
    expect(concretePath("/api/notes/[id]", session)).toEqual({ path: "/api/notes/n1" });
  });
  it("static routes need no id", () => {
    expect(concretePath("/api/me", undefined)).toEqual({ path: "/api/me" });
  });
  it("never invents ids", () => {
    const r = concretePath("/api/notes/[id]", undefined);
    expect(r).toEqual({ skip: { outcome: "INCONCLUSIVE", reason: "no test id for this route" } });
    expect(concretePath("/api/x/[id]", session)).toHaveProperty("skip");
  });
});

describe("concretePath encoding", () => {
  const sess = (pattern: string, id: string) => ({ resources: { [pattern]: id } }) as never;
  it("encodes reserved characters in [x] ids", () => {
    expect(concretePath("/api/n/[id]", sess("/api/n/[id]", "a b#c?d/../x"))).toEqual({
      path: "/api/n/a%20b%23c%3Fd%2F..%2Fx",
    });
  });
  it("keeps slashes between catch-all parts", () => {
    expect(concretePath("/api/f/[...p]", sess("/api/f/[...p]", "a b/c"))).toEqual({
      path: "/api/f/a%20b/c",
    });
  });
  it("skips patterns with several dynamic segments", () => {
    const p = "/api/o/[org]/n/[id]";
    expect(concretePath(p, sess(p, "n1"))).toHaveProperty("skip");
  });
});
