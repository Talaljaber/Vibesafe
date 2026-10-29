import { describe, it, expect } from "vitest";
import { RouteSecretDetector } from "../../src/detectors/route-secret-detector.js";
import { IdorDetector } from "../../src/detectors/idor-detector.js";
import { UNAMBIGUOUS_SECRET_NAME_RE } from "../../src/detectors/patterns/auth-patterns.js";
import { run } from "../helpers/injection.js";

describe("pagination cursors are not secret names", () => {
  for (const n of [
    "pageToken",
    "nextToken",
    "prevToken",
    "cursorToken",
    "continuationToken",
    "syncToken",
  ])
    it(`${n} is excluded`, () => expect(UNAMBIGUOUS_SECRET_NAME_RE.test(n)).toBe(false));
  for (const n of ["token", "accessToken", "csrf_token", "adminSecret"])
    it(`${n} is still a secret name`, () => expect(UNAMBIGUOUS_SECRET_NAME_RE.test(n)).toBe(true));

  it("does not flag a cursor compared with a literal", async () => {
    const f = await run(new RouteSecretDetector(), {
      "app/api/list/route.ts": `export async function GET(req: Request) {
  const pageToken = new URL(req.url).searchParams.get("pageToken");
  if (pageToken === "first") return Response.json([]);
  return Response.json([1]);
}`,
    });
    expect(f).toHaveLength(0);
  });
});

describe("literal Authorization credential", () => {
  const route = (exit: string): Record<string, string> => ({
    "app/api/cron/route.ts": `export async function GET(req: Request) {
  const auth = req.headers.get("authorization");
  if (auth !== "Bearer abc123def") ${exit}
  return Response.json({ ok: true });
}`,
  });
  it("flags with a 404 exit", async () => {
    const f = await run(
      new RouteSecretDetector(),
      route("return new Response(null, { status: 404 });"),
    );
    expect(f).toHaveLength(1);
    expect(f[0]!.ruleId).toBe("auth/hardcoded-route-secret");
  });
  it("flags with a throw exit", async () => {
    const f = await run(new RouteSecretDetector(), route('throw new Error("nope");'));
    expect(f).toHaveLength(1);
  });
});

describe("IDOR ownership comparison needs a denying exit", () => {
  const handler = (body: string): Record<string, string> => ({
    "app/api/orders/[id]/route.ts": `import { getServerSession } from "next-auth";
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await getServerSession();
  if (!session) return new Response(null, { status: 401 });
  const order = await db.order.findUnique({ where: { id: params.id } });
${body}
  return Response.json(order);
}`,
  });
  const d = new IdorDetector();
  it("is suppressed by an if comparison that returns 403", async () => {
    const f = await run(
      d,
      handler(
        `  if (order.userId !== session.user.id) return new Response(null, { status: 403 });`,
      ),
    );
    expect(f).toHaveLength(0);
  });
  it("is suppressed by a boolean local checked with a throw", async () => {
    const f = await run(
      d,
      handler(`  const isOwner = order.userId === session.user.id;
  if (!isOwner) throw new Error("forbidden");`),
    );
    expect(f).toHaveLength(0);
  });
  it("is not suppressed when the comparison only feeds a value", async () => {
    const f = await run(
      d,
      handler(`  const mine = order.userId === session.user.id;
  console.log(mine);`),
    );
    expect(f).toHaveLength(1);
  });
});
