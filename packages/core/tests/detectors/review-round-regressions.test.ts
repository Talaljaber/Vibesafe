import { describe, it, expect } from "vitest";
import { SsrfDetector } from "../../src/detectors/ssrf-detector.js";
import { CheckThenActDetector } from "../../src/detectors/check-then-act-detector.js";
import { IdorDetector } from "../../src/detectors/idor-detector.js";
import { PathTraversalDetector } from "../../src/detectors/path-traversal-detector.js";
import { PostMessageDetector } from "../../src/detectors/postmessage-detector.js";
import { UNAMBIGUOUS_SECRET_NAME_RE } from "../../src/detectors/patterns/auth-patterns.js";
import { run } from "../helpers/injection.js";

describe("ssrf config-object url keys", () => {
  const src = (cfg: string): Record<string, string> => ({
    "app/api/p/route.ts": `import axios from "axios";
export async function GET(req: Request) {
  const src = new URL(req.url).searchParams.get("u")!;
  const u = src;
  const r = await axios(${cfg});
  return Response.json(r.data);
}`,
  });
  it.each(["{url:src}", "{ url : u }", "{ baseURL:src }"])("flags %s", async (cfg) => {
    expect(await run(new SsrfDetector(), src(cfg))).toHaveLength(1);
  });
  it("ignores a constant url", async () => {
    expect(await run(new SsrfDetector(), src('{ url: "https://api.example.com" }'))).toHaveLength(
      0,
    );
  });
});

describe("check-then-act user-record helpers", () => {
  const route = (init: string): Record<string, string> => ({
    "app/api/spend/route.ts": `export async function POST(req: Request) {
  const user = ${init};
  if (user.credits < 1) return new Response("no", { status: 402 });
  await prisma.user.update({ where: { id: user.id }, data: { credits: user.credits - 1 } });
  return Response.json({ ok: true });
}`,
  });
  it("flags a credits check on a getCurrentUser row", async () => {
    expect(await run(new CheckThenActDetector(), route("await getCurrentUser()"))).toHaveLength(1);
  });
  it("ignores a pure session reader", async () => {
    expect(await run(new CheckThenActDetector(), route("await getServerSession()"))).toHaveLength(
      0,
    );
  });
});

describe("idor deny forms", () => {
  const handler = (body: string): Record<string, string> => ({
    "app/api/orders/[id]/route.ts": `import { getServerSession } from "next-auth";
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await getServerSession();
  if (!session) return new Response(null, { status: 401 });
  const order = await db.order.findUnique({ where: { id: params.id } });
${body}
}`,
  });
  it("suppressed by a ternary owner check with an error branch", async () => {
    const f = await run(
      new IdorDetector(),
      handler(
        "  return order.userId === session.user.id ? Response.json(order) : new Response(null, { status: 403 });",
      ),
    );
    expect(f).toHaveLength(0);
  });
  it("suppressed by forbidden()", async () => {
    const f = await run(
      new IdorDetector(),
      handler(
        "  if (order.userId !== session.user.id) forbidden();\n  return Response.json(order);",
      ),
    );
    expect(f).toHaveLength(0);
  });
  it("still flags a ternary that only computes a value", async () => {
    const f = await run(
      new IdorDetector(),
      handler(
        "  const mine = order.userId === session.user.id ? 1 : 0;\n  return Response.json({ order, mine });",
      ),
    );
    expect(f).toHaveLength(1);
  });
});

describe("path traversal inline resolved guard", () => {
  const route = (guard: string): Record<string, string> => ({
    "app/api/f/route.ts": `import fs from "fs";
import path from "path";
export async function GET(req: Request) {
  const name = new URL(req.url).searchParams.get("n")!;
${guard}
  return new Response(fs.readFileSync(path.join("/srv/uploads", name)));
}`,
  });
  it("suppressed by inline resolve().startsWith(literal)", async () => {
    const f = await run(
      new PathTraversalDetector(),
      route(
        '  if (!path.resolve("/srv/uploads", name).startsWith("/srv/uploads/")) return new Response(null, { status: 400 });',
      ),
    );
    expect(f).toHaveLength(0);
  });
  it("flags an unguarded read", async () => {
    expect(await run(new PathTraversalDetector(), route(""))).toHaveLength(1);
  });
});

describe("postMessage String() comparison", () => {
  const page = (check: string): Record<string, string> => ({
    "components/F.tsx": `"use client";
import { useEffect } from "react";
export function F() {
  useEffect(() => {
    function onMessage(event: MessageEvent) {
${check}
      localStorage.setItem("x", event.data.value);
    }
    window.addEventListener("message", onMessage);
    return () => window.removeEventListener("message", onMessage);
  }, []);
  return null;
}`,
  });
  it("String(origin) compared to a literal is a check", async () => {
    const f = await run(
      new PostMessageDetector(),
      page('      if (String(event.origin) !== "https://trusted.example.com") return;'),
    );
    expect(f).toHaveLength(0);
  });
  it("String(origin) merely assigned is not a check", async () => {
    const f = await run(new PostMessageDetector(), page("      const s = String(event.origin);"));
    expect(f).toHaveLength(1);
  });
});

describe("pagination token names", () => {
  it.each(["nextPageToken", "next_page_token"])("%s is not a secret name", (n) => {
    expect(UNAMBIGUOUS_SECRET_NAME_RE.test(n)).toBe(false);
  });
  it("apiToken still is", () => {
    expect(UNAMBIGUOUS_SECRET_NAME_RE.test("apiToken")).toBe(true);
  });
});
