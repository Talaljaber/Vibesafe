import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { MissingAuthDetector } from "../../src/detectors/missing-auth-detector.js";
import { RouteSecretDetector } from "../../src/detectors/route-secret-detector.js";

const ctx = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake",
  projectContext: {} as any,
  files: Object.keys(files),
  config: {} as any,
  readFile: async (f) => files[f] ?? "",
});
const run = (files: Record<string, string>) => new MissingAuthDetector().detect(ctx(files));

const POST_WRITE = [
  "export async function POST(req: Request) {",
  "  const body = await req.json();",
  "  await db.items.create({ data: { name: body.name } });",
  "  return Response.json({ ok: true });",
  "}",
].join("\n");

describe("MissingAuthDetector: public-by-design routes", () => {
  it("still flags an ordinary unauthenticated mutating route", async () => {
    const f = await run({ "app/api/items/route.ts": POST_WRITE });
    expect(f).toHaveLength(1);
    expect(f[0]!.ruleId).toBe("auth/missing-route-auth");
  });

  it("skips sign-in, sign-up, password reset, OAuth callbacks and health probes", async () => {
    for (const path of [
      "app/api/login/route.ts",
      "app/api/auth/signup/route.ts",
      "app/api/forgot-password/route.ts",
      "app/api/auth/callback/route.ts",
      "app/api/oauth/github/callback/route.ts",
      "app/api/health/route.ts",
      "pages/api/register.ts",
    ]) {
      expect(await run({ [path]: POST_WRITE }), path).toEqual([]);
    }
  });

  it("does not treat look-alike paths as public", async () => {
    for (const path of ["app/api/login-history/route.ts", "app/api/healthcare/route.ts"]) {
      expect(await run({ [path]: POST_WRITE }), path).toHaveLength(1);
    }
  });

  it("skips Stripe Checkout session creation and signed (non-Stripe) webhooks", async () => {
    const checkout = [
      "export async function POST(req: Request) {",
      "  const { priceId } = await req.json();",
      "  const s = await stripe.checkout.sessions.create({ line_items: [{ price: priceId, quantity: 1 }] });",
      "  return Response.json({ url: s.url });",
      "}",
    ].join("\n");
    const svix = [
      "export async function POST(req: Request) {",
      "  const payload = await req.text();",
      "  const evt = webhook.verify(payload, Object.fromEntries(req.headers));",
      "  await db.events.create({ data: evt });",
      "  return new Response(null, { status: 204 });",
      "}",
    ].join("\n");
    expect(await run({ "app/api/checkout/route.ts": checkout })).toEqual([]);
    expect(await run({ "app/api/hooks/clerk/route.ts": svix })).toEqual([]);
  });
});

describe("MissingAuthDetector: per-handler auth", () => {
  it("accepts auth wrappers and same-file auth helpers", async () => {
    const wrapped = [
      'import { withAuth } from "@/lib/auth";',
      "export const POST = withAuth(async (req: Request) => {",
      "  await db.items.create({ data: {} });",
      "  return Response.json({ ok: true });",
      "});",
    ].join("\n");
    const helper = [
      "async function requireStaffUser() {",
      "  const session = await getServerSession();",
      '  if (!session) throw new Error("unauthorized");',
      "  return session;",
      "}",
      "export async function POST(req: Request) {",
      "  await requireStaffUser();",
      "  await db.items.create({ data: {} });",
      "  return Response.json({ ok: true });",
      "}",
    ].join("\n");
    expect(await run({ "app/api/items/route.ts": wrapped })).toEqual([]);
    expect(await run({ "app/api/items/route.ts": helper })).toEqual([]);
  });

  it("reports the unauthenticated handler when another handler in the file checks auth", async () => {
    const f = await run({
      "app/api/items/route.ts": [
        "export async function GET() {",
        "  const session = await getServerSession();",
        '  if (!session) return new Response("Unauthorized", { status: 401 });',
        "  return Response.json(await db.items.findMany());",
        "}",
        "export async function DELETE(req: Request) {",
        "  await db.items.deleteMany();",
        "  return Response.json({ ok: true });",
        "}",
      ].join("\n"),
    });
    expect(f).toHaveLength(1);
    expect(f[0]!.line).toBe(6);
  });

  it("does not report a mutating handler that calls an unknown auth-like helper", async () => {
    const f = await run({
      "app/api/items/route.ts": [
        "export async function GET() {",
        "  const session = await getServerSession();",
        '  if (!session) return new Response("Unauthorized", { status: 401 });',
        "  return Response.json([]);",
        "}",
        "export async function POST(req: Request) {",
        "  const user = await getUserOrThrowFromToken(req);",
        "  await db.items.create({ data: { owner: user.id } });",
        "  return Response.json({ ok: true });",
        "}",
      ].join("\n"),
    });
    expect(f).toEqual([]);
  });
});

describe("MissingAuthDetector: request-secret checks", () => {
  const cron = (check: string) =>
    [
      "export async function POST(req: Request) {",
      check,
      "  await db.sessions.deleteMany();",
      "  return Response.json({ ok: true });",
      "}",
    ].join("\n");

  it("treats a header secret compared with an env var as authentication", async () => {
    const f = await run({
      "app/api/jobs/purge/route.ts": cron(
        '  if (req.headers.get("authorization") !== `Bearer ${process.env.CRON_SECRET}`) return new Response("Unauthorized", { status: 401 });',
      ),
    });
    expect(f).toEqual([]);
  });

  it("leaves a literal secret to auth/hardcoded-route-secret, without co-firing", async () => {
    const files = {
      "app/api/jobs/purge/route.ts": cron(
        '  if (new URL(req.url).searchParams.get("key") !== "purge-2024-zz") return new Response("no", { status: 401 });',
      ),
    };
    expect(await run(files)).toEqual([]);
    const secret = await new RouteSecretDetector().detect(ctx(files));
    expect(secret.map((x) => x.ruleId)).toEqual(["auth/hardcoded-route-secret"]);
  });

  it("does not treat an enum-style query comparison as authentication", async () => {
    const f = await run({
      "app/api/items/route.ts": cron(
        '  if (new URL(req.url).searchParams.get("mode") === "fast") console.info("fast");',
      ),
    });
    expect(f).toHaveLength(1);
  });

  it("accepts a request-secret check in an Express handler chain", async () => {
    const express = [
      'import express from "express";',
      "const app = express();",
      'app.post("/internal/reindex", (req, res) => {',
      '  if (req.headers["x-internal-token"] !== process.env.INTERNAL_TOKEN) return res.status(401).end();',
      "  reindex();",
      "  res.json({ ok: true });",
      "});",
      'app.post("/items", (req, res) => {',
      "  createItem(req.body);",
      "  res.json({ ok: true });",
      "});",
    ].join("\n");
    const f = await run({ "server.ts": express });
    expect(f.map((x) => x.ruleId)).toEqual(["auth/missing-route-auth"]);
    expect(f[0]!.line).toBe(8);
  });
});

describe("MissingAuthDetector: unauthenticated tenant reads", () => {
  const read = (pre: string, filter: string) =>
    [
      'import { adminDb } from "@/lib/server/db";',
      "export async function GET(req: Request) {",
      pre,
      '  const orgId = new URL(req.url).searchParams.get("orgId");',
      `  const { data } = await adminDb.from("orders").select("*")${filter};`,
      "  return Response.json(data);",
      "}",
    ].join("\n");

  it("flags a service-role read filtered by a tenant id from the query string", async () => {
    const f = await run({ "app/api/reports/route.ts": read("", '.eq("org_id", orgId)') });
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({
      ruleId: "auth/missing-route-auth",
      severity: "critical",
      confidence: "high",
      line: 2,
    });
  });

  it("flags a user-id read taken from the query string and keeps ids stable", async () => {
    const files = { "app/api/reports/route.ts": read("", '.eq("user_id", orgId).limit(10)') };
    const a = await run(files);
    const b = await run(files);
    expect(a).toHaveLength(1);
    expect(b.map((x) => x.id)).toEqual(a.map((x) => x.id));
  });

  it("does not flag authenticated, public-flag, non-tenant or RLS-scoped reads", async () => {
    const authed = read(
      '  const session = await getServerSession();\n  if (!session) return new Response("Unauthorized", { status: 401 });',
      '.eq("org_id", orgId)',
    );
    expect(await run({ "app/api/reports/route.ts": authed })).toEqual([]);
    expect(
      await run({
        "app/api/reports/route.ts": read("", '.eq("org_id", orgId).eq("is_published", true)'),
      }),
    ).toEqual([]);
    expect(await run({ "app/api/reports/route.ts": read("", '.eq("category", orgId)') })).toEqual(
      [],
    );
    const rls = read("", '.eq("org_id", orgId)')
      .replace('import { adminDb } from "@/lib/server/db";', "")
      .replace("adminDb", "(await createClient())");
    expect(await run({ "app/api/reports/route.ts": rls })).toEqual([]);
  });

  it("ignores commented-out queries", async () => {
    const f = await run({
      "app/api/reports/route.ts": read("", "").replace(
        "  const { data }",
        '  // const { data } = await adminDb.from("orders").select("*").eq("org_id", orgId);\n  const { data }',
      ),
    });
    expect(f).toEqual([]);
  });
});
