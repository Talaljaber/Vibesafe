import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { IdorDetector } from "../../src/detectors/idor-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const ctx = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake",
  projectContext: {} as any,
  files: Object.keys(files),
  config: {} as any,
  readFile: async (f) => files[f] ?? "",
});
const run = (files: Record<string, string>) => new IdorDetector().detect(ctx(files));

const route = (body: string, sig = "_req: Request, { params }: Ctx"): string =>
  [
    'import { adminDb } from "@/lib/db/admin";',
    'import { getSession } from "@/lib/server/auth";',
    `export async function GET(${sig}) {`,
    "  const session = await getSession();",
    "  if (!session) return unauthorized();",
    body,
    "}",
  ].join("\n");

describe("IdorDetector", () => {
  it("flags a service-role lookup by route param id without org scoping", async () => {
    const f = await run({
      "app/api/orders/[id]/route.ts": route(
        '  const { data } = await adminDb\n    .from("orders")\n    .select("*")\n    .eq("id", params.id)\n    .maybeSingle();\n  return Response.json(data);',
      ),
    });
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({
      ruleId: "authorization/idor-unscoped-lookup",
      severity: "high",
      confidence: "medium",
      line: 9,
    });
    expect(f[0]!.evidence).toContain('.eq("id", params.id)');
    expectRubric(f);
  });

  it("flags Prisma deletes by a body id and Express handlers using req.user", async () => {
    const f = await run({
      "app/api/notes/route.ts": [
        'import { auth } from "@/auth";',
        "export async function DELETE(req: Request) {",
        "  const session = await auth();",
        "  if (!session) return new Response(null, { status: 401 });",
        "  const { id } = await req.json();",
        "  await prisma.note.delete({ where: { id } });",
        "  return Response.json({ ok: true });",
        "}",
      ].join("\n"),
      "server/routes.js": [
        'const express = require("express");',
        "const router = express.Router();",
        'router.get("/invoices/:id", async (req, res) => {',
        "  if (!req.user) return res.sendStatus(401);",
        "  const invoice = await prisma.invoice.findUnique({ where: { id: req.params.id } });",
        "  res.json(invoice);",
        "});",
      ].join("\n"),
    });
    expect(f.map((x) => [x.file, x.line])).toEqual([
      ["app/api/notes/route.ts", 6],
      ["server/routes.js", 5],
    ]);
    expectRubric(f);
  });

  it("does not flag queries scoped to the session's org or user", async () => {
    const f = await run({
      "app/api/orders/[id]/route.ts": route(
        '  const { data } = await adminDb.from("orders").select("*").eq("id", params.id).eq("org_id", session.orgId).single();\n  return Response.json(data);',
      ),
      "app/api/me/route.ts": route(
        '  await adminDb.from("profiles").update({ name: "x" }).eq("id", session.user.id);',
        "req: Request",
      ),
    });
    expect(f).toEqual([]);
  });

  it("does not flag when the row's owner is checked, RLS clients, or admin-only handlers", async () => {
    const f = await run({
      "app/api/a/[id]/route.ts": route(
        '  const { data } = await adminDb.from("orders").select("*").eq("id", params.id).single();\n  if (data.org_id !== session.orgId) return notFound();',
      ),
      "app/api/b/[id]/route.ts": route(
        '  const supabase = createServerClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, { cookies });\n  await supabase.from("orders").select("*").eq("id", params.id);',
      ),
      "app/api/c/[id]/route.ts": route(
        '  if (session.role !== "admin") return forbidden();\n  await adminDb.from("orders").delete().eq("id", params.id);',
      ),
      "app/api/admin/orgs/route.ts": route(
        '  await adminDb.from("organizations").update({ plan }).eq("id", params.id);',
      ),
    });
    expect(f).toEqual([]);
  });

  it("does not flag unauthenticated handlers, signed webhooks or public storefront reads", async () => {
    const f = await run({
      "app/api/public/[id]/route.ts": [
        "export async function GET(_req: Request, { params }: Ctx) {",
        '  return Response.json(await adminDb.from("orders").select("*").eq("id", params.id));',
        "}",
      ].join("\n"),
      "app/api/stripe/webhook/route.ts": [
        "export async function POST(req: Request) {",
        "  const event = stripe.webhooks.constructEvent(await req.text(), sig, secret);",
        "  const orderId = event.data.object.metadata.orderId;",
        '  await adminDb.from("orders").update({ status: "paid" }).eq("id", orderId);',
        "}",
      ].join("\n"),
      "app/api/store/[slug]/route.ts": route(
        '  await adminDb.from("stores").select("*").eq("slug", params.slug).eq("is_published", true);',
      ),
    });
    expect(f).toEqual([]);
  });

  it("ignores comments, strings, client files and non-JS files", async () => {
    const f = await run({
      "app/api/x/[id]/route.ts": route(
        '  // await adminDb.from("orders").select("*").eq("id", params.id)\n  const s = \'adminDb.from("orders").eq("id", params.id)\';',
      ),
      "components/Order.tsx": `"use client";\n${route('  await adminDb.from("orders").select().eq("id", params.id);')}`,
      "app/views.py": 'Order.objects.get(id=request.GET["id"])',
    });
    expect(f).toEqual([]);
  });

  it("reports unknown clients at medium confidence and keeps ids stable", async () => {
    const files = {
      "app/api/orders/[id]/route.ts": route(
        '  await supabase.from("orders").delete().eq("id", params.id);',
      ),
    };
    const a = await run(files);
    const b = await run(files);
    expect(a).toHaveLength(1);
    expect(a[0]!.confidence).toBe("medium");
    expect(b.map((x) => x.id)).toEqual(a.map((x) => x.id));
  });
});

describe("IdorDetector: review round 1", () => {
  it("treats <row>.customerId compared with the session as an ownership check", async () => {
    const f = await run({
      "app/api/orders/[id]/route.ts": route(
        '  const { data: order } = await adminDb.from("orders").select("*").eq("id", params.id).maybeSingle();\n  if (order.customerId !== session.customerId) return notFound();\n  return Response.json(order);',
      ),
    });
    expect(f).toEqual([]);
  });

  it("emits one summary finding after the per-file cap", async () => {
    const q = (i: number): string =>
      `  const r${i} = await adminDb.from("orders").select("*").eq("id", params.id).maybeSingle();`;
    const body = Array.from({ length: 28 }, (_, i) => q(i)).join("\n");
    const f = await run({ "app/api/orders/[id]/route.ts": route(body) });
    expect(f).toHaveLength(26);
    expect(f.filter((x) => x.title.includes("3 more"))).toHaveLength(1);
  });
});
