import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { AuthOrderDetector } from "../../src/detectors/auth-order-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const ctx = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake",
  projectContext: {} as any,
  files: Object.keys(files),
  config: {} as any,
  readFile: async (f) => files[f] ?? "",
});
const run = (files: Record<string, string>) => new AuthOrderDetector().detect(ctx(files));

describe("AuthOrderDetector", () => {
  it("flags a service-role write that runs before the session check", async () => {
    const f = await run({
      "app/api/invoices/[id]/route.ts": [
        'import { adminDb } from "@/lib/server/db";',
        "export async function DELETE(_req: Request, { params }: Ctx) {",
        "  const { data: invoice } = await adminDb",
        '    .from("invoices")',
        '    .update({ status: "void" })',
        '    .eq("id", params.id)',
        "    .single();",
        "  const session = await getSession();",
        "  if (!session || session.orgId !== invoice.org_id) {",
        "    return forbidden();",
        "  }",
        "  return Response.json({ invoice });",
        "}",
      ].join("\n"),
    });
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({
      ruleId: "authorization/auth-check-after-write",
      severity: "high",
      confidence: "high",
      line: 5,
    });
    expectRubric(f);
  });

  it("flags a Prisma delete before a role check (Express) and an unknown client at medium", async () => {
    const f = await run({
      "server/app.js": [
        'const express = require("express");',
        "const app = express();",
        'app.delete("/posts/:id", async (req, res) => {',
        "  await prisma.post.delete({ where: { id: req.params.id } });",
        '  if (req.user.role !== "admin") return res.status(403).end();',
        "  res.sendStatus(204);",
        "});",
      ].join("\n"),
      "app/api/x/route.ts": [
        "export async function POST(req: Request) {",
        '  await supabase.from("posts").insert({ title: "x" });',
        "  const session = await auth();",
        '  if (!session) return new Response("Unauthorized", { status: 401 });',
        "}",
      ].join("\n"),
    });
    expect(f.map((x) => [x.file, x.line, x.confidence]).sort()).toEqual([
      ["app/api/x/route.ts", 2, "medium"],
      ["server/app.js", 4, "high"],
    ]);
    expectRubric(f);
  });

  it("does not flag handlers that check first, wrapped handlers or log writes", async () => {
    const f = await run({
      "app/api/a/route.ts": [
        "export async function POST(req: Request) {",
        "  const session = await getSession();",
        "  if (!session) return unauthorized();",
        '  await adminDb.from("orders").insert({ org_id: session.orgId });',
        '  if (session.role !== "admin") return forbidden();',
        "}",
      ].join("\n"),
      "app/api/b/route.ts": [
        "export const POST = withAuth(async (req, { session }) => {",
        '  await adminDb.from("orders").insert({ org_id: session.orgId });',
        "  if (!session) return unauthorized();",
        "});",
      ].join("\n"),
      "app/api/login/route.ts": [
        "export async function POST(req: Request) {",
        '  await adminDb.from("login_attempts").insert({ ip });',
        "  const session = await getSession();",
        "  if (!session) return unauthorized();",
        "}",
      ].join("\n"),
    });
    expect(f).toEqual([]);
  });

  it("does not flag handlers without any later check, RLS clients, comments or client files", async () => {
    const f = await run({
      "app/api/c/route.ts":
        'export async function POST() {\n  await adminDb.from("orders").insert({});\n}',
      "app/api/d/route.ts": [
        "export async function POST() {",
        "  const supabase = createServerClient(url, anon, { cookies });",
        '  await supabase.from("orders").insert({});',
        "  const session = await getSession();",
        "  if (!session) return unauthorized();",
        "}",
      ].join("\n"),
      "app/api/e/route.ts": [
        "export async function POST() {",
        '  // await adminDb.from("orders").insert({})',
        "  const session = await getSession();",
        "  if (!session) return unauthorized();",
        "}",
      ].join("\n"),
      "components/X.tsx":
        '"use client";\nexport async function POST() { await adminDb.from("o").insert({}); const s = await getSession(); if (!s) return unauthorized(); }',
    });
    expect(f).toEqual([]);
  });

  it("keeps ids stable across runs", async () => {
    const files = {
      "app/api/y/route.ts":
        'export async function PUT() {\n  await adminDb.from("o").update({ a: 1 }).eq("id", 1);\n  const s = await getSession();\n  if (!s) return unauthorized();\n}',
    };
    const a = await run(files);
    const b = await run(files);
    expect(a).toHaveLength(1);
    expect(b.map((x) => x.id)).toEqual(a.map((x) => x.id));
  });
});
