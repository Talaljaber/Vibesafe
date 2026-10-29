import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { MassAssignmentDetector } from "../../src/detectors/mass-assignment-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const ctx = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake",
  projectContext: {} as any,
  files: Object.keys(files),
  config: {} as any,
  readFile: async (f) => files[f] ?? "",
});
const run = (files: Record<string, string>) => new MassAssignmentDetector().detect(ctx(files));

const patch = (body: string): string =>
  [
    "export async function PATCH(req: Request, { params }: Ctx) {",
    "  const session = await getSession();",
    "  if (!session) return unauthorized();",
    body,
    "}",
  ].join("\n");

describe("MassAssignmentDetector", () => {
  it("flags a spread request body into a member update (high confidence)", async () => {
    const f = await run({
      "app/api/org/members/[userId]/route.ts": patch(
        [
          "  const body = await req.json();",
          "  const { data } = await adminDb",
          '    .from("org_members")',
          "    .update({ ...body, updated_at: new Date().toISOString() })",
          '    .eq("org_id", session.orgId)',
          '    .eq("user_id", params.userId);',
        ].join("\n"),
      ),
    });
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({
      ruleId: "authorization/mass-assignment",
      severity: "high",
      confidence: "high",
      line: 7,
    });
    expectRubric(f);
  });

  it("flags Prisma data: req.body in Express and whole bodies on other models (medium)", async () => {
    const f = await run({
      "server/app.js": [
        'const express = require("express");',
        "const app = express();",
        'app.put("/users/:id", requireAuth, async (req, res) => {',
        "  const user = await prisma.user.update({ where: { id: req.user.id }, data: req.body });",
        "  res.json(user);",
        "});",
      ].join("\n"),
      "app/api/orders/route.ts": [
        "export async function POST(req: Request) {",
        "  const order = await req.json();",
        '  await adminDb.from("orders").insert(order);',
        "}",
      ].join("\n"),
    });
    expect(f.map((x) => [x.file, x.line, x.confidence]).sort()).toEqual([
      ["app/api/orders/route.ts", 3, "medium"],
      ["server/app.js", 4, "high"],
    ]);
    expectRubric(f);
  });

  it("does not flag explicit fields, schema-parsed or picked bodies", async () => {
    const f = await run({
      "app/api/a/route.ts": patch(
        '  const body = await req.json();\n  await adminDb.from("profiles").update({ name: body.name, bio: body.bio }).eq("id", session.user.id);',
      ),
      "app/api/b/route.ts": patch(
        '  const parsed = schema.safeParse(await req.json());\n  if (!parsed.success) return bad();\n  await adminDb.from("profiles").insert({ ...parsed.data, user_id: session.user.id });',
      ),
      "app/api/c/route.ts": patch(
        '  const body = await req.json();\n  await adminDb.from("users").update(pick(body, ["name"])).eq("id", session.user.id);',
      ),
    });
    expect(f).toEqual([]);
  });

  it("does not flag absolute values from arguments, identity spreads or DB rows", async () => {
    const f = await run({
      "app/api/d/route.ts": patch(
        [
          "  const { quantity } = await req.json();",
          '  const { data: product } = await adminDb.from("products").select().eq("id", params.id).single();',
          '  await adminDb.from("products").update({ stock: product.stock - quantity }).eq("id", product.id);',
          '  await adminDb.from("audit").insert({ ...session.user, action: "x" });',
          '  await adminDb.from("archive").insert({ ...product });',
        ].join("\n"),
      ),
    });
    expect(f).toEqual([]);
  });

  it("ignores comments, strings, client components and non-JS files", async () => {
    const f = await run({
      "app/api/e/route.ts": patch(
        '  // await adminDb.from("users").update({ ...body })\n  const s = \'adminDb.from("users").update({ ...body })\';',
      ),
      "components/Form.tsx":
        '"use client";\nexport function F() { const body = {}; supabase.from("users").update({ ...body }); }',
      "app/views.py": "User.objects.filter(id=pk).update(**request.data)",
    });
    expect(f).toEqual([]);
  });

  it("keeps ids stable across runs", async () => {
    const files = {
      "app/api/u/route.ts": patch(
        "  const body = await req.json();\n  await prisma.user.update({ where: { id: session.user.id }, data: { ...body } });",
      ),
    };
    const a = await run(files);
    const b = await run(files);
    expect(a).toHaveLength(1);
    expect(b.map((x) => x.id)).toEqual(a.map((x) => x.id));
  });
});
