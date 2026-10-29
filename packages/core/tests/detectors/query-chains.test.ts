import { describe, it, expect } from "vitest";
import { createJsSource } from "../../src/detectors/utils/js-source.js";
import {
  extractQueryChains,
  isIdColumn,
  isOwnerColumn,
  requestValue,
  resolveSupabaseClient,
} from "../../src/detectors/utils/query-chains.js";
import { classifyFile } from "../../src/detectors/utils/file-kind.js";
import { handlerSpans } from "../../src/detectors/utils/js-functions.js";
import { analyzeTaint } from "../../src/detectors/utils/taint.js";

const chains = (text: string) => extractQueryChains(createJsSource(text));

describe("extractQueryChains: Supabase", () => {
  it("reads a multi-line chain with verb, table, filters and payload", () => {
    const [c] = chains(
      [
        "const { data } = await adminDb",
        '  .from("orders")',
        '  .update({ status: "paid" })',
        '  .eq("id", params.id)',
        '  .eq("org_id", session.orgId)',
        "  .select()",
        "  .single();",
      ].join("\n"),
    );
    expect(c).toMatchObject({
      orm: "supabase",
      table: "orders",
      verb: "update",
      receiver: "adminDb",
    });
    expect(c!.verbLine).toBe(3);
    expect(c!.payload?.text).toBe('{ status: "paid" }');
    expect(c!.filters.map((f) => [f.column, f.value.text, f.line])).toEqual([
      ["id", "params.id", 4],
      ["org_id", "session.orgId", 5],
    ]);
    expect(c!.opaqueFilter).toBe(false);
  });

  it("defaults to select, reads match() objects and marks or() as opaque", () => {
    const [a, b] = chains(
      'db.from("t").match({ id, org_id: orgId });\nsb.from("u").select("*").or("a.eq.1,b.eq.2");',
    );
    expect(a!.verb).toBe("select");
    expect(a!.filters.map((f) => f.column)).toEqual(["id", "org_id"]);
    expect(b!.opaqueFilter).toBe(true);
  });

  it("merges q = q.eq(...) refinements of a bound chain", () => {
    const [c] = chains(
      'let q = supabase.from("orders").select("*").eq("id", id);\nif (x) q = q.eq("org_id", orgId);\nawait q;',
    );
    expect(c!.filters.map((f) => f.column)).toEqual(["id", "org_id"]);
  });

  it("ignores storage buckets, non-literal from() and comments or strings", () => {
    expect(chains('supabase.storage.from("avatars").upload(path, file);')).toEqual([]);
    expect(
      chains(
        '// adminDb.from("orders").delete().eq("id", id)\nconst s = \'x.from("t").delete()\';',
      ),
    ).toEqual([]);
  });

  it("classifies service-role, RLS and unknown clients", () => {
    const src = createJsSource(
      [
        'import { adminDb } from "@/lib/db/admin";',
        'import { sb } from "@/lib/supabase";',
        "const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);",
        "const userClient = createServerClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, { cookies });",
      ].join("\n"),
    );
    expect(resolveSupabaseClient(src, "adminDb")).toBe("service-role");
    expect(resolveSupabaseClient(src, "admin")).toBe("service-role");
    expect(resolveSupabaseClient(src, "userClient")).toBe("rls");
    expect(resolveSupabaseClient(src, "sb")).toBe("unknown");
  });
});

describe("extractQueryChains: Prisma and Drizzle", () => {
  it("reads Prisma where/data", () => {
    const [c] = chains(
      "await prisma.user.update({ where: { id: params.id }, data: { ...body } });",
    );
    expect(c).toMatchObject({ orm: "prisma", table: "user", verb: "update", client: "direct" });
    expect(c!.filters.map((f) => f.column)).toEqual(["id"]);
    expect(c!.payload?.text).toBe("{ ...body }");
  });

  it("marks relation filters and AND/OR as opaque", () => {
    const [a, b] = chains(
      "prisma.post.findFirst({ where: { id, author: { orgId } } });\nprisma.post.findMany({ where: { OR: [{ a }, { b }] } });",
    );
    expect(a!.opaqueFilter).toBe(true);
    expect(b!.opaqueFilter).toBe(true);
  });

  it("reads Drizzle update/set/where and select/from/where", () => {
    const [u, s] = chains(
      "await db.update(users).set(body).where(eq(users.id, id));\nawait db.select().from(orders).where(eq(orders.id, orderId));",
    );
    expect(u).toMatchObject({ orm: "drizzle", verb: "update", table: "users" });
    expect(u!.payload?.text).toBe("body");
    expect(u!.filters.map((f) => f.column)).toEqual(["id"]);
    expect(s).toMatchObject({ verb: "select", table: "orders" });
  });
});

describe("column helpers", () => {
  it("recognises owner and id columns", () => {
    expect(isOwnerColumn("org_id")).toBe(true);
    expect(isOwnerColumn("orders.user_id")).toBe(true);
    expect(isOwnerColumn("userId")).toBe(true);
    expect(isOwnerColumn("id")).toBe(false);
    expect(isIdColumn("id")).toBe(true);
    expect(isIdColumn("invoiceId")).toBe(true);
    expect(isIdColumn("slug")).toBe(false);
  });
});

describe("requestValue", () => {
  const file = "app/api/orders/[id]/route.ts";
  const text = [
    "export async function GET(req: Request, { params }: Ctx) {",
    "  const session = await getSession();",
    "  const orgId = session.orgId;",
    "  const n = Number(params.id);",
    '  const row = await adminDb.from("o").select().eq("id", params.id).single();',
    '  await adminDb.from("o").select().eq("org_id", orgId).eq("id", row.data.id).eq("n", n);',
    "}",
  ].join("\n");
  const src = createJsSource(text);
  const span = handlerSpans(src, classifyFile(file, text))[0]!;
  const state = analyzeTaint(src, span);
  const [first, second] = extractQueryChains(src);

  it("treats route params as request values", () => {
    expect(requestValue(state, src, first!.filters[0]!.value)?.label).toBe("route parameters");
  });

  it("never treats identity-derived values or DB results as request values", () => {
    const [org, id, n] = second!.filters;
    expect(requestValue(state, src, org!.value)).toBeUndefined();
    expect(requestValue(state, src, id!.value)).toBeUndefined();
    expect(requestValue(state, src, n!.value)?.path).toBe("binding");
  });
});
