import { describe, it, expect } from "vitest";
import type { Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { CheckThenActDetector } from "../../src/detectors/check-then-act-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const detector = new CheckThenActDetector();

const createContext = (files: Record<string, string>, includeTests = false): ScanContext => ({
  rootPath: "/fake/path",
  projectContext: {} as ScanContext["projectContext"],
  files: Object.keys(files),
  config: { rootPath: "/fake/path", includeTests },
  readFile: async (file) => files[file] ?? "",
});

async function run(files: Record<string, string>, includeTests = false): Promise<Finding[]> {
  const findings = await detector.detect(createContext(files, includeTests));
  expectRubric(findings);
  return findings;
}

const lineOf = (src: string, needle: string): number =>
  src.split("\n").findIndex((l) => l.includes(needle)) + 1;

const SUPABASE = `export async function POST(req: Request) {
  const { items } = await req.json();
  for (const item of items) {
    const { data: product } = await supabase
      .from("products")
      .select("id, stock")
      .eq("id", item.productId)
      .single();
    if (!product) return Response.json({ error: "not found" }, { status: 404 });
    if (product.stock < item.quantity) {
      return Response.json({ error: "out of stock" }, { status: 409 });
    }
    await supabase
      .from("products")
      .update({ stock: product.stock - item.quantity })
      .eq("id", product.id);
  }
  return Response.json({ ok: true });
}
`;

const PRISMA_DERIVED = `export async function spendCredits(userId: string, cost: number) {
  const account = await prisma.account.findUnique({ where: { userId } });
  if (!account || account.credits < cost) throw new Error("insufficient credits");
  const remaining = account.credits - cost;
  await prisma.account.update({ where: { userId }, data: { credits: remaining } });
}
`;

const MONGOOSE = `router.post("/withdraw", async (req, res) => {
  const wallet = await Wallet.findById(req.user.walletId);
  if (wallet.balance < req.body.amount) return res.status(400).json({ error: "low balance" });
  wallet.balance -= req.body.amount;
  await wallet.save();
  res.json({ ok: true });
});
`;

const SQL = `export async function POST(req: Request) {
  const { id, qty } = await req.json();
  const { rows: [ticket] } = await pool.query("SELECT * FROM tickets WHERE id = $1", [id]);
  if (ticket.remaining >= qty) {
    await sql\`UPDATE tickets SET remaining = \${ticket.remaining - qty} WHERE id = \${id}\`;
  }
  return Response.json({ ok: true });
}
`;

describe("CheckThenActDetector", () => {
  it("flags a Supabase stock decrement written as an absolute value after a check", async () => {
    const findings = await run({ "app/api/orders/route.ts": SUPABASE });
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.ruleId).toBe("validation/check-then-act-race");
    expect(f.category).toBe("validation");
    expect(f.severity).toBe("medium");
    expect(f.confidence).toBe("medium");
    expect(f.line).toBe(lineOf(SUPABASE, "stock: product.stock"));
  });

  it("flags a Prisma update through a derived local", async () => {
    const findings = await run({ "lib/server/credits.ts": PRISMA_DERIVED });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.line).toBe(lineOf(PRISMA_DERIVED, "data: { credits: remaining }"));
  });

  it("flags a Mongoose read-modify-save after a check", async () => {
    const findings = await run({ "server/routes/wallet.js": MONGOOSE });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.line).toBe(lineOf(MONGOOSE, "wallet.balance -="));
  });

  it("flags an UPDATE template that writes the precomputed value", async () => {
    const findings = await run({ "app/api/tickets/route.ts": SQL });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.line).toBe(lineOf(SQL, "UPDATE tickets"));
  });

  it("does not flag atomic updates, transactions, locks or compare-and-swap", async () => {
    const atomic = `export async function POST(req: Request) {
  const { id, qty } = await req.json();
  const product = await prisma.product.findUnique({ where: { id } });
  if (product.stock < qty) return Response.json({}, { status: 409 });
  await prisma.product.update({ where: { id }, data: { stock: { decrement: qty } } });
  await sql\`UPDATE products SET stock = stock - \${qty} WHERE id = \${id} AND stock >= \${qty}\`;
  return Response.json({});
}
`;
    const transaction = `export async function POST(req: Request) {
  const { id, qty } = await req.json();
  await prisma.$transaction(async (tx) => {
    const product = await tx.product.findUnique({ where: { id } });
    if (product.stock < qty) throw new Error("out of stock");
    await tx.product.update({ where: { id }, data: { stock: product.stock - qty } });
  });
  return Response.json({});
}
`;
    const cas = `export async function POST(req: Request) {
  const { id, qty } = await req.json();
  const { data: product } = await supabase.from("products").select().eq("id", id).single();
  if (product.stock < qty) return Response.json({}, { status: 409 });
  const { count } = await supabase
    .from("products")
    .update({ stock: product.stock - qty })
    .eq("id", id)
    .eq("stock", product.stock);
  return Response.json({ count });
}
`;
    const forUpdate = `export async function POST(req: Request) {
  const { id, qty } = await req.json();
  const { rows: [p] } = await client.query("SELECT * FROM products WHERE id = $1 FOR UPDATE", [id]);
  if (p.stock < qty) return Response.json({}, { status: 409 });
  await client.query("UPDATE products SET stock = $1 WHERE id = $2", [p.stock - qty, id]);
  return Response.json({});
}
`;
    expect(
      await run({
        "app/api/a/route.ts": atomic,
        "app/api/b/route.ts": transaction,
        "app/api/c/route.ts": cas,
        "app/api/d/route.ts": forUpdate,
      }),
    ).toEqual([]);
  });

  it("requires a read, a check on the same field and an update call", async () => {
    const noCheck = `export async function POST(req: Request) {
  const { id } = await req.json();
  const post = await prisma.post.findUnique({ where: { id } });
  await prisma.post.update({ where: { id }, data: { views: post.views + 1 } });
  return Response.json({});
}
`;
    const otherField = `export async function POST(req: Request) {
  const { id, qty } = await req.json();
  const product = await prisma.product.findUnique({ where: { id } });
  if (!product.active) return Response.json({}, { status: 404 });
  await prisma.product.update({ where: { id }, data: { stock: product.stock - qty } });
  return Response.json({});
}
`;
    const notRead = `export function POST(cart: { total: number }, fee: number) {
  if (cart.total < 10) return null;
  return buildOrder({ total: cart.total + fee });
}
`;
    const local = `export async function GET() {
  const stats = await loadStats();
  if (stats.count > 10) return Response.json({ total: stats.count - 10 });
  return Response.json({});
}
`;
    expect(
      await run({
        "app/api/a/route.ts": noCheck,
        "app/api/b/route.ts": otherField,
        "app/api/c/route.ts": notRead,
        "app/api/d/route.ts": local,
      }),
    ).toEqual([]);
  });

  it("ignores comments, strings, client files, scripts and tests by default", async () => {
    const commented = `export async function POST(req: Request) {
  const product = await db.find();
  if (product.stock < 1) return Response.json({});
  // await db.update({ stock: product.stock - 1 });
  const s = "db.update({ stock: product.stock - 1 })";
  return Response.json({ s });
}
`;
    expect(
      await run({
        "app/api/a/route.ts": commented,
        "components/Cart.tsx": `"use client";\n${SUPABASE}`,
        "scripts/restock.ts": SUPABASE,
        "tests/orders.test.ts": SUPABASE,
        "db/migrate.sql": "UPDATE products SET stock = stock - 1;",
        "app/views.py": "product.stock = product.stock - 1\nproduct.save()",
      }),
    ).toEqual([]);
    expect(await run({ "tests/orders.test.ts": SUPABASE }, true)).toHaveLength(1);
  });

  it("produces stable ids", async () => {
    const files = { "app/api/orders/route.ts": SUPABASE, "server/routes/wallet.js": MONGOOSE };
    const a = await run(files);
    const b = await run(files);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
    expect(a).toHaveLength(2);
  });

  it("never throws on unbalanced input", async () => {
    const broken = `export async function POST(req) {
  const p = await db.find();
  if (p.stock < 1) {
    await db.update({ stock: p.stock - 1 }
`;
    await expect(run({ "app/api/x/route.ts": broken })).resolves.toBeDefined();
  });
});
