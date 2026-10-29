import { describe, it, expect } from "vitest";
import { CheckThenActDetector } from "../../src/detectors/check-then-act-detector.js";
import { run } from "../helpers/injection.js";

const d = new CheckThenActDetector();
const route = (body: string): Record<string, string> => ({
  "app/api/buy/route.ts": `export async function POST(req: Request) {
${body}
}`,
});

describe("check-then-act precision", () => {
  it("flags a stored record with a non-null assertion", async () => {
    const f = await run(
      d,
      route(`  const product = await prisma.product.findUnique({ where: { id: 1 } });
  if (product!.stock < 1) return new Response("no", { status: 409 });
  await prisma.product.update({ where: { id: 1 }, data: { stock: product!.stock - 1 } });
  return Response.json({ ok: true });`),
    );
    expect(f).toHaveLength(1);
  });

  it("ignores a binding that is request input", async () => {
    const f = await run(
      d,
      route(`  const body = await req.json();
  if (body.qty < 1) return new Response("bad", { status: 400 });
  await prisma.cart.update({ where: { id: 1 }, data: { qty: body.qty - 1 } });
  return Response.json({ ok: true });`),
    );
    expect(f).toHaveLength(0);
  });

  it("ignores a binding that is the caller's session", async () => {
    const f = await run(
      d,
      route(`  const session = await getServerSession();
  if (session.credits < 1) return new Response("no", { status: 402 });
  await prisma.account.update({ where: { id: 1 }, data: { credits: session.credits - 1 } });
  return Response.json({ ok: true });`),
    );
    expect(f).toHaveLength(0);
  });

  it("a lock keyword in a comment is not a lock", async () => {
    const f = await run(
      d,
      route(`  // TODO: wrap in a $transaction, FOR UPDATE
  const product = await prisma.product.findUnique({ where: { id: 1 } });
  if (product.stock < 1) return new Response("no", { status: 409 });
  await prisma.product.update({ where: { id: 1 }, data: { stock: product.stock - 1 } });
  return Response.json({ ok: true });`),
    );
    expect(f).toHaveLength(1);
  });

  it("a real transaction still suppresses", async () => {
    const f = await run(
      d,
      route(`  await prisma.$transaction(async (tx) => {
    const product = await tx.product.findUnique({ where: { id: 1 } });
    if (product.stock < 1) throw new Error("no");
    await tx.product.update({ where: { id: 1 }, data: { stock: product.stock - 1 } });
  });
  return Response.json({ ok: true });`),
    );
    expect(f).toHaveLength(0);
  });
});
