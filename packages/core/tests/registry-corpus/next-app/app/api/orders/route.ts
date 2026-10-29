import { db } from "@/lib/db";

export async function POST(req: Request) {
  const body = await req.json();
  const order = await db.order.create({ data: body });
  console.log("created order", order.id);
  return Response.json(order);
}

export async function DELETE(req: Request) {
  const { id } = await req.json();
  await db.order.delete({ where: { id } });
  return Response.json({ ok: true });
}
