import { NextRequest, NextResponse } from "next/server";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

export async function POST(req: NextRequest) {
  const { productId, quantity } = await req.json();
  const product = await prisma.product.findUnique({ where: { id: productId } });
  if (!product || product.stock < quantity) {
    return NextResponse.json({ error: "Out of stock" }, { status: 409 });
  }
  await prisma.product.update({
    where: { id: productId },
    data: { stock: product.stock - quantity },
  });
  const order = await prisma.order.create({
    data: { productId, quantity, totalCents: product.priceCents * quantity },
  });
  return NextResponse.json({ order }, { status: 201 });
}
