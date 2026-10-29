import { NextRequest, NextResponse } from "next/server";
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY ?? "");

export async function POST(req: NextRequest) {
  const { items } = await req.json();
  const session = await stripe.checkout.sessions.create({
    mode: "payment",
    line_items: items.map((item: { name: string; price: number; quantity: number }) => ({
      quantity: item.quantity,
      price_data: {
        currency: "usd",
        unit_amount: Math.round(item.price * 100),
        product_data: { name: item.name },
      },
    })),
    success_url: `${process.env.APP_URL}/thanks`,
  });
  return NextResponse.json({ url: session.url });
}
