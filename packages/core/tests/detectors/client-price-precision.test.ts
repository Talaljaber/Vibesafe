import { describe, it, expect } from "vitest";
import { ClientTrustedPriceDetector } from "../../src/detectors/client-trusted-price-detector.js";
import { run } from "../helpers/injection.js";

const d = new ClientTrustedPriceDetector();

const checkout = (read: string, extra = ""): string => `import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_KEY!);
${extra}
export async function POST(req: Request) {
${read}
  const session = await stripe.checkout.sessions.create({
    line_items: [{ price_data: { currency: "usd", product_data: { name: "x" }, unit_amount: amount }, quantity: 1 }],
    mode: "payment",
  });
  return Response.json({ id: session.id });
}`;

describe("client-trusted price precision", () => {
  it("flags a price read with formData.get", async () => {
    const f = await run(d, {
      "app/api/checkout/route.ts": checkout(`  const formData = await req.formData();
  const amount = Number(formData.get("price"));`),
    });
    expect(f).toHaveLength(1);
  });

  it("flags a price read with searchParams.get", async () => {
    const f = await run(d, {
      "app/api/checkout/route.ts": checkout(
        `  const amount = Number(new URL(req.url).searchParams.get("amount"));`,
      ),
    });
    expect(f.length).toBeLessThanOrEqual(1);
  });

  it("does not treat a non-price formData field as a price", async () => {
    const f = await run(d, {
      "app/api/checkout/route.ts": checkout(`  const formData = await req.formData();
  const amount = PRICES[String(formData.get("plan"))];`),
    });
    expect(f).toHaveLength(0);
  });

  it("a donation word only in a comment does not suppress", async () => {
    const f = await run(d, {
      "app/api/checkout/route.ts": checkout(`  // this is not a donation flow
  const formData = await req.formData();
  const amount = Number(formData.get("price"));`),
    });
    expect(f).toHaveLength(1);
  });

  it("a donation handler is still skipped", async () => {
    const f = await run(d, {
      "app/api/checkout/route.ts": checkout(`  const formData = await req.formData();
  const amount = Number(formData.get("donation_amount"));`),
    });
    expect(f).toHaveLength(0);
  });

  it("the file path no longer suppresses", async () => {
    const f = await run(d, {
      "app/api/deposit-checkout/route.ts": checkout(`  const formData = await req.formData();
  const amount = Number(formData.get("price"));`),
    });
    expect(f).toHaveLength(1);
  });
});
