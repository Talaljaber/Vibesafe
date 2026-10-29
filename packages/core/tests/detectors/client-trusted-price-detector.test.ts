import { describe, it, expect } from "vitest";
import type { Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { ClientTrustedPriceDetector } from "../../src/detectors/client-trusted-price-detector.js";
import { MissingValidationDetector } from "../../src/detectors/missing-validation-detector.js";
import { applyPrecedence } from "../../src/scanner/precedence.js";
import { toolingPrecedence } from "../../src/detectors/groups/tooling.js";
import { applyRuleOverridesWithStats } from "../../src/scanner/rule-overrides.js";
import { expectRubric } from "../helpers/rubric.js";

const detector = new ClientTrustedPriceDetector();

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

const ROUTE = "app/api/checkout/route.ts";
const lineOf = (src: string, needle: string): number =>
  src.split("\n").findIndex((l) => l.includes(needle)) + 1;

const DIRECT = `import { NextRequest, NextResponse } from "next/server";
import { stripe } from "@/lib/stripe";

export async function POST(req: NextRequest) {
  const session = await stripe.checkout.sessions.create({
    mode: "payment",
    line_items: [
      {
        quantity: 1,
        price_data: {
          currency: "usd",
          unit_amount: Math.round(req.body.price * 100),
          product_data: { name: "Item" },
        },
      },
    ],
    success_url: "https://example.com/ok",
  });
  return NextResponse.json({ url: session.url });
}
`;

const MAPPED = `import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { stripe, toCents } from "@/lib/stripe";

const schema = z.object({
  items: z.array(z.object({ id: z.string(), name: z.string(), price: z.number(), quantity: z.number() })),
});

export async function POST(req: NextRequest) {
  const parsed = schema.safeParse(await req.json());
  if (!parsed.success) return NextResponse.json({ error: "bad" }, { status: 400 });
  const { items } = parsed.data;
  const session = await stripe.checkout.sessions.create({
    mode: "payment",
    line_items: items.map((i) => ({
      quantity: i.quantity,
      price_data: {
        currency: "usd",
        unit_amount: toCents(i.price),
        product_data: { name: i.name },
      },
    })),
  });
  return NextResponse.json({ url: session.url });
}
`;

const PAYMENT_INTENT_TOTAL = `import express from "express";
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const app = express();

app.post("/api/pay", async (req, res) => {
  const { cart } = req.body;
  const total = cart.reduce((sum, line) => sum + line.price * line.quantity, 0);
  const intent = await stripe.paymentIntents.create({
    amount: Math.round(total * 100),
    currency: "usd",
  });
  res.json({ clientSecret: intent.client_secret });
});
`;

const DESTRUCTURED = `export async function POST(request: Request) {
  const { amount, currency } = await request.json();
  const intent = await stripe.paymentIntents.create({ amount, currency });
  return Response.json({ secret: intent.client_secret });
}
`;

const PAYPAL = `export async function POST(req: Request) {
  const body = await req.json();
  const order = await paypal.orders.create({
    intent: "CAPTURE",
    purchase_units: [{ amount: { currency_code: "USD", value: String(body.total) } }],
  });
  return Response.json(order);
}
`;

describe("ClientTrustedPriceDetector", () => {
  it("flags a request price passed straight to Stripe as critical/high", async () => {
    const findings = await run({ [ROUTE]: DIRECT });
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.ruleId).toBe("validation/client-trusted-price");
    expect(f.category).toBe("validation");
    expect(f.line).toBe(lineOf(DIRECT, "unit_amount"));
    expect(f.severity).toBe("critical");
    expect(f.confidence).toBe("high");
    expect(f.deployBlocking).toBe(true);
    expect(f.evidence).toContain("unit_amount");
  });

  it("flags prices from schema-validated body items mapped into line items (high/medium)", async () => {
    const findings = await run({ [ROUTE]: MAPPED });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.line).toBe(lineOf(MAPPED, "unit_amount"));
    expect(findings[0]!.severity).toBe("high");
    expect(findings[0]!.confidence).toBe("medium");
  });

  it("follows a local total computed from client prices into a PaymentIntent (Express)", async () => {
    const findings = await run({ "server.js": PAYMENT_INTENT_TOTAL });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.line).toBe(lineOf(PAYMENT_INTENT_TOTAL, "amount: Math.round"));
    expect(findings[0]!.severity).toBe("high");
  });

  it("flags a shorthand amount destructured from the body", async () => {
    const findings = await run({ "app/api/pay/route.ts": DESTRUCTURED });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.line).toBe(3);
  });

  it("flags a PayPal purchase unit amount taken from the body", async () => {
    const findings = await run({ "app/api/paypal/route.ts": PAYPAL });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.line).toBe(lineOf(PAYPAL, "purchase_units"));
  });

  it("does not flag prices loaded from the database", async () => {
    const src = `export async function POST(req: Request) {
  const { items } = await req.json();
  const line_items = [];
  for (const item of items) {
    const product = await db.product.findUnique({ where: { id: item.productId } });
    const session = await stripe.checkout.sessions.create({
      line_items: [{ quantity: item.quantity, price_data: { currency: "usd", unit_amount: product.price } }],
    });
  }
  return Response.json({});
}
`;
    expect(await run({ [ROUTE]: src })).toEqual([]);
  });

  it("does not flag server-side lookups keyed by request data, or client quantities", async () => {
    const src = `const PLANS = { basic: { price: 900 }, pro: { price: 2900 } };
const CATALOG = [{ id: "a", price: 100 }];
export async function POST(req: Request) {
  const body = await req.json();
  const plan = PLANS[body.plan];
  const product = CATALOG.find((p) => p.id === body.productId);
  const a = await stripe.paymentIntents.create({ amount: plan.price, currency: "usd" });
  const b = await stripe.paymentIntents.create({ amount: product.price * body.quantity, currency: "usd" });
  const c = await stripe.checkout.sessions.create({
    line_items: [{ price: body.priceId, quantity: body.quantity }],
  });
  return Response.json({ a, b, c });
}
`;
    expect(await run({ [ROUTE]: src })).toEqual([]);
  });

  it("does not flag a client price that is checked against the server price first", async () => {
    const src = `export async function POST(req: Request) {
  const body = await req.json();
  const product = await db.product.findUnique({ where: { id: body.productId } });
  if (body.price !== product.price) return Response.json({ error: "price changed" }, { status: 409 });
  await stripe.paymentIntents.create({ amount: body.price, currency: "usd" });
  return Response.json({});
}
`;
    expect(await run({ [ROUTE]: src })).toEqual([]);
  });

  it("ignores comments, strings, metadata, admin price setup and donation handlers", async () => {
    const commented = `export async function POST(req: Request) {
  const body = await req.json();
  // await stripe.paymentIntents.create({ amount: body.price })
  const note = "stripe.paymentIntents.create({ amount: body.price })";
  await stripe.paymentIntents.create({ amount: 500, currency: "usd", metadata: { amount: body.price } });
  await stripe.prices.create({ unit_amount: body.price, currency: "usd", product: body.productId });
  return Response.json({ note });
}
`;
    const donation = `export async function POST(req: Request) {
  const { amount } = await req.json();
  await stripe.paymentIntents.create({ amount, currency: "usd" });
  return Response.json({});
}
`;
    expect(await run({ [ROUTE]: commented, "app/api/donations/route.ts": donation })).toEqual([]);
  });

  it("skips client code, scripts, tests (unless includeTests) and non-handler helpers", async () => {
    const helper = `export async function createIntent(body: { price: number }) {
  return stripe.paymentIntents.create({ amount: body.price, currency: "usd" });
}
`;
    const files = {
      "components/Checkout.tsx": `"use client";\n${DIRECT}`,
      "scripts/charge.ts": DIRECT,
      "tests/checkout.test.ts": DIRECT,
      "lib/payments.ts": helper,
      "migrations/x.sql": "-- unit_amount: req.body.price",
      "api/charge.py": "stripe.PaymentIntent.create(amount=request.json['price'])",
    };
    expect(await run(files)).toEqual([]);
    const withTests = await run({ "tests/app/api/checkout/route.ts": DIRECT }, true);
    expect(withTests).toHaveLength(1);
  });

  it("flags server actions that charge an argument's price", async () => {
    const src = `"use server";
export async function checkout(cart: { price: number; quantity: number }[]) {
  const session = await stripe.checkout.sessions.create({
    line_items: cart.map((line) => ({
      quantity: line.quantity,
      price_data: { currency: "usd", unit_amount: line.price },
    })),
  });
  return session.url;
}
`;
    const findings = await run({ "app/actions/checkout.ts": src });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.line).toBe(lineOf(src, "unit_amount"));
  });

  it("produces stable ids and one finding per sink line", async () => {
    const a = await run({ [ROUTE]: DIRECT, "app/api/pay/route.ts": DESTRUCTURED });
    const b = await run({ [ROUTE]: DIRECT, "app/api/pay/route.ts": DESTRUCTURED });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
    expect(new Set(a.map((f) => `${f.file}:${f.line}`)).size).toBe(a.length);
  });

  it("never throws on unbalanced input", async () => {
    const broken = `export async function POST(req: Request) {
  await stripe.paymentIntents.create({ amount: req.body.price, currency: "usd"
`;
    const findings = await run({ [ROUTE]: broken });
    for (const f of findings) expect(f.severity).not.toBe("critical");
  });
});

describe("validation/client-trusted-price precedence", () => {
  const ROUTE_WITHOUT_SCHEMA = `export async function POST(req: Request) {
  const body = await req.json();
  const session = await stripe.checkout.sessions.create({
    line_items: [{ quantity: 1, price_data: { currency: "usd", unit_amount: body.price } }],
  });
  return Response.json({ url: session.url });
}
`;

  async function both(): Promise<Finding[]> {
    const ctx = createContext({ [ROUTE]: ROUTE_WITHOUT_SCHEMA });
    const price = await detector.detect(ctx);
    // The generic finding gains its handler's endLine in the injection stream; give it one
    // here so the enclosing scope can be exercised.
    const generic = (await new MissingValidationDetector().detect(ctx)).map((f) => ({
      ...f,
      endLine: 7,
    }));
    expect(price).toHaveLength(1);
    expect(generic).toHaveLength(1);
    return [...generic, ...price];
  }

  it("hides the generic missing-body-validation finding of the same handler", async () => {
    const res = applyPrecedence(await both(), toolingPrecedence);
    expect(res.findings.map((f) => f.ruleId)).toEqual(["validation/client-trusted-price"]);
    expect(res.suppressed).toBe(1);
  });

  it("brings the generic finding back when the winner is turned off", async () => {
    const { findings } = applyRuleOverridesWithStats(await both(), {
      "validation/client-trusted-price": "off",
    });
    const res = applyPrecedence(findings, toolingPrecedence);
    expect(res.findings.map((f) => f.ruleId)).toEqual(["validation/missing-body-validation"]);
  });

  it("the winner is at least as severe as the loser", async () => {
    const [generic, price] = await both();
    const rank = { critical: 4, high: 3, medium: 2, low: 1 } as const;
    expect(rank[price!.severity]).toBeGreaterThanOrEqual(rank[generic!.severity]);
  });
});
