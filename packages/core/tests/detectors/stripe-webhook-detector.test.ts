import { describe, it, expect } from "vitest";
import { StripeWebhookDetector } from "../../src/detectors/stripe-webhook-detector.js";
import { MissingAuthDetector } from "../../src/detectors/missing-auth-detector.js";
import type { ScanContext } from "@vibesafe/shared";

describe("StripeWebhookDetector", () => {
  const detector = new StripeWebhookDetector();

  const createContext = (files: Record<string, string>): ScanContext => ({
    rootPath: "/fake/path",
    projectContext: {} as any,
    files: Object.keys(files),
    config: {} as any,
    readFile: async (file) => files[file] || "",
  });

  it("should flag unverified Stripe webhook route in Next.js App Router", async () => {
    const context = createContext({
      "app/api/webhooks/stripe/route.ts": `
        export async function POST(req: Request) {
          const body = await req.json();
          if (body.type === "checkout.session.completed") {
            await fulfillSubscription(body.data.object);
          }
          return Response.json({ received: true });
        }
      `,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("auth/stripe-webhook-unsigned");
    expect(findings[0].severity).toBe("critical");
    expect(findings[0].deployBlocking).toBe(true);
    expect(findings[0].file).toBe("app/api/webhooks/stripe/route.ts");
  });

  it("should flag unverified Stripe webhook in Next.js Pages Router", async () => {
    const context = createContext({
      "pages/api/stripe/webhook.js": `
        export default async function handler(req, res) {
          const sig = req.headers['stripe-signature'];
          const event = req.body;
          if (event.type === 'invoice.payment_succeeded') {
            await markInvoicePaid(event.data.object);
          }
          res.json({ received: true });
        }
      `,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("auth/stripe-webhook-unsigned");
    expect(findings[0].severity).toBe("critical");
  });

  it("should flag Express route handling Stripe events without constructEvent", async () => {
    const context = createContext({
      "server/routes/billing.ts": `
        import express from "express";
        import Stripe from "stripe";

        const router = express.Router();
        const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

        router.post("/stripe-webhook", (req, res) => {
          const sig = req.headers["stripe-signature"];
          const event = req.body;
          res.status(200).send("OK");
        });
      `,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("auth/stripe-webhook-unsigned");
  });

  it("should not flag when stripe.webhooks.constructEvent is used", async () => {
    const context = createContext({
      "app/api/webhooks/stripe/route.ts": `
        import { headers } from "next/headers";
        import { stripe } from "@/lib/stripe";

        export async function POST(req: Request) {
          const body = await req.text();
          const signature = headers().get("stripe-signature")!;

          let event;
          try {
            event = stripe.webhooks.constructEvent(
              body,
              signature,
              process.env.STRIPE_WEBHOOK_SECRET!
            );
          } catch (err: any) {
            return new Response(\`Webhook Error: \${err.message}\`, { status: 400 });
          }

          if (event.type === "checkout.session.completed") {
            await fulfillOrder(event.data.object);
          }

          return Response.json({ received: true });
        }
      `,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(0);
  });

  it("should not flag when constructEvent is called directly", async () => {
    const context = createContext({
      "src/pages/api/webhook/stripe.ts": `
        import { constructEvent } from "@/lib/stripe-helper";

        export default async function handler(req: any, res: any) {
          const event = constructEvent(req.body, req.headers["stripe-signature"]);
          res.json({ ok: true });
        }
      `,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(0);
  });

  it("should flag when constructEvent is commented out", async () => {
    const context = createContext({
      "app/api/webhooks/stripe/route.ts": `
        export async function POST(req: Request) {
          // const event = stripe.webhooks.constructEvent(body, sig, secret);
          /* event = webhooks.constructEvent(body, sig, secret); */
          const event = await req.json();
          return Response.json({ received: true });
        }
      `,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("auth/stripe-webhook-unsigned");
  });

  it("should ignore standard non-webhook routes", async () => {
    const context = createContext({
      "app/api/users/route.ts": `
        export async function GET() {
          return Response.json({ users: [] });
        }
      `,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(0);
  });

  it("should prevent MissingAuthDetector from raising conflicting session auth errors on Stripe webhooks", async () => {
    const missingAuthDetector = new MissingAuthDetector();
    const context = createContext({
      "app/api/webhooks/stripe/route.ts": `
        export async function POST(req: Request) {
          const event = await req.json();
          return Response.json({ received: true });
        }
      `,
    });
    const missingAuthFindings = await missingAuthDetector.detect(context);
    // MissingAuthDetector skips Stripe webhook routes, deferring to StripeWebhookDetector
    expect(missingAuthFindings).toHaveLength(0);

    const stripeFindings = await detector.detect(context);
    expect(stripeFindings).toHaveLength(1);
    expect(stripeFindings[0].ruleId).toBe("auth/stripe-webhook-unsigned");
  });
});
