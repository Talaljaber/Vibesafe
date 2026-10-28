import { describe, it, expect } from "vitest";
import { StripeWebhookDetector } from "../../src/detectors/stripe-webhook-detector.js";
import { MissingAuthDetector } from "../../src/detectors/missing-auth-detector.js";
import { stripComments } from "../../src/detectors/utils/strip-comments.js";
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
    expect(findings[0]?.ruleId).toBe("auth/stripe-webhook-unsigned");
    expect(findings[0]?.severity).toBe("critical");
    expect(findings[0]?.deployBlocking).toBe(true);
    expect(findings[0]?.file).toBe("app/api/webhooks/stripe/route.ts");
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
    expect(findings[0]?.ruleId).toBe("auth/stripe-webhook-unsigned");
    expect(findings[0]?.severity).toBe("critical");
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
    expect(findings[0]?.ruleId).toBe("auth/stripe-webhook-unsigned");
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
          const event = constructEvent(await getRawBody(req), req.headers["stripe-signature"]);
          res.json({ ok: true });
        }
        export const config = { api: { bodyParser: false } };
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
    expect(findings[0]?.ruleId).toBe("auth/stripe-webhook-unsigned");
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
    expect(stripeFindings[0]?.ruleId).toBe("auth/stripe-webhook-unsigned");
  });

  it("accepts constructEventAsync and ignores test files", async () => {
    const context = createContext({
      "app/api/webhooks/stripe/route.ts": `
        export async function POST(req: Request) {
          const event = await stripe.webhooks.constructEventAsync(await req.text(), req.headers.get("stripe-signature")!, secret);
          return Response.json({ ok: event.id });
        }
      `,
      "app/api/webhooks/stripe/route.test.ts": `export async function POST() { const e = 1; }`,
    });
    expect(await detector.detect(context)).toHaveLength(0);
  });

  it("flags verification against a parsed body", async () => {
    const context = createContext({
      "app/api/stripe/webhook/route.ts": `
        export async function POST(req: Request) {
          const event = stripe.webhooks.constructEvent(JSON.stringify(await req.json()), sig, secret);
          return Response.json({ ok: true });
        }
      `,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe("auth/stripe-webhook-parsed-body");
    expect(findings[0]?.deployBlocking).toBe(false);
  });

  it("flags Pages Router verification using the parsed req.body", async () => {
    const context = createContext({
      "pages/api/stripe/webhook.ts": `
        export default async function handler(req: any, res: any) {
          const event = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"], secret);
          res.json({ ok: true });
        }
      `,
    });
    const findings = await detector.detect(context);
    expect(findings.map((f) => f.ruleId)).toEqual(["auth/stripe-webhook-parsed-body"]);
  });

  it("produces stable ids", async () => {
    const files = {
      "app/api/webhooks/stripe/route.ts": `export async function POST(req: Request) { return Response.json(await req.json()); }`,
    };
    const a = await detector.detect(createContext(files));
    const b = await detector.detect(createContext(files));
    expect(a[0]?.id).toBe(b[0]?.id);
    expect(a[0]?.id).toMatch(/^AUTH-/);
  });

  const ruleIds = async (files: Record<string, string>) => (await detector.detect(createContext(files))).map((f) => f.ruleId);

  it("does not claim unsigned when verification is delegated to an imported helper", async () => {
    expect(
      await ruleIds({
        "app/api/webhooks/stripe/route.ts": `
          import { verifyStripeWebhook } from "@/lib/stripe";
          export async function POST(req: Request) {
            const event = await verifyStripeWebhook(req);
            if (event.type === "checkout.session.completed") await fulfill(event);
            return Response.json({ ok: true });
          }
        `,
      }),
    ).toEqual([]);
  });

  it("still flags a route that only imports an unrelated helper", async () => {
    expect(
      await ruleIds({
        "app/api/webhooks/stripe/route.ts": `
          import { fulfill } from "@/lib/orders";
          export async function POST(req: Request) {
            const event = await req.json();
            if (event.type === "checkout.session.completed") await fulfill(event);
            return Response.json({ ok: true });
          }
        `,
      }),
    ).toEqual(["auth/stripe-webhook-unsigned"]);
  });

  it("does not treat stripe-named UI or docs files as webhook routes", async () => {
    expect(
      await ruleIds({
        "components/stripe/webhook-settings.tsx": `export default function WebhookSettings() { return <div/>; }`,
        "app/stripe-webhook-docs/page.tsx": `export default function Page() { return <p>stripe webhook docs</p>; }`,
      }),
    ).toEqual([]);
  });

  it("does not treat a webhook-endpoint management route as a receiver", async () => {
    expect(
      await ruleIds({
        "app/api/stripe/create-webhook-endpoint/route.ts": `
          import Stripe from "stripe";
          const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
          export async function POST(req: Request) {
            const ep = await stripe.webhookEndpoints.create({ url: "https://x.dev/hook", enabled_events: ["*"] });
            return Response.json(ep);
          }
        `,
      }),
    ).toEqual([]);
  });

  it("detects webhook routes that import stripe from an alias or only read the signature header", async () => {
    expect(
      await ruleIds({
        "app/api/webhook/route.ts": `
          import { stripe } from "@/lib/stripe";
          export async function POST(req: Request) {
            const event = await req.json();
            if (event.type === "checkout.session.completed") await grant(event);
            return Response.json({ ok: true });
          }
        `,
      }),
    ).toEqual(["auth/stripe-webhook-unsigned"]);
    expect(
      await ruleIds({
        "server/hooks.ts": `
          router.post("/hook", (req, res) => { const s = req.headers["stripe-signature"]; res.send(s); });
        `,
      }),
    ).toEqual(["auth/stripe-webhook-unsigned"]);
  });

  it("does not accept constructEvent mentioned only in a string or as a foreign member call", async () => {
    expect(
      await ruleIds({
        "app/api/webhooks/stripe/route.ts": `
          export async function POST(req: Request) {
            const note = "call constructEvent(body) later";
            const e = await req.json();
            return Response.json({ note, e });
          }
        `,
        "pages/api/stripe/webhook.ts": `
          export default async function handler(req: any, res: any) {
            const e = other.constructEvent(req.body);
            res.json({ e, sig: req.headers["stripe-signature"] });
          }
        `,
      }),
    ).toEqual(["auth/stripe-webhook-unsigned", "auth/stripe-webhook-unsigned"]);
  });

  it("is not fooled by a commented-out constructEvent after a JSX apostrophe", async () => {
    expect(
      await ruleIds({
        "app/api/webhooks/stripe/route.ts": `
          const msg = "Don't";
          export async function POST(req: Request) {
            // stripe.webhooks.constructEvent(body, sig, secret);
            return Response.json(await req.json());
          }
        `,
      }),
    ).toEqual(["auth/stripe-webhook-unsigned"]);
  });

  it("does not raise parsed-body when raw hints are present", async () => {
    expect(
      await ruleIds({
        "server/stripe-webhook.ts": `
          router.post("/stripe-webhook", express.raw({ type: "application/json" }), (req, res) => {
            const event = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"], secret);
            res.json({ ok: event.id });
          });
        `,
        "pages/api/stripe/webhook.ts": `
          export const config = { api: { bodyParser: false } };
          export default async function handler(req: any, res: any) {
            const event = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"], secret);
            res.json({ ok: event.id });
          }
        `,
        "app/api/stripe/webhook/route.ts": `
          export async function POST(req: Request) {
            const event = stripe.webhooks.constructEvent(await req.text(), req.headers.get("stripe-signature")!, secret);
            return Response.json({ ok: event.id });
          }
        `,
      }),
    ).toEqual([]);
  });

  it("does not let an unrelated 'raw' word suppress parsed-body", async () => {
    expect(
      await ruleIds({
        "pages/api/stripe/webhook.ts": `
          export default async function handler(req: any, res: any) {
            const rawEvent = 1;
            const event = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"], secret);
            res.json({ rawEvent, event });
          }
        `,
      }),
    ).toEqual(["auth/stripe-webhook-parsed-body"]);
  });

  it("flags constructEventAsync with a parsed body", async () => {
    expect(
      await ruleIds({
        "app/api/stripe/webhook/route.ts": `
          export async function POST(req: Request) {
            const event = await stripe.webhooks.constructEventAsync(JSON.stringify(await req.json()), sig, secret);
            return Response.json({ ok: event.id });
          }
        `,
      }),
    ).toEqual(["auth/stripe-webhook-parsed-body"]);
  });

  it("ignores Stripe-referencing helper files that are not handlers", async () => {
    expect(
      await ruleIds({
        "lib/stripe.ts": `
          import Stripe from "stripe";
          export const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
          export const EVENT = "checkout.session.completed";
        `,
      }),
    ).toEqual([]);
  });

  it("skips test files in both naming styles", async () => {
    const body = `export async function POST(req: Request) { return Response.json(await req.json()); }`;
    expect(
      await ruleIds({
        "app/api/webhooks/stripe/__tests__/route.ts": body,
        "app/api/webhooks/stripe/route.spec.ts": body,
      }),
    ).toEqual([]);
  });

  it("reports line and evidence, and ids differ per rule with the AUTH prefix", async () => {
    const unsigned = await detector.detect(
      createContext({
        "app/api/stripe/webhook/route.ts": `// header\nexport async function POST(req: Request) {\n  return Response.json(await req.json());\n}\n`,
      }),
    );
    expect(unsigned[0]?.line).toBe(2);
    expect(unsigned[0]?.evidence).toBe("export async function POST(req: Request) {");
    const parsed = await detector.detect(
      createContext({
        "app/api/stripe/webhook/route.ts": `export async function POST(req: Request) {\n  const e = stripe.webhooks.constructEvent(JSON.stringify(await req.json()), sig, secret);\n}\n`,
      }),
    );
    expect(parsed[0]?.line).toBe(2);
    expect(parsed[0]?.evidence).toContain("constructEvent(JSON.stringify");
    expect(unsigned[0]?.id).toMatch(/^AUTH-/);
    expect(parsed[0]?.id).toMatch(/^AUTH-/);
    expect(unsigned[0]?.id).not.toBe(parsed[0]?.id);
  });

  it("never prints a hardcoded whsec_ secret in evidence", async () => {
    const secret = "whsec_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4";
    const findings = await detector.detect(
      createContext({
        "app/api/stripe/webhook/route.ts": `export async function POST(req: Request) {\n  const e = stripe.webhooks.constructEvent(JSON.stringify(req.body), sig, "${secret}");\n}\n`,
        "pages/api/stripe/webhook.ts": `export default async function handler(req: any, res: any) { const s = "whsec_short1"; }`,
      }),
    );
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) expect(f.evidence).not.toMatch(/whsec_(?!\*\*\*)\w{4,}/);
    expect(JSON.stringify(findings)).not.toContain(secret);
  });

  it("MissingAuthDetector still flags non-Stripe mutating routes", async () => {
    const missingAuth = new MissingAuthDetector();
    const findings = await missingAuth.detect(
      createContext({
        "app/api/orders/route.ts": `export async function POST(req: Request) { return Response.json(await req.json()); }`,
      }),
    );
    expect(findings.map((f) => f.ruleId)).toEqual(["auth/missing-route-auth"]);
  });

  it("MissingAuthDetector is not skipped by webhook signals that only appear in comments", async () => {
    const missingAuth = new MissingAuthDetector();
    const files = {
      "app/api/orders/route.ts": `
        import Stripe from "stripe";
        // handle customer.subscription.deleted, check stripe-signature
        /* checkout.session.completed */
        export async function POST(req: Request) { return Response.json(await req.json()); }
      `,
    };
    expect((await missingAuth.detect(createContext(files))).map((f) => f.ruleId)).toEqual(["auth/missing-route-auth"]);
    expect(await detector.detect(createContext(files))).toHaveLength(0);
  });
});

describe("stripComments", () => {
  it("keeps // inside string literals such as URLs", () => {
    const src = `const u = "https://example.com/x"; // trailing`;
    const out = stripComments(src);
    expect(out.trimEnd()).toBe(`const u = "https://example.com/x";`);
    expect(out).toHaveLength(src.length);
  });

  it("handles escaped quotes", () => {
    const src = `const s = "a \\" // not a comment"; // real`;
    expect(stripComments(src)).toContain(`"a \\" // not a comment";`);
    expect(stripComments(src)).not.toContain("real");
  });

  it("keeps template literal text and nested templates, strips comments after them", () => {
    const src = "const t = `a ${ `b // c` } d`; // gone";
    const out = stripComments(src);
    expect(out).toContain("`a ${ `b // c` } d`;");
    expect(out).not.toContain("gone");
  });

  it("blanks an unterminated block comment through the end and preserves line count", () => {
    const src = "a\n/* open\nstill\nb";
    const out = stripComments(src);
    expect(out.split("\n")).toHaveLength(4);
    expect(out).not.toContain("still");
    expect(out.startsWith("a\n")).toBe(true);
  });

  it("does not let an unbalanced apostrophe swallow later lines", () => {
    const out = stripComments("<p>Don't</p>\n// secret comment\nconst x = 1;");
    expect(out).not.toContain("secret comment");
    expect(out).toContain("const x = 1;");
  });

  it("understands regex literals containing quotes or slashes", () => {
    const out = stripComments("const r = /['\"]/;\n// comment one\nconst q = /a\\/\\/b/; // comment two");
    expect(out).not.toContain("comment one");
    expect(out).not.toContain("comment two");
  });

  it("blanks string contents on request but keeps template expression code", () => {
    const out = stripComments("x('constructEvent(') + `a ${y.constructEvent(1)}`", { blankStrings: true });
    expect(out).not.toContain("'constructEvent('");
    expect(out).toContain("y.constructEvent(1)");
  });
  describe("review round 1 hardening", () => {
    const detector = new StripeWebhookDetector();
    const ctx = (files: Record<string, string>): ScanContext => ({
      rootPath: "/fake/path",
      projectContext: {} as any,
      files: Object.keys(files),
      config: {} as any,
      readFile: async (file) => files[file] || "",
    });

    it("stripComments stays fast on division-heavy input", () => {
      const src = "const x = a/b/c;\n".repeat(12_000);
      const start = Date.now();
      stripComments(src);
      stripComments("a/b/c ".repeat(30_000));
      expect(Date.now() - start).toBeLessThan(1000);
    });

    it("does not treat property access to payment_intent as a webhook signal", async () => {
      const findings = await detector.detect(
        ctx({
          "app/api/admin/refund/route.ts": `
            import Stripe from "stripe";
            export async function POST(req: Request) {
              const session = await getSession();
              await refund(session.payment_intent.id);
              console.log("payment_intent.refunded");
              return Response.json({ ok: true });
            }
          `,
        }),
      );
      expect(findings).toHaveLength(0);
    });

    it("does not let a db.webhooks table or a zod validateBody silence the unsigned finding", async () => {
      const findings = await detector.detect(
        ctx({
          "app/api/webhooks/stripe/route.ts": `
            import { validateBody } from "@/lib/validate";
            export async function POST(req: Request) {
              const event = validateBody(await req.json());
              await db.webhooks.create(event);
              return Response.json({ received: true });
            }
          `,
        }),
      );
      expect(findings.map((f) => f.ruleId)).toEqual(["auth/stripe-webhook-unsigned"]);
    });

    it("does not report a header-only helper file as a webhook route", async () => {
      const findings = await detector.detect(
        ctx({
          "lib/stripe-signature.ts": `
            export function getSignature(req: Request) {
              return req.headers.get("stripe-signature");
            }
          `,
        }),
      );
      expect(findings).toHaveLength(0);
    });
  });
});
