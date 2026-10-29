import { describe, it, expect } from "vitest";
import type { ScanContext } from "@vibesafe/shared";
import { MissingAuthDetector } from "../../src/detectors/missing-auth-detector";
import { MissingValidationDetector } from "../../src/detectors/missing-validation-detector";
import {
  StripeWebhookDetector,
  isStripeWebhookExpressRoute,
} from "../../src/detectors/stripe-webhook-detector";
import {
  extractExpressRoutes,
  isExpressCandidateFile,
  usesExpress,
} from "../../src/detectors/utils/route-analyzer";

const ctx = (
  files: Record<string, string>,
  dependencies: Record<string, string> = { express: "^4.0.0" },
): ScanContext => ({
  rootPath: "/fake",
  projectContext: { dependencies } as never,
  files: Object.keys(files),
  config: {} as never,
  readFile: async (f) => files[f] ?? "",
});

describe("extractExpressRoutes", () => {
  it("extracts method, path, line and handler chain", () => {
    const src = `const app = express();\n\napp.post("/items", requireAuth, async (req, res) => {\n  res.json({});\n});\nrouter.get('/a/:id', h);`;
    const routes = extractExpressRoutes(src);
    expect(routes.map((r) => [r.method, r.path, r.line])).toEqual([
      ["POST", "/items", 3],
      ["GET", "/a/:id", 6],
    ]);
    expect(routes[0]!.handlerChain).toContain("requireAuth");
    expect(routes[0]!.handlerChain).toContain("res.json");
    expect(routes[0]!.handlerChain).not.toContain("router.get");
  });

  it("supports put/patch/delete/all and custom router names", () => {
    const src = `const r = express.Router();\nr.put("/x", h);\nr.patch("/x", h);\nr.delete("/x", h);\nr.all("/x", h);`;
    expect(extractExpressRoutes(src).map((r) => r.method)).toEqual([
      "PUT",
      "PATCH",
      "DELETE",
      "ALL",
    ]);
  });

  it("ignores axios/map style calls and single-argument getters", () => {
    const src = `axios.get("/x", { headers });\nmap.get("/y", 1);\napp.get("env");\nclient.post("/z", body);`;
    expect(extractExpressRoutes(src)).toHaveLength(0);
  });

  it("handles parentheses and strings inside handlers", () => {
    const src = `app.post("/x", (req, res) => { const s = ")"; res.send(s); });\napp.get("/y", h);`;
    const routes = extractExpressRoutes(src);
    expect(routes).toHaveLength(2);
    expect(routes[0]!.handlerChain).toContain("res.send(s)");
    expect(routes[0]!.handlerChain).not.toContain("/y");
  });
});

describe("helpers", () => {
  it("isExpressCandidateFile", () => {
    for (const f of ["server.js", "src/app.ts", "a/b.mjs", "a.cjs"])
      expect(isExpressCandidateFile(f)).toBe(true);
    for (const f of ["a.test.ts", "a.spec.js", "types.d.ts", "a.tsx", "x.json"])
      expect(isExpressCandidateFile(f)).toBe(false);
  });
  it("usesExpress via dependency or import", () => {
    expect(usesExpress("", { express: "4" })).toBe(true);
    expect(usesExpress(`import express from "express";`)).toBe(true);
    expect(usesExpress(`const e = require('express')`)).toBe(true);
    expect(usesExpress("app.get('/', h, i)", {})).toBe(false);
  });
});

describe("MissingAuthDetector (Express)", () => {
  const detector = new MissingAuthDetector();

  it("flags a mutating route without auth with its line", async () => {
    const findings = await detector.detect(
      ctx({
        "server.js": `const app = require("express")();\n\napp.post("/orders", (req, res) => res.send("ok"));\n`,
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe("auth/missing-route-auth");
    expect(findings[0]!.line).toBe(3);
    expect(findings[0]!.severity).toBe("high");
  });

  it("is critical on sensitive paths", async () => {
    const findings = await detector.detect(
      ctx({ "routes.ts": `router.delete("/admin/users/:id", handler);` }),
    );
    expect(findings[0]!.severity).toBe("critical");
    expect(findings[0]!.deployBlocking).toBe(true);
  });

  it.each([
    `app.post("/x", requireAuth, h);`,
    `app.post("/x", isAuthenticated, h);`,
    `app.put("/x", passport.authenticate("jwt", { session: false }), h);`,
    `app.patch("/x", verifyToken, h);`,
    `app.delete("/x", jwt({ secret }), h);`,
    `app.post("/x", auth(), h);`,
    `app.post("/x", ensureLoggedIn(), h);`,
    `app.post("/x", (req, res) => { const s = getSession(req); res.send(s); });`,
  ])("accepts auth in chain: %s", async (line) => {
    expect(await detector.detect(ctx({ "server.js": line }))).toHaveLength(0);
  });

  it("accepts a preceding app.use(auth) and router.use(auth)", async () => {
    const a = `app.use(requireAuth);\napp.post("/x", h);`;
    const b = `const router = express.Router();\nrouter.use(authMiddleware);\nrouter.delete("/x", h);`;
    const c = `app.use("/api", passport.authenticate("jwt"));\napp.post("/api/x", h);`;
    expect(await detector.detect(ctx({ "a.js": a, "b.js": b, "c.js": c }))).toHaveLength(0);
  });

  it("does not accept an auth use() that comes after the route or is scoped elsewhere", async () => {
    const after = `app.post("/x", h);\napp.use(requireAuth);`;
    const scoped = `app.use("/admin", requireAuth);\napp.post("/public/x", h);`;
    expect(await detector.detect(ctx({ "a.js": after }))).toHaveLength(1);
    expect(await detector.detect(ctx({ "b.js": scoped }))).toHaveLength(1);
  });

  it("accepts app.use(path, auth, router) mounting", async () => {
    const src = `const adminRouter = express.Router();\napp.use("/admin", requireAuth, adminRouter);\nadminRouter.post("/x", h);`;
    // use() precedes the route textually only if declared earlier; here it does.
    expect(await detector.detect(ctx({ "a.js": src }))).toHaveLength(0);
  });

  it("ignores GET routes, public auth paths and non-express files", async () => {
    expect(await detector.detect(ctx({ "a.js": `app.get("/x", h);` }))).toHaveLength(0);
    expect(
      await detector.detect(
        ctx({ "a.js": `app.post("/login", h);\napp.post("/api/register", h);` }),
      ),
    ).toHaveLength(0);
    expect(await detector.detect(ctx({ "a.js": `app.post("/x", h);` }, {}))).toHaveLength(0);
    expect(await detector.detect(ctx({ "a.test.js": `app.post("/x", h);` }))).toHaveLength(0);
  });

  it("detects express via import when the dependency is not in the context", async () => {
    const findings = await detector.detect(
      ctx(
        { "a.mjs": `import express from "express";\nconst app = express();\napp.post("/x", h);` },
        {},
      ),
    );
    expect(findings).toHaveLength(1);
  });

  it("produces stable distinct ids per route", async () => {
    const findings = await detector.detect(
      ctx({ "a.js": `app.post("/x", h);\napp.put("/y", h);` }),
    );
    expect(new Set(findings.map((f) => f.id)).size).toBe(2);
  });
});

describe("MissingValidationDetector (Express)", () => {
  const detector = new MissingValidationDetector();

  it("flags req.body use without validation, on the right line", async () => {
    const src = `app.post("/x", (req, res) => {\n  const name = req.body.name;\n  res.send(name);\n});`;
    const findings = await detector.detect(ctx({ "server.js": src }));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe("validation/missing-body-validation");
    expect(findings[0]!.line).toBe(2);
  });

  it("flags req.query/req.params only on mutating routes, as medium", async () => {
    const src = `app.get("/a", (req, res) => res.send(req.query.q));
app.get("/b/:id", (req, res) => res.send(req.params.id));
app.delete("/c/:id", (req, res) => res.send(req.params.id));`;
    const findings = await detector.detect(ctx({ "server.js": src }));
    expect(findings.map((f) => [f.line, f.severity])).toEqual([[3, "medium"]]);
  });

  it("keeps body reads high and sanitizes the route path in messages", async () => {
    const src = 'app.post("/x\u0001y", (req, res) => res.send(req.body));';
    const ctl = String.fromCharCode(1);
    const findings = await detector.detect(ctx({ "server.js": src }));
    expect(findings[0]!.severity).toBe("high");
    expect(findings[0]!.plainEnglishProblem).not.toContain(ctl);
  });

  it("does not treat validated-looking variables in the handler body as validation", async () => {
    const a = `app.post("/x", (req, res) => { const validated = false; console.log(validated); res.json(req.body); });`;
    const b = `app.post("/x", (req, res) => { validatorSetup(); res.json(req.body); });`;
    const c = `app.post("/x", validated, (req, res) => res.json(req.body));`;
    expect(await detector.detect(ctx({ "a.js": a, "b.js": b, "c.js": c }))).toHaveLength(3);
  });

  it("accepts a bare validateBody middleware identifier", async () => {
    const src = `app.post("/x", validateBody, (req, res) => res.json(req.body));`;
    expect(await detector.detect(ctx({ "a.js": src }))).toHaveLength(0);
  });

  it("reports the right line when the chain starts on a later line", async () => {
    const src = `app.post("/x",
  mw,
  (req, res) => {
    res.json(req.body);
  });`;
    const findings = await detector.detect(ctx({ "a.js": src }));
    expect(findings[0]!.line).toBe(4);
  });

  it("accepts zod parse / safeParse in the handler", async () => {
    const a = `import { z } from "zod";\napp.post("/x", (req, res) => { const d = schema.parse(req.body); res.json(d); });`;
    const b = `app.post("/x", (req, res) => { const r = schema.safeParse(req.body); res.json(r); });`;
    expect(await detector.detect(ctx({ "a.ts": a, "b.ts": b }))).toHaveLength(0);
  });

  it("accepts express-validator when imported", async () => {
    const src = `const { body, validationResult } = require("express-validator");
app.post("/x", body("email").isEmail(), (req, res) => {
  const errors = validationResult(req);
  res.json(req.body);
});`;
    expect(await detector.detect(ctx({ "a.js": src }))).toHaveLength(0);
  });

  it("does not treat body( as validation when express-validator is not imported", async () => {
    const src = `app.post("/x", body("email"), (req, res) => { res.json(req.body); });`;
    expect(await detector.detect(ctx({ "a.js": src }))).toHaveLength(1);
  });

  it("accepts celebrate and validate middleware", async () => {
    const a = `const { celebrate, Joi } = require("celebrate");\napp.post("/x", celebrate({ body: Joi.object() }), (req, res) => res.json(req.body));`;
    const b = `app.post("/x", validate(schema), (req, res) => res.json(req.body));`;
    expect(await detector.detect(ctx({ "a.js": a, "b.js": b }))).toHaveLength(0);
  });

  it("does not flag routes that never read request input or non-express files", async () => {
    expect(
      await detector.detect(ctx({ "a.js": `app.post("/x", (req, res) => res.send("ok"));` })),
    ).toHaveLength(0);
    expect(
      await detector.detect(
        ctx({ "a.js": `app.post("/x", (req, res) => res.send(req.body));` }, {}),
      ),
    ).toHaveLength(0);
  });

  it("only attributes validation to its own route", async () => {
    const src = `app.post("/a", (req, res) => { const d = schema.parse(req.body); res.json(d); });\napp.post("/b", (req, res) => res.json(req.body));`;
    const findings = await detector.detect(ctx({ "a.js": src }));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.line).toBe(2);
  });
});

describe("Express review fixes", () => {
  const auth = new MissingAuthDetector();
  const validation = new MissingValidationDetector();

  it("does not treat an axios instance named api/server as a route", async () => {
    const src = `const api = axios.create({});
api.post("/admin/users", payload);
api.delete("/items/1", cfg);
server.post("/x", body);`;
    expect(extractExpressRoutes(src)).toHaveLength(0);
    expect(await auth.detect(ctx({ "client.ts": src }))).toHaveLength(0);
    expect(await validation.detect(ctx({ "client.ts": src }))).toHaveLength(0);
  });

  it("still accepts a receiver declared from express()/Router()", () => {
    const src = `const api = express.Router();
api.post("/x", h);`;
    expect(extractExpressRoutes(src)).toHaveLength(1);
  });

  it("ignores routes in comments and strings", () => {
    const src = `// app.post("/x", h);
const s = 'app.post("/y", h)';`;
    expect(extractExpressRoutes(src)).toHaveLength(0);
  });

  it("skips app.all catch-alls (CORS, 404) but flags real all routes", async () => {
    const cors = `app.all("*", (req, res, next) => { res.header("Access-Control-Allow-Origin", "*"); next(); });`;
    const nf = `app.all("/*", (req, res) => res.status(404).send("nope"));`;
    const nf2 = `app.all("/anything", (req, res) => res.status(404).send("nope"));`;
    expect(await auth.detect(ctx({ "a.js": cors, "b.js": nf, "c.js": nf2 }))).toHaveLength(0);
    expect(
      await auth.detect(ctx({ "a.js": `app.all("/items", (req, res) => res.send("x"));` })),
    ).toHaveLength(1);
  });

  it("handles regex literals in handlers without swallowing later routes", async () => {
    const src = [
      `app.post("/a", (req, res) => { const s = req.body.x.replace(/"/g, ""); res.send(s); });`,
      `app.post("/b", (req, res) => { res.send(/['"]/.test("x")); });`,
      `app.post("/c", requireAuth, (req, res) => res.send(1));`,
      `app.post("/d", (req, res) => res.send(1));`,
    ].join("\n");
    const routes = extractExpressRoutes(src);
    expect(routes.map((r) => r.path)).toEqual(["/a", "/b", "/c", "/d"]);
    expect(routes[0]!.handlerChain).not.toContain("/b");
    const findings = await auth.detect(ctx({ "a.js": src }));
    expect(findings.map((f) => f.line)).toEqual([1, 2, 4]);
  });

  it("handles nested template literals", () => {
    const src =
      'app.post("/a", (req, res) => { res.send(`x ${`y ${req.body.a}`} )`); });\napp.get("/b", h);';
    const routes = extractExpressRoutes(src);
    expect(routes).toHaveLength(2);
    expect(routes[0]!.handlerChain).not.toContain('"/b"');
  });

  it("truncates an unbalanced chain at the next route", () => {
    const src = `app.post("/a", (req, res) => { res.send(1);
app.post("/b", requireAuth, h);`;
    const routes = extractExpressRoutes(src);
    expect(routes[0]!.handlerChain).not.toContain("requireAuth");
  });

  it.each([
    `app.post("/x", (req, res) => { const authenticated = false; res.json({ authenticated }); });`,
    `app.post("/x", (req, res) => { const isAuthed = false; res.send(isAuthed); });`,
    `app.post("/x", (req, res) => { // TODO add auth()
 res.send("ok"); });`,
    `app.post("/x", (req, res) => { validateUser(req.body); res.send("a requireAuth string"); });`,
  ])("does not treat body text as auth: %s", async (src) => {
    expect(await auth.detect(ctx({ "a.js": src }))).toHaveLength(1);
  });

  it("does not whitelist the whole /auth subtree", async () => {
    const src = [
      `/auth/change-password`,
      `/api/auth/delete-account`,
      `/auth/2fa/enable`,
      `/auth/logout`,
    ]
      .map((p) => `app.post("${p}", h);`)
      .join("\n");
    expect(await auth.detect(ctx({ "a.js": src }))).toHaveLength(4);
    const pub = `app.post("/auth/login", h);
app.post("/oauth/github/callback", h);
app.post("/forgot-password", h);`;
    expect(await auth.detect(ctx({ "a.js": pub }))).toHaveLength(0);
  });

  it("scopes use() on a segment boundary and on routers", async () => {
    const apiary = `app.use("/api", requireAuth);
app.post("/apiary/x", h);`;
    const below = `app.use("/api", requireAuth);
app.post("/api/x", h);`;
    const router = `const router = express.Router();
router.use("/admin", requireAuth);
router.post("/public", h);`;
    const routerOk = `const router = express.Router();
router.use("/admin", requireAuth);
router.post("/admin/x", h);`;
    expect(await auth.detect(ctx({ "a.js": apiary }))).toHaveLength(1);
    expect(await auth.detect(ctx({ "a.js": below }))).toHaveLength(0);
    expect(await auth.detect(ctx({ "a.js": router }))).toHaveLength(1);
    expect(await auth.detect(ctx({ "a.js": routerOk }))).toHaveLength(0);
  });

  it("accepts template-literal paths", async () => {
    const src = "app.post(`/items`, (req, res) => res.send(1));";
    expect(await auth.detect(ctx({ "a.js": src }))).toHaveLength(1);
  });

  describe("Stripe webhook routes", () => {
    const stripe = new StripeWebhookDetector();
    const signed = `const express = require("express");
const Stripe = require("stripe");
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const app = express();

app.post("/webhooks/stripe", express.raw({ type: "application/json" }), (req, res) => {
  const sig = req.headers["stripe-signature"];
  const event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  res.json({ received: event.type });
});

app.post("/orders", express.json(), (req, res) => {
  res.json({ total: req.body.total });
});`;
    const unsigned = `const express = require("express");
const Stripe = require("stripe");
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const app = express();

app.post("/webhooks/stripe", express.json(), (req, res) => {
  const event = req.body;
  if (event.type === "checkout.session.completed") grantAccess(event.data.object);
  res.json({ received: true });
});`;

    it("does not flag a signature-verified webhook for auth or validation", async () => {
      const authLines = (await auth.detect(ctx({ "server.js": signed }))).map((f) => f.line);
      const validationLines = (await validation.detect(ctx({ "server.js": signed }))).map(
        (f) => f.line,
      );
      expect(authLines).toEqual([12]);
      expect(validationLines).toEqual([13]);
      expect(await stripe.detect(ctx({ "server.js": signed }))).toHaveLength(0);
    });

    it("still flags other routes in the same file", async () => {
      const findings = await auth.detect(ctx({ "server.js": signed }));
      expect(findings).toHaveLength(1);
      expect(findings[0]!.plainEnglishProblem).toContain("POST /orders");
    });

    it("leaves an unsigned webhook to the Stripe detector, which reports it", async () => {
      expect(await auth.detect(ctx({ "server.js": unsigned }))).toHaveLength(0);
      const findings = await stripe.detect(ctx({ "server.js": unsigned }));
      expect(findings.map((f) => f.ruleId)).toEqual(["auth/stripe-webhook-unsigned"]);
    });

    it("keeps webhook-looking routes covered in files that are not Stripe webhooks", async () => {
      const src = `app.post("/webhooks/github", (req, res) => res.json(req.body));`;
      expect(await auth.detect(ctx({ "server.js": src }))).toHaveLength(1);
      expect(await validation.detect(ctx({ "server.js": src }))).toHaveLength(1);
    });

    const mixed = `const express = require("express");
const Stripe = require("stripe");
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const app = express();

app.post("/webhooks/stripe", express.raw({ type: "application/json" }), (req, res) => {
  const sig = req.headers["stripe-signature"];
  const event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  res.json({ received: event.type });
});

app.post("/webhooks/github", express.json(), (req, res) => {
  // not stripe: forwards the "stripe" style payload as is
  res.json({ action: req.body.action });
});`;

    it("flags a non-Stripe webhook route that shares a file with a Stripe webhook", async () => {
      const authFindings = await auth.detect(ctx({ "server.js": mixed }));
      expect(authFindings.map((f) => f.line)).toEqual([12]);
      expect(authFindings[0]!.plainEnglishProblem).toContain("POST /webhooks/github");
      const validationFindings = await validation.detect(ctx({ "server.js": mixed }));
      expect(validationFindings.map((f) => f.line)).toEqual([14]);
      expect(validationFindings[0]!.plainEnglishProblem).toContain("POST /webhooks/github");
    });

    it("skips a signed Stripe webhook on a generic path via chain evidence", async () => {
      const src = `const express = require("express");
const Stripe = require("stripe");
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const app = express();

app.post("/webhook", bodyParser.raw({ type: "application/json" }), (req, res) => {
  const sig = req.headers["stripe-signature"];
  const event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  res.json({ received: event.type });
});`;
      expect(await auth.detect(ctx({ "server.js": src }))).toHaveLength(0);
      expect(await validation.detect(ctx({ "server.js": src }))).toHaveLength(0);
    });

    it("skips a generic webhook path whose chain mounts express.raw before a named handler", async () => {
      const src = `const express = require("express");
const Stripe = require("stripe");
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const app = express();

function onEvent(req, res) {
  const event = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"], secret);
  res.json({ received: event.type });
}

app.post("/webhook", express.raw({ type: "application/json" }), onEvent);`;
      expect(await auth.detect(ctx({ "server.js": src }))).toHaveLength(0);
    });

    it("treats bodyParser.raw like express.raw for a generic webhook path", async () => {
      const src = `const express = require("express");
const bodyParser = require("body-parser");
const Stripe = require("stripe");
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const app = express();

function onEvent(req, res) {
  const event = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"], secret);
  res.json({ received: event.type });
}

app.post("/webhook", bodyParser.raw({ type: "application/json" }), onEvent);`;
      expect(await auth.detect(ctx({ "server.js": src }))).toHaveLength(0);
      expect(await validation.detect(ctx({ "server.js": src }))).toHaveLength(0);
      expect(await stripe.detect(ctx({ "server.js": src }))).toHaveLength(0);
    });
  });

  describe("isStripeWebhookExpressRoute", () => {
    const route = (path: string, chainCode: string) => ({ path, chainCode });

    it("requires a webhook path", () => {
      expect(isStripeWebhookExpressRoute(route("/stripe/events", "constructEvent(x)"))).toBe(false);
    });

    it("accepts Stripe evidence in the path or chain code", () => {
      expect(isStripeWebhookExpressRoute(route("/webhooks/stripe", "(req, res) => {}"))).toBe(true);
      for (const chain of [
        "(req, res) => stripe.webhooks.constructEvent(req.body, s, k)",
        'express.raw({ type: "" }), h',
        "(req, res) => verify(req.rawBody)",
        "handleStripeEvent",
      ]) {
        expect(isStripeWebhookExpressRoute(route("/webhook", chain))).toBe(true);
      }
    });

    it("rejects webhook routes without Stripe evidence", () => {
      expect(isStripeWebhookExpressRoute(route("/webhooks/github", "express.json(), h"))).toBe(
        false,
      );
    });

    it("ignores text inside blanked comments and strings of real routes", () => {
      const src = `app.post("/webhooks/github", (req, res) => {\n  // stripe constructEvent rawBody\n  res.send("stripe");\n});`;
      const [r] = extractExpressRoutes(src);
      expect(isStripeWebhookExpressRoute(r!)).toBe(false);
    });
  });

  it("leaves Next.js API route files on the non-Express branch", async () => {
    const src = `export async function POST() { return Response.json({}); }
const app = express();
app.post("/x", h);`;
    const findings = await auth.detect(ctx({ "app/api/users/route.ts": src }));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.title).toBe("Missing authentication in API Route");
  });
});
