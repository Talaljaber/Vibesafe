import { describe, it, expect } from "vitest";
import type { ScanContext } from "@vibesafe/shared";
import { MissingAuthDetector } from "../../src/detectors/missing-auth-detector";
import { MissingValidationDetector } from "../../src/detectors/missing-validation-detector";
import {
  extractExpressRoutes,
  isExpressCandidateFile,
  usesExpress,
} from "../../src/detectors/utils/route-analyzer";

const ctx = (files: Record<string, string>, dependencies: Record<string, string> = { express: "^4.0.0" }): ScanContext => ({
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
    expect(extractExpressRoutes(src).map((r) => r.method)).toEqual(["PUT", "PATCH", "DELETE", "ALL"]);
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
    for (const f of ["server.js", "src/app.ts", "a/b.mjs", "a.cjs"]) expect(isExpressCandidateFile(f)).toBe(true);
    for (const f of ["a.test.ts", "a.spec.js", "types.d.ts", "a.tsx", "x.json"]) expect(isExpressCandidateFile(f)).toBe(false);
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
      ctx({ "server.js": `const app = require("express")();\n\napp.post("/orders", (req, res) => res.send("ok"));\n` }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe("auth/missing-route-auth");
    expect(findings[0]!.line).toBe(3);
    expect(findings[0]!.severity).toBe("high");
  });

  it("is critical on sensitive paths", async () => {
    const findings = await detector.detect(ctx({ "routes.ts": `router.delete("/admin/users/:id", handler);` }));
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
    expect(await detector.detect(ctx({ "a.js": `app.post("/login", h);\napp.post("/api/register", h);` }))).toHaveLength(0);
    expect(await detector.detect(ctx({ "a.js": `app.post("/x", h);` }, {}))).toHaveLength(0);
    expect(await detector.detect(ctx({ "a.test.js": `app.post("/x", h);` }))).toHaveLength(0);
  });

  it("detects express via import when the dependency is not in the context", async () => {
    const findings = await detector.detect(
      ctx({ "a.mjs": `import express from "express";\nconst app = express();\napp.post("/x", h);` }, {}),
    );
    expect(findings).toHaveLength(1);
  });

  it("produces stable distinct ids per route", async () => {
    const findings = await detector.detect(ctx({ "a.js": `app.post("/x", h);\napp.put("/y", h);` }));
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

  it("flags req.query and req.params", async () => {
    const src = `app.get("/a", (req, res) => res.send(req.query.q));\napp.get("/b/:id", (req, res) => res.send(req.params.id));`;
    const findings = await detector.detect(ctx({ "server.js": src }));
    expect(findings.map((f) => f.line)).toEqual([1, 2]);
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
    expect(await detector.detect(ctx({ "a.js": `app.post("/x", (req, res) => res.send("ok"));` }))).toHaveLength(0);
    expect(await detector.detect(ctx({ "a.js": `app.post("/x", (req, res) => res.send(req.body));` }, {}))).toHaveLength(0);
  });

  it("only attributes validation to its own route", async () => {
    const src = `app.post("/a", (req, res) => { const d = schema.parse(req.body); res.json(d); });\napp.post("/b", (req, res) => res.json(req.body));`;
    const findings = await detector.detect(ctx({ "a.js": src }));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.line).toBe(2);
  });
});
