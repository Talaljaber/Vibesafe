import { describe, it, expect } from "vitest";
import { RateLimitDetector } from "../../src/detectors/rate-limit-detector";
import type { ScanContext } from "@vibesafe/shared";

describe("RateLimitDetector", () => {
  const detector = new RateLimitDetector();

  const run = (files: Record<string, string>) => {
    const context = {
      rootPath: "/fake/path",
      projectContext: {},
      files: Object.keys(files),
      config: {},
      readFile: async (file: string) => files[file] ?? "",
    } as unknown as ScanContext;
    return detector.detect(context);
  };

  describe("Next.js routes", () => {
    it("flags a login route as high", async () => {
      const f = await run({
        "app/api/auth/login/route.ts": `export async function POST(req: Request) {\n  const body = await req.json();\n  return Response.json({});\n}`,
      });
      expect(f).toHaveLength(1);
      expect(f[0]!.ruleId).toBe("security_config/missing-rate-limit");
      expect(f[0]!.category).toBe("security_config");
      expect(f[0]!.severity).toBe("high");
      expect(f[0]!.line).toBe(1);
      expect(f[0]!.id).toMatch(/^CFG-/);
    });

    it.each([
      "signup",
      "register",
      "password-reset",
      "forgot-password",
      "otp",
      "verify",
      "sign-in",
    ])("flags /%s", async (seg) => {
      const f = await run({
        [`app/api/${seg}/route.ts`]: `export async function POST() { return new Response("ok"); }`,
      });
      expect(f).toHaveLength(1);
      expect(f[0]!.severity).toBe("high");
    });

    it("flags pages/api and src/ layouts", async () => {
      const f = await run({
        "src/pages/api/login.ts": `export default function handler(req, res) { if (req.method === "POST") res.end(); }`,
      });
      expect(f).toHaveLength(1);
    });

    it("flags AI endpoints (openai) as high", async () => {
      const f = await run({
        "app/api/chat/route.ts": `import OpenAI from "openai";\nconst c = new OpenAI();\nexport async function POST() { return Response.json(await c.chat.completions.create({})); }`,
      });
      expect(f).toHaveLength(1);
      expect(f[0]!.severity).toBe("high");
      expect(f[0]!.title).toContain("AI/LLM");
      expect(f[0]!.line).toBe(3);
    });

    it("flags anthropic and ai sdk usage", async () => {
      const f = await run({
        "app/api/a/route.ts": `import Anthropic from "@anthropic-ai/sdk";\nconst c = new Anthropic();\nexport async function POST() { await c.messages.create({}); }`,
        "app/api/b/route.ts": `import { streamText } from "ai";\nexport async function POST() { return streamText({}); }`,
      });
      expect(f).toHaveLength(2);
    });

    it("does not flag a route that only imports an AI/messaging SDK", async () => {
      const f = await run({
        "app/api/a/route.ts": `import Anthropic from "@anthropic-ai/sdk";\nexport async function POST() {}`,
        "app/api/b/route.ts": `import type { Resend } from "resend";\nexport async function POST() {}`,
      });
      expect(f).toEqual([]);
    });

    it("skips webhook receivers", async () => {
      const f = await run({
        "app/api/webhooks/resend/route.ts": `import { Resend } from "resend";\nconst r = new Resend("k");\nexport async function POST() {}`,
      });
      expect(f).toEqual([]);
    });

    it.each([
      ["resend", `const x = new Resend("k");`],
      ["nodemailer", `const x = t.sendMail({});`],
      ["twilio", `const x = twilio(a, b);`],
    ])("flags %s as medium", async (lib, call) => {
      const f = await run({
        "app/api/notify/route.ts": `import x from "${lib}";\nexport async function POST() { ${call} }`,
      });
      expect(f).toHaveLength(1);
      expect(f[0]!.severity).toBe("medium");
    });

    it("reports the highest severity once when kinds combine", async () => {
      const f = await run({
        "app/api/login/route.ts": `import { Resend } from "resend";\nexport async function POST() { new Resend("k"); }`,
      });
      expect(f).toHaveLength(1);
      expect(f[0]!.severity).toBe("high");
    });

    it("ignores unrelated routes", async () => {
      const f = await run({ "app/api/todos/route.ts": `export async function POST() {}` });
      expect(f).toEqual([]);
    });

    it("ignores a sensitive path with no exported handler", async () => {
      const f = await run({ "app/api/login/route.ts": `export const dynamic = "force-dynamic";` });
      expect(f).toEqual([]);
    });

    it("ignores the word 'ai' appearing elsewhere and non-SDK imports", async () => {
      const f = await run({
        "app/api/x/route.ts": `import { ai } from "./ai";\nexport async function POST() {}`,
      });
      expect(f).toEqual([]);
    });

    it("is satisfied by an in-file limiter", async () => {
      const f = await run({
        "app/api/login/route.ts": `import { Ratelimit } from "@upstash/ratelimit";\nconst rl = new Ratelimit({});\nexport async function POST() { await rl.limit("ip"); }`,
      });
      expect(f).toEqual([]);
    });

    it.each([
      `import { rateLimiter } from "rate-limiter-flexible";`,
      `const ok = await rateLimit(req);`,
      `const r = limiter.check(req);`,
    ])("accepts signal: %s", async (line) => {
      const f = await run({ "app/api/login/route.ts": `${line}\nexport async function POST() {}` });
      expect(f).toEqual([]);
    });

    it("does not treat a commented-out limiter as protection", async () => {
      const f = await run({
        "app/api/login/route.ts": `// TODO: add rateLimit(req)\n/* import { Ratelimit } from "@upstash/ratelimit" */\nexport async function POST() {}`,
      });
      expect(f).toHaveLength(1);
    });

    it("is satisfied by a shared limiter module imported by the route", async () => {
      const f = await run({
        "lib/limit.ts": `import { Ratelimit } from "@upstash/ratelimit";\nexport const rl = new Ratelimit({});`,
        "app/api/login/route.ts": `import { rl } from "@/lib/limit";\nexport async function POST() { await rl.limit("x"); }`,
      });
      expect(f).toEqual([]);
    });

    it("a limiter module the route does not import does not protect it", async () => {
      const f = await run({
        "lib/limit.ts": `import { Ratelimit } from "@upstash/ratelimit";`,
        "app/api/login/route.ts": `export async function POST() {}`,
      });
      expect(f).toHaveLength(1);
    });

    it("is satisfied by middleware.ts using a limiter that covers /api", async () => {
      const f = await run({
        "middleware.ts": `import { Ratelimit } from "@upstash/ratelimit";\nexport function middleware() {}\nexport const config = { matcher: ["/api/:path*"] };`,
        "app/api/login/route.ts": `export async function POST() {}`,
      });
      expect(f).toEqual([]);
    });

    it("middleware whose matcher excludes /api does not protect", async () => {
      const f = await run({
        "middleware.ts": `import { Ratelimit } from "@upstash/ratelimit";\nexport const config = { matcher: ["/dashboard/:path*"] };`,
        "app/api/login/route.ts": `export async function POST() {}`,
      });
      expect(f).toHaveLength(1);
    });

    it("accepts slowDown and express-slow-down signals", async () => {
      const f = await run({
        "app/api/a/login/route.ts": `import slowDown from "express-slow-down";\nexport async function POST() {}`,
        "app/api/b/login/route.ts": `const s = slowDown({});\nexport async function POST() {}`,
      });
      expect(f).toEqual([]);
    });

    it("accepts a limiter module imported via a relative path", async () => {
      const f = await run({
        "app/api/login/limit.ts": `import { Ratelimit } from "@upstash/ratelimit";\nexport const rl = 1;`,
        "app/api/login/route.ts": `import { rl } from "./limit";\nexport async function POST() {}`,
      });
      expect(f).toEqual([]);
    });

    it("a quoted string mentioning rate-limit is not a signal", async () => {
      const f = await run({
        "app/api/login/route.ts": `const msg = "rate-limit exceeded";\nexport async function POST() {}`,
      });
      expect(f).toHaveLength(1);
    });

    it("recognises a monorepo middleware only for its own app", async () => {
      const mw = `import { Ratelimit } from "@upstash/ratelimit";\nexport function middleware() {}`;
      const f = await run({
        "apps/web/middleware.ts": mw,
        "apps/web/app/api/login/route.ts": `export async function POST() {}`,
        "apps/admin/app/api/login/route.ts": `export async function POST() {}`,
      });
      expect(f).toHaveLength(1);
      expect(f[0]!.file).toBe("apps/admin/app/api/login/route.ts");
    });

    it("redacts secrets in evidence", async () => {
      const f = await run({
        "app/api/chat/route.ts": `import OpenAI from "openai";\nexport async function POST() { new OpenAI({ apiKey: "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCD" }); }`,
      });
      expect(f).toHaveLength(1);
      expect(f[0]!.evidence).not.toContain("abcdefghijklmnopqrstuvwxyz0123456789");
    });

    it("ignores test files", async () => {
      const f = await run({
        "tests/app/api/login/route.test.ts": `export async function POST() {}`,
      });
      expect(f).toEqual([]);
    });
  });

  describe("Express routes", () => {
    it("flags an unprotected login route with its line", async () => {
      const f = await run({
        "server.js": `const express = require("express");\nconst app = express();\napp.post("/login", async (req, res) => {\n  res.json({});\n});`,
      });
      expect(f).toHaveLength(1);
      expect(f[0]!.severity).toBe("high");
      expect(f[0]!.line).toBe(3);
      expect(f[0]!.evidence).toContain('app.post("/login"');
    });

    it("flags AI and email routes", async () => {
      const f = await run({
        "routes.ts": [
          `import express from "express";`,
          `import OpenAI from "openai";`,
          `import nodemailer from "nodemailer";`,
          `const router = express.Router();`,
          `router.post("/ask", async (req, res) => { await openai.chat.completions.create({}); });`,
          `router.post("/invite", async (req, res) => { await transporter.sendMail({}); });`,
        ].join("\n"),
      });
      expect(f).toHaveLength(2);
      expect(f.map((x) => x.severity).sort()).toEqual(["high", "medium"]);
    });

    it("accepts a limiter passed as route middleware", async () => {
      const f = await run({
        "server.js": `const express = require("express");\nconst app = express();\napp.post("/login", loginLimiter, async (req, res) => {});\napp.post("/signup", async (req, res) => {});`,
      });
      expect(f).toHaveLength(1);
      expect(f[0]!.line).toBe(4);
    });

    it("accepts a global app.use(limiter) in the same file", async () => {
      const f = await run({
        "server.js": `const express = require("express");\nconst rateLimit = require("express-rate-limit");\nconst app = express();\napp.use(rateLimit({}));\napp.post("/login", (req, res) => {});`,
      });
      expect(f).toEqual([]);
    });

    it("accepts a global limiter in an app file that imports the router", async () => {
      const f = await run({
        "app.js": `const express = require("express");\nconst auth = require("./routes/auth");\nconst app = express();\napp.use(limiter);\napp.use("/auth", auth);`,
        "routes/auth.js": `const express = require("express");\nconst router = express.Router();\nrouter.post("/login", (req, res) => {});`,
      });
      expect(f).toEqual([]);
    });

    it("a limiter in an unrelated file does not exempt other files", async () => {
      const f = await run({
        "other/app.js": `const express = require("express");\nconst app = express();\napp.use(limiter);`,
        "routes/auth.js": `const express = require("express");\nconst router = express.Router();\nrouter.post("/login", (req, res) => {});`,
      });
      expect(f).toHaveLength(1);
    });

    it("a path-scoped limiter only covers matching routes", async () => {
      const f = await run({
        "server.js": `const express = require("express");\nconst app = express();\napp.use("/health", limiter);\napp.use("/auth", authLimiter);\napp.post("/login", (req, res) => {});\napp.post("/auth/login", (req, res) => {});`,
      });
      expect(f).toHaveLength(1);
      expect(f[0]!.line).toBe(5);
    });

    it("express.json() plus a limiter on /login only still flags /signup", async () => {
      const f = await run({
        "server.js": `const express = require("express");\nconst rateLimit = require("express-rate-limit");\nconst app = express();\nconst loginLimiter = rateLimit({});\napp.use(express.json());\napp.post("/login", loginLimiter, (req, res) => {});\napp.post("/signup", (req, res) => {});`,
      });
      expect(f).toHaveLength(1);
      expect(f[0]!.line).toBe(7);
    });

    it("a limiter imported but never applied is still flagged", async () => {
      const f = await run({
        "server.js": `const express = require("express");\nconst rateLimit = require("express-rate-limit");\nconst app = express();\napp.use(express.json());\napp.post("/login", (req, res) => {});`,
      });
      expect(f).toHaveLength(1);
    });

    it("accepts a shared limiter module applied with use()", async () => {
      const f = await run({
        "lib/guard.js": `const rateLimit = require("express-rate-limit");\nmodule.exports = rateLimit({});`,
        "server.js": `const express = require("express");\nconst guard = require("./lib/guard");\nconst app = express();\napp.use(guard);\napp.post("/login", (req, res) => {});`,
      });
      expect(f).toEqual([]);
    });

    it("a shared limiter module that is imported but not applied does not protect", async () => {
      const f = await run({
        "lib/guard.js": `const rateLimit = require("express-rate-limit");\nmodule.exports = rateLimit({});`,
        "server.js": `const express = require("express");\nconst guard = require("./lib/guard");\nconst app = express();\napp.use(express.json());\napp.post("/login", (req, res) => {});`,
      });
      expect(f).toHaveLength(1);
    });

    it("does not flag a GET login page but flags router.route().post()", async () => {
      const f = await run({
        "server.js": `const express = require("express");\nconst app = express();\napp.get("/login", (req, res) => res.render("login"));\napp.route("/signup").post((req, res) => {});`,
      });
      expect(f).toHaveLength(1);
      expect(f[0]!.line).toBe(4);
    });

    it("flags twilio SMS routes as medium", async () => {
      const f = await run({
        "server.js": `const express = require("express");\nconst twilio = require("twilio");\nconst app = express();\napp.post("/send", async (req, res) => { await twilio(a, b).messages.create({}); });`,
      });
      expect(f).toHaveLength(1);
      expect(f[0]!.severity).toBe("medium");
    });

    it("ignores non-sensitive routes", async () => {
      const f = await run({
        "server.js": `const express = require("express");\nconst app = express();\napp.get("/health", (req, res) => res.send("ok"));`,
      });
      expect(f).toEqual([]);
    });

    it("ignores http client calls that look like routes", async () => {
      const f = await run({
        "client.ts": `import axios from "axios";\nconst api = axios.create();\napi.post("/login", { a: 1 });`,
      });
      expect(f).toEqual([]);
    });

    it("express.json({ limit }) is a body size option, not a rate limiter", async () => {
      const f = await run({
        "server.js": `const express = require("express");\nconst app = express();\napp.use(express.json({ limit: "1mb" }));\napp.post("/login", (req, res) => {});`,
      });
      expect(f).toHaveLength(1);
    });

    it("bodyParser limit in the mounting file does not suppress a mounted router", async () => {
      const f = await run({
        "server.js": `const express = require("express");\nconst bodyParser = require("body-parser");\nconst auth = require("./routes/auth");\nconst app = express();\napp.use(bodyParser.urlencoded({ limit: "10mb" }));\napp.use(auth);`,
        "routes/auth.js": `const express = require("express");\nconst router = express.Router();\nrouter.post("/login", (req, res) => {});`,
      });
      expect(f).toHaveLength(1);
      expect(f[0]!.file).toBe("routes/auth.js");
    });

    it("a route-arg validate({ limit }) option is not a limiter", async () => {
      const f = await run({
        "server.js": `const express = require("express");\nconst app = express();\napp.post("/login", validate({ limit: 20 }), (req, res) => {});`,
      });
      expect(f).toHaveLength(1);
    });

    it("resolves relative imports against the importing directory, not any same-named file", async () => {
      const f = await run({
        "lib/utils.ts": `import { Ratelimit } from "@upstash/ratelimit";\nexport const x = 1;`,
        "app/api/login/utils.ts": `export const y = 1;`,
        "app/api/login/route.ts": `import { y } from "./utils";\nexport async function POST() { return Response.json({ y }); }`,
      });
      expect(f).toHaveLength(1);
    });

    it("still resolves a relative import to its real sibling", async () => {
      const f = await run({
        "app/api/login/limit.ts": `import { Ratelimit } from "@upstash/ratelimit";\nexport const rl = new Ratelimit({});`,
        "app/api/login/route.ts": `import { rl } from "./limit";\nexport async function POST() { return Response.json({}); }`,
      });
      expect(f).toEqual([]);
    });

    it("does not flag AI routes in a file that only imports the SDK for another route", async () => {
      const f = await run({
        "server.ts": `import express from "express";\nimport OpenAI from "openai";\nconst app = express();\napp.get("/health", (req, res) => res.send("ok"));`,
      });
      expect(f).toEqual([]);
    });
  });
});
