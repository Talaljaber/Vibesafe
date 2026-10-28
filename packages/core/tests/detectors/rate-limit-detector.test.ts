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

    it.each(["signup", "register", "password-reset", "forgot-password", "otp", "verify", "sign-in"])(
      "flags /%s",
      async (seg) => {
        const f = await run({ [`app/api/${seg}/route.ts`]: `export async function POST() { return new Response("ok"); }` });
        expect(f).toHaveLength(1);
        expect(f[0]!.severity).toBe("high");
      },
    );

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

    it("flags anthropic and ai sdk imports", async () => {
      const f = await run({
        "app/api/a/route.ts": `import Anthropic from "@anthropic-ai/sdk";\nexport async function POST() {}`,
        "app/api/b/route.ts": `import { streamText } from "ai";\nexport async function POST() {}`,
      });
      expect(f).toHaveLength(2);
    });

    it.each(["resend", "nodemailer", "twilio"])("flags %s as medium", async (lib) => {
      const f = await run({
        "app/api/notify/route.ts": `import x from "${lib}";\nexport async function POST() {}`,
      });
      expect(f).toHaveLength(1);
      expect(f[0]!.severity).toBe("medium");
    });

    it("reports the highest severity once when kinds combine", async () => {
      const f = await run({
        "app/api/login/route.ts": `import { Resend } from "resend";\nexport async function POST() {}`,
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

    it("ignores test files", async () => {
      const f = await run({ "tests/app/api/login/route.test.ts": `export async function POST() {}` });
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

    it("accepts a global limiter set up in another file", async () => {
      const f = await run({
        "app.js": `const express = require("express");\nconst app = express();\napp.use(limiter);\n`,
        "routes/auth.js": `const express = require("express");\nconst router = express.Router();\nrouter.post("/login", (req, res) => {});`,
      });
      expect(f).toEqual([]);
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

    it("does not flag AI routes in a file that only imports the SDK for another route", async () => {
      const f = await run({
        "server.ts": `import express from "express";\nimport OpenAI from "openai";\nconst app = express();\napp.get("/health", (req, res) => res.send("ok"));`,
      });
      expect(f).toEqual([]);
    });
  });
});
