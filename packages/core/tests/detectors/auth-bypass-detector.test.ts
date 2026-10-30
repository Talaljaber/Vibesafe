import { describe, it, expect } from "vitest";
import os from "node:os";
import path from "node:path";
import { promises as fs } from "node:fs";
import type { ScanContext, Severity } from "@talaljaber/vibesafe-shared";
import { AuthBypassDetector } from "../../src/detectors/auth-bypass-detector.js";
import { JwtMisuseDetector } from "../../src/detectors/jwt-misuse-detector.js";
import { authzPrecedence } from "../../src/detectors/groups/authz.js";
import { DetectorRegistry } from "../../src/scanner/detector-registry.js";
import { ScannerPipeline } from "../../src/scanner/pipeline.js";
import { expectRubric } from "../helpers/rubric.js";

const ctx = (files: Record<string, string>, only?: string): ScanContext => ({
  rootPath: "/fake",
  projectContext: {} as any,
  files: only ? [only] : Object.keys(files),
  config: {} as any,
  readFile: async (f) => files[f] ?? "",
});
const run = (files: Record<string, string>, only?: string) =>
  new AuthBypassDetector().detect(ctx(files, only));
const rule = <T extends { ruleId: string }>(list: T[], r: string): T[] =>
  list.filter((f) => f.ruleId === r);

const JWT = "auth/jwt-decode-without-verify";
const ENV = "auth/auth-disabled-outside-production";
const OPEN = "auth/secret-check-fails-open";

describe("auth/jwt-decode-without-verify", () => {
  it("flags a share token decoded from the query string and compared to the record", async () => {
    const files = {
      "app/api/docs/[id]/route.ts": [
        'import jwt from "jsonwebtoken";',
        "export async function GET(req: Request) {",
        "  const doc = await db.doc.find();",
        '  const share = new URL(req.url).searchParams.get("share");',
        "  if (share) {",
        "    const claims = jwt.decode(share) as { docId?: string } | null;",
        "    if (!claims || claims.docId !== doc.id) throw new Error('bad');",
        "    return Response.redirect(url);",
        "  }",
        "}",
      ].join("\n"),
    };
    const f = rule(await run(files), JWT);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "high", confidence: "high", line: 6 });
    expectRubric(f);
    expect(rule(await run(files), JWT).map((x) => x.id)).toEqual(f.map((x) => x.id));
  });

  it("flags jose decodeJwt of a bearer header used in a lookup", async () => {
    const f = rule(
      await run({
        "server/api.ts": [
          'import { decodeJwt } from "jose";',
          "export async function handler(req: Request) {",
          '  const bearer = req.headers.get("authorization")?.split(" ")[1] ?? "";',
          "  const payload = decodeJwt(bearer);",
          "  return db.user.findUnique({ where: { id: payload.sub } });",
          "}",
        ].join("\n"),
      }),
      JWT,
    );
    expect(f).toHaveLength(1);
    expect(f[0]!.line).toBe(4);
    expectRubric(f);
  });

  it("flags a manual base64 payload parse from a cookie", async () => {
    const f = rule(
      await run({
        "middleware.ts": [
          'import { NextResponse } from "next/server";',
          "export function middleware(req: any) {",
          '  const t = req.cookies.get("session")?.value ?? "";',
          '  const claims = JSON.parse(atob(t.split(".")[1]));',
          '  if (claims.role !== "admin") return NextResponse.redirect(new URL("/login", req.url));',
          "  return NextResponse.next();",
          "}",
        ].join("\n"),
      }),
      JWT,
    );
    expect(f).toHaveLength(1);
  });

  it("is silent when the same token is verified in the file", async () => {
    const f = await run({
      "app/api/x/route.ts": [
        'import jwt from "jsonwebtoken";',
        "export async function GET(req: Request) {",
        '  const token = req.headers.get("authorization") ?? "";',
        "  const header = jwt.decode(token, { complete: true });",
        "  const key = await keyFor(header?.header.kid);",
        "  const claims = jwt.verify(token, key) as any;",
        "  if (claims.role !== 'admin') throw new Error('no');",
        "}",
      ].join("\n"),
    });
    expect(rule(f, JWT)).toHaveLength(0);
  });

  it("is silent when the decoded value is only logged or returned", async () => {
    const f = await run({
      "app/api/debug/route.ts": [
        'import jwt from "jsonwebtoken";',
        "export async function GET(req: Request) {",
        '  const token = req.headers.get("authorization") ?? "";',
        "  const claims = jwt.decode(token);",
        "  console.log(claims);",
        "  return Response.json({ claims });",
        "}",
      ].join("\n"),
    });
    expect(rule(f, JWT)).toHaveLength(0);
  });

  it("is silent in client files", async () => {
    const f = await run({
      "components/Header.tsx": [
        '"use client";',
        'import { jwtDecode } from "jwt-decode";',
        "export function Header() {",
        '  const token = localStorage.getItem("token") ?? "";',
        "  const claims = jwtDecode<{ exp: number }>(token);",
        "  if (claims.exp < Date.now() / 1000) throw new Error('expired');",
        "  return null;",
        "}",
      ].join("\n"),
    });
    expect(rule(f, JWT)).toHaveLength(0);
  });

  it("is silent when the token is not request data and claims are not a gate", async () => {
    const f = await run({
      "lib/jobs.ts": [
        'import jwt from "jsonwebtoken";',
        "export function expiry(stored: string) {",
        "  const c = jwt.decode(stored) as any;",
        "  return c?.exp;",
        "}",
      ].join("\n"),
    });
    expect(rule(f, JWT)).toHaveLength(0);
  });

  it("is hidden by crypto/jwt-decode-for-auth on the same line, and returns when that rule is off", async () => {
    const files: Record<string, string> = {
      "app/api/docs/route.ts": [
        'import jwt from "jsonwebtoken";',
        "export async function GET(req: Request) {",
        '  const share = new URL(req.url).searchParams.get("share");',
        "  const claims = jwt.decode(share) as any;",
        "  if (claims.role !== 'admin') throw new Error('bad');",
        "  return Response.json({});",
        "}",
      ].join("\n"),
    };
    const scan = async (overrides?: Record<string, "off" | Severity>) => {
      const root = await fs.mkdtemp(path.join(os.tmpdir(), "vibesafe-ab-"));
      try {
        for (const [rel, content] of Object.entries(files)) {
          const abs = path.join(root, rel);
          await fs.mkdir(path.dirname(abs), { recursive: true });
          await fs.writeFile(abs, content);
        }
        const registry = new DetectorRegistry();
        registry.register(new JwtMisuseDetector());
        registry.register(new AuthBypassDetector());
        registry.registerPrecedence(authzPrecedence);
        return (
          await new ScannerPipeline(registry).scan({
            rootPath: root,
            useConfigFile: false,
            ...(overrides ? { ruleOverrides: overrides } : {}),
          })
        ).findings.map((f) => f.ruleId);
      } finally {
        await fs.rm(root, { recursive: true, force: true });
      }
    };
    const both = await scan();
    expect(both).toContain("crypto/jwt-decode-for-auth");
    expect(both).not.toContain(JWT);
    const off = await scan({ "crypto/jwt-decode-for-auth": "off" });
    expect(off).not.toContain("crypto/jwt-decode-for-auth");
    expect(off).toContain(JWT);
  });
});

describe("auth/auth-disabled-outside-production", () => {
  it("flags an Express auth middleware that returns next() outside production", async () => {
    const files = {
      "src/middleware/auth.ts": [
        "export function internalAuth(req: any, res: any, next: any) {",
        "  if (config.nodeEnv !== 'production') {",
        "    return next();",
        "  }",
        "  const token = req.headers['x-token'];",
        "  if (!token || token !== config.token) {",
        "    return res.status(401).json({ error: 'unauthorized' });",
        "  }",
        "  next();",
        "}",
      ].join("\n"),
    };
    const f = rule(await run(files), ENV);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "high", confidence: "medium", line: 2 });
    expectRubric(f);
  });

  it("flags a Next middleware with isDev and an env flag as medium", async () => {
    const f = rule(
      await run({
        "middleware.ts": [
          'import { NextResponse } from "next/server";',
          "export function middleware(req: any) {",
          "  if (process.env.NODE_ENV === 'development') return NextResponse.next();",
          "  if (process.env.SKIP_AUTH) return NextResponse.next();",
          "  if (!req.cookies.get('session')) return NextResponse.redirect(new URL('/login', req.url));",
          "  return NextResponse.next();",
          "}",
        ].join("\n"),
      }),
      ENV,
    );
    expect(f.map((x) => `${x.line}:${x.severity}:${x.confidence}`)).toEqual([
      "3:high:medium",
      "4:medium:medium",
    ]);
    expectRubric(f);
  });

  it("is silent when the env check denies", async () => {
    const f = await run({
      "src/middleware/auth.ts": [
        "export function requireAuth(req: any, res: any, next: any) {",
        "  if (process.env.NODE_ENV !== 'production') return res.status(401).end();",
        "  if (!req.user) return res.status(401).end();",
        "  next();",
        "}",
      ].join("\n"),
    });
    expect(rule(f, ENV)).toHaveLength(0);
  });

  it("is silent for === 'test' bypasses and env checks outside auth functions", async () => {
    const f = await run({
      "src/middleware/auth.ts": [
        "export function requireAuth(req: any, res: any, next: any) {",
        "  if (process.env.NODE_ENV === 'test') return next();",
        "  if (!req.user) return res.status(401).end();",
        "  next();",
        "}",
      ].join("\n"),
      "src/middleware/logging.ts": [
        "export function requestLogger(req: any, res: any, next: any) {",
        "  if (process.env.NODE_ENV !== 'production') { console.log(req.url); return next(); }",
        "  res.status(401);",
        "  next();",
        "}",
      ].join("\n"),
    });
    expect(rule(f, ENV)).toHaveLength(0);
  });

  it("is silent when the bypass also needs a secret header", async () => {
    const f = await run({
      "src/middleware/auth.ts": [
        "export function requireAuth(req: any, res: any, next: any) {",
        "  if (process.env.NODE_ENV !== 'production' && req.headers['x-dev-secret'] === process.env.DEV_SECRET) {",
        "    return next();",
        "  }",
        "  if (!req.user) return res.status(401).end();",
        "  next();",
        "}",
      ].join("\n"),
    });
    expect(rule(f, ENV)).toHaveLength(0);
  });

  it("is silent when the auth function never denies", async () => {
    const f = await run({
      "src/lib/authors.ts": [
        "export function listAuthors(req: any, res: any, next: any) {",
        "  if (process.env.NODE_ENV !== 'production') return next();",
        "  res.json([]);",
        "}",
      ].join("\n"),
    });
    expect(rule(f, ENV)).toHaveLength(0);
  });
});

describe("auth/secret-check-fails-open", () => {
  it("flags `if (secret && header !== Bearer secret)` returning 401", async () => {
    const files = {
      "app/api/cron/route.ts": [
        "export async function GET(req: Request) {",
        "  const secret = process.env.CRON_SECRET;",
        "  if (secret && req.headers.get('authorization') !== `Bearer ${secret}`) {",
        "    return new Response('unauthorized', { status: 401 });",
        "  }",
        "  return Response.json({ ok: true });",
        "}",
      ].join("\n"),
    };
    const f = rule(await run(files), OPEN);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "high", confidence: "high", line: 3 });
    expectRubric(f);
    expect(rule(await run(files), OPEN).map((x) => x.id)).toEqual(f.map((x) => x.id));
  });

  it("flags the nested form with process.env read inline", async () => {
    const f = rule(
      await run({
        "server/hook.ts": [
          "export function hook(req: any, res: any) {",
          "  if (process.env.WEBHOOK_TOKEN) {",
          "    if (req.query.token !== process.env.WEBHOOK_TOKEN) return res.status(403).end();",
          "  }",
          "  res.json({});",
          "}",
        ].join("\n"),
      }),
      OPEN,
    );
    expect(f).toHaveLength(1);
    expect(f[0]!.line).toBe(2);
  });

  it("is silent when the check fails closed", async () => {
    const f = await run({
      "app/api/a/route.ts": [
        "export async function GET(req: Request) {",
        "  const secret = process.env.CRON_SECRET;",
        "  if (!secret || req.headers.get('authorization') !== `Bearer ${secret}`) {",
        "    return new Response('unauthorized', { status: 401 });",
        "  }",
        "  return Response.json({});",
        "}",
      ].join("\n"),
    });
    expect(rule(f, OPEN)).toHaveLength(0);
  });

  it("is silent when an earlier guard rejects a missing secret", async () => {
    const f = await run({
      "app/api/b/route.ts": [
        "export async function GET(req: Request) {",
        "  const secret = process.env.API_TOKEN;",
        "  if (!secret) return new Response('misconfigured', { status: 500 });",
        "  if (secret && req.headers.get('x-token') !== secret) {",
        "    return new Response('no', { status: 401 });",
        "  }",
        "  return Response.json({});",
        "}",
      ].join("\n"),
    });
    expect(rule(f, OPEN)).toHaveLength(0);
  });

  it("is silent for length warnings and feature flags", async () => {
    const f = await run({
      "lib/config.ts": [
        "export function check(req: any) {",
        "  const key = process.env.SIGNING_KEY;",
        "  if (key && key.length < 32) console.warn('short key');",
        "  const flag = process.env.FEATURE_BETA;",
        "  if (flag && req.query.beta !== flag) throw new Error('no beta');",
        "}",
      ].join("\n"),
    });
    expect(rule(f, OPEN)).toHaveLength(0);
  });

  it("is silent when an else branch denies", async () => {
    const f = await run({
      "app/api/c/route.ts": [
        "export async function GET(req: Request) {",
        "  const secret = process.env.CRON_SECRET;",
        "  if (secret) {",
        "    if (req.headers.get('x') !== secret) return new Response('no', { status: 401 });",
        "  } else {",
        "    return new Response('off', { status: 503 });",
        "  }",
        "  return Response.json({});",
        "}",
      ].join("\n"),
    });
    expect(rule(f, OPEN)).toHaveLength(0);
  });
});

describe("auth-bypass-detector scoping", () => {
  it("skips test files and honours targetFiles contexts", async () => {
    const src = [
      "export async function GET(req: Request) {",
      "  const secret = process.env.CRON_SECRET;",
      "  if (secret && req.headers.get('a') !== secret) return new Response('x', { status: 401 });",
      "}",
    ].join("\n");
    const files = { "app/api/a/route.ts": src, "app/api/b/route.test.ts": src };
    expect(await run(files, "app/api/b/route.test.ts")).toHaveLength(0);
    expect(await run(files, "app/api/a/route.ts")).toHaveLength(1);
  });
});
