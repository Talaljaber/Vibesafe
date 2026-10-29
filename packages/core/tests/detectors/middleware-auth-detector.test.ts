import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { MiddlewareAuthDetector } from "../../src/detectors/middleware-auth-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const ctx = (files: Record<string, string>, only?: string[]): ScanContext => ({
  rootPath: "/fake",
  projectContext: {} as any,
  files: only ?? Object.keys(files),
  config: {} as any,
  readFile: async (f) => files[f] ?? "",
});
const run = (files: Record<string, string>, only?: string[]) =>
  new MiddlewareAuthDetector().detect(ctx(files, only));

const cookieMiddleware = (matcher: string): string =>
  [
    "import { NextResponse } from 'next/server';",
    "export function middleware(req) {",
    "  const hasSession = req.cookies",
    "    .getAll()",
    "    .some((c) => c.name.startsWith('sb-') && c.name.includes('auth-token'));",
    "  if (!hasSession) return NextResponse.redirect(new URL('/login', req.url));",
    "  return NextResponse.next();",
    "}",
    `export const config = { matcher: ${matcher} };`,
  ].join("\n");

const pages = {
  "app/admin/page.tsx": "'use client';\nexport default function A() { return null; }",
  "app/dashboard/page.tsx": "export default function D() { return null; }",
};

describe("MiddlewareAuthDetector: auth/middleware-cookie-presence-only", () => {
  it("flags a cookie-presence gate (getAll().some and get())", async () => {
    const f = await run({
      "middleware.ts": cookieMiddleware("['/dashboard/:path*']"),
      "src/middleware.ts": [
        "export function middleware(request) {",
        "  const token = request.cookies.get('session')?.value;",
        "  if (!token) return NextResponse.redirect(new URL('/sign-in', request.url));",
        "}",
      ].join("\n"),
    });
    const cookie = f.filter((x) => x.ruleId === "auth/middleware-cookie-presence-only");
    expect(cookie.map((x) => [x.file, x.line])).toEqual([
      ["middleware.ts", 3],
      ["src/middleware.ts", 2],
    ]);
    expect(cookie[0]).toMatchObject({ severity: "medium", confidence: "medium" });
    expectRubric(f);
  });

  it("does not flag middleware that verifies the token or session", async () => {
    const f = await run({
      "middleware.ts": [
        "import { jwtVerify } from 'jose';",
        "export async function middleware(req) {",
        "  const token = req.cookies.get('session')?.value;",
        "  if (!token) return NextResponse.redirect(new URL('/login', req.url));",
        "  await jwtVerify(token, secret);",
        "}",
      ].join("\n"),
      "src/middleware.ts": [
        "export async function middleware(request) {",
        "  const supabase = createServerClient(url, key, { cookies: { getAll() { return request.cookies.getAll(); } } });",
        "  const { data } = await supabase.auth.getUser();",
        "  if (!data.user) return NextResponse.redirect(new URL('/login', request.url));",
        "}",
      ].join("\n"),
    });
    expect(f).toEqual([]);
  });

  it("does not flag non-auth cookies, commented code or non-middleware files", async () => {
    const f = await run({
      "middleware.ts": [
        "export function middleware(req) {",
        "  const locale = req.cookies.get('NEXT_LOCALE')?.value;",
        "  // const s = req.cookies.get('session'); if (!s) return NextResponse.redirect('/login')",
        "  return NextResponse.rewrite(new URL(`/${locale}`, req.url));",
        "}",
      ].join("\n"),
      "lib/session.ts":
        "export function f(req) { if (!req.cookies.get('session')) return NextResponse.redirect('/login'); }",
    });
    expect(f).toEqual([]);
  });
});

describe("MiddlewareAuthDetector: auth/middleware-matcher-gap", () => {
  it("flags an existing /admin section that the matcher does not cover", async () => {
    const f = await run({
      "middleware.ts": cookieMiddleware("['/dashboard/:path*', '/settings/:path*']"),
      ...pages,
    });
    const gap = f.filter((x) => x.ruleId === "auth/middleware-matcher-gap");
    expect(gap).toHaveLength(1);
    expect(gap[0]).toMatchObject({ severity: "high", confidence: "medium", line: 9 });
    expectRubric(f);
  });

  it("flags user areas at medium and finds sections by probing when only middleware is scanned", async () => {
    const files = {
      "middleware.ts": [
        "import { auth } from './auth';",
        "export default auth((req) => { if (!req.auth) return Response.redirect(new URL('/login', req.url)); });",
        'export const config = { matcher: ["/admin/:path*"] };',
      ].join("\n"),
      "app/dashboard/page.tsx": "export default function D() { return null; }",
    };
    const f = await run(files, ["middleware.ts"]);
    expect(f.map((x) => [x.ruleId, x.severity, x.line])).toEqual([
      ["auth/middleware-matcher-gap", "medium", 3],
    ]);
    expectRubric(f);
  });

  it("skips regex matchers, catch-alls, sections that check the session themselves and missing matchers", async () => {
    const f = await run({
      "middleware.ts": cookieMiddleware("['/((?!_next|api).*)']"),
      "src/middleware.ts": cookieMiddleware("['/:path*']").replace(/cookies[\s\S]*?\);/, "x;"),
      ...pages,
    });
    expect(f.filter((x) => x.ruleId === "auth/middleware-matcher-gap")).toEqual([]);
    const guarded = await run({
      "middleware.ts": [
        "export async function middleware(req) { const s = await getToken({ req }); if (!s) return NextResponse.redirect('/login'); }",
        "export const config = { matcher: ['/dashboard/:path*'] };",
      ].join("\n"),
      "app/admin/layout.tsx":
        "export default async function L({ children }) { const s = await getServerSession(); if (!s) redirect('/login'); return children; }",
      "app/dashboard/page.tsx": "export default function D() { return null; }",
    });
    expect(guarded).toEqual([]);
  });

  it("does not report middleware that does not gate access, and keeps ids stable", async () => {
    const files = {
      "middleware.ts":
        "export function middleware() { return NextResponse.next(); }\nexport const config = { matcher: ['/dashboard/:path*'] };",
      ...pages,
    };
    expect(await run(files)).toEqual([]);
    const gapFiles = { "middleware.ts": cookieMiddleware("['/dashboard/:path*']"), ...pages };
    const a = await run(gapFiles);
    const b = await run(gapFiles);
    expect(b.map((x) => x.id)).toEqual(a.map((x) => x.id));
  });
});
