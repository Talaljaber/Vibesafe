import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { RouteSecretDetector } from "../../src/detectors/route-secret-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const ctx = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake",
  projectContext: {} as any,
  files: Object.keys(files),
  config: {} as any,
  readFile: async (f) => files[f] ?? "",
});
const run = (files: Record<string, string>) => new RouteSecretDetector().detect(ctx(files));

describe("RouteSecretDetector: auth/hardcoded-route-secret", () => {
  it("flags a query parameter compared with a literal and redacts the literal", async () => {
    const f = await run({
      "app/api/cron/cleanup/route.ts": [
        "export async function GET(req: NextRequest) {",
        '  if (req.nextUrl.searchParams.get("key") !== "nightly-job") {',
        "    return unauthorized();",
        "  }",
        "}",
      ].join("\n"),
    });
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({
      ruleId: "auth/hardcoded-route-secret",
      severity: "high",
      confidence: "high",
      line: 2,
    });
    expect(f[0]!.evidence).not.toContain("nightly-job");
    expectRubric(f);
  });

  it("flags header and bound-variable forms (Express and Next)", async () => {
    const f = await run({
      "server/app.js": [
        'const express = require("express");',
        "const app = express();",
        "app.use((req, res, next) => {",
        '  if (req.headers["x-admin-token"] === "letmein") return next();',
        "  res.sendStatus(401);",
        "});",
      ].join("\n"),
      "app/api/hook/route.ts": [
        "export async function POST(request: Request) {",
        '  const auth = request.headers.get("authorization");',
        '  if (auth !== "Bearer abc123") return new Response(null, { status: 401 });',
        "}",
      ].join("\n"),
    });
    expect(f.map((x) => [x.file, x.line]).sort()).toEqual([
      ["app/api/hook/route.ts", 3],
      ["server/app.js", 4],
    ]);
    expectRubric(f);
  });

  it("does not flag enum comparisons, env secrets compared in constant time or trivial literals", async () => {
    const f = await run({
      "app/api/list/route.ts": [
        "export async function GET(req: NextRequest) {",
        '  const dir = req.nextUrl.searchParams.get("dir") === "asc" ? "asc" : "desc";',
        "  const isSelf = session.user.id === params.userId;",
        "  if (!isSelf && !isManager) return forbidden();",
        "}",
      ].join("\n"),
      "app/api/cron/route.ts": [
        'import { timingSafeEqual } from "node:crypto";',
        "export async function GET(req: Request) {",
        '  const token = req.headers.get("authorization");',
        "  if (token !== `Bearer ${process.env.CRON_SECRET}`) return unauthorized();",
        "}",
      ].join("\n"),
      "app/api/opt/route.ts":
        'export async function GET(req: Request) {\n  if (req.headers.get("x-token") === "") return bad();\n}',
    });
    expect(f).toEqual([]);
  });

  it("ignores comments, strings, client components and non-JS files", async () => {
    const f = await run({
      "app/api/a/route.ts":
        '// if (searchParams.get("key") !== "abc") return unauthorized();\nconst s = \'searchParams.get("key") !== "abc"\';',
      "components/Gate.tsx":
        '"use client";\nexport function G() { const searchParams = useSearchParams(); if (searchParams.get("key") !== "abc") return null; }',
      "app/views.py": 'if request.GET["key"] != "abc":\n    return HttpResponseForbidden()',
    });
    expect(f).toEqual([]);
  });
});

describe("RouteSecretDetector: auth/non-constant-time-compare", () => {
  it("flags secrets compared with === against env vars (low)", async () => {
    const f = await run({
      "app/api/cron/route.ts": [
        "export async function GET(req: Request) {",
        '  if (req.headers.get("authorization") !== `Bearer ${process.env.CRON_SECRET}`) {',
        "    return unauthorized();",
        "  }",
        "}",
      ].join("\n"),
      "server/key.js": [
        "const API_KEY = process.env.API_KEY;",
        "function check(req) {",
        '  return req.headers["x-api-key"] === API_KEY;',
        "}",
      ].join("\n"),
    });
    expect(f.map((x) => [x.ruleId, x.severity, x.line])).toEqual([
      ["auth/non-constant-time-compare", "low", 2],
      ["auth/non-constant-time-compare", "low", 3],
    ]);
    expectRubric(f);
  });

  it("keeps ids stable across runs", async () => {
    const files = {
      "app/api/c/route.ts":
        'export async function GET(req: NextRequest) {\n  if (req.nextUrl.searchParams.get("secret") !== "s3cret") return unauthorized();\n}',
    };
    const a = await run(files);
    const b = await run(files);
    expect(a).toHaveLength(1);
    expect(b.map((x) => x.id)).toEqual(a.map((x) => x.id));
  });
});

describe("RouteSecretDetector: review round 1", () => {
  it("does not treat a Bearer prefix concatenated with an env secret as hardcoded", async () => {
    const f = await run({
      "app/api/cron/route.ts": [
        "export async function GET(req: Request) {",
        '  const header = req.headers.get("authorization");',
        '  if (header !== "Bearer " + process.env.CRON_SECRET) {',
        "    return new Response(null, { status: 401 });",
        "  }",
        "}",
      ].join("\n"),
    });
    expect(f.filter((x) => x.ruleId === "auth/hardcoded-route-secret")).toEqual([]);
  });

  it("does not flag enum-style comparisons in redirect branches", async () => {
    const f = await run({
      "app/auth/confirm/route.ts": [
        "export async function GET(request: Request) {",
        "  const { searchParams } = new URL(request.url);",
        '  if (searchParams.get("token_type") === "recovery") {',
        '    return NextResponse.redirect(new URL("/reset", request.url));',
        "  }",
        '  if (request.headers.get("x-auth-provider") === "google") {',
        '    return NextResponse.redirect(new URL("/g", request.url));',
        "  }",
        "}",
      ].join("\n"),
    });
    expect(f).toEqual([]);
  });
});

describe("RouteSecretDetector: review round 2", () => {
  const handler = (cond: string): string =>
    [
      "export async function GET(request: Request) {",
      "  const session = await getSession();",
      "  if (!session) return new Response(null, { status: 401 });",
      "  const { searchParams } = new URL(request.url);",
      cond,
      "  return Response.json({});",
      "}",
    ].join("\n");

  it("does not flag non-denying key/auth enum comparisons", async () => {
    const f = await run({
      "app/api/list/route.ts": handler(
        '  const sort = searchParams.get("key") === "createdAt" ? "a" : "b";\n  const p = searchParams.get("auth") === "google" ? 1 : 2;',
      ),
    });
    expect(f.filter((x) => x.ruleId === "auth/hardcoded-route-secret")).toEqual([]);
  });

  it("flags a denying key comparison at high and a non-denying secret name at medium", async () => {
    const f = await run({
      "app/api/job/route.ts": [
        "export async function GET(request: Request) {",
        "  const { searchParams } = new URL(request.url);",
        '  if (searchParams.get("key") !== "nightly-job") return new Response(null, { status: 401 });',
        '  const ok = searchParams.get("secret") === "abc123";',
        "}",
      ].join("\n"),
    });
    const hits = f.filter((x) => x.ruleId === "auth/hardcoded-route-secret");
    expect(hits.map((x) => x.confidence)).toEqual(["high", "medium"]);
  });
});
