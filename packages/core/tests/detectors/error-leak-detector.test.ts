import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { ErrorLeakDetector } from "../../src/detectors/error-leak-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const ctx = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake",
  projectContext: {} as any,
  files: Object.keys(files),
  config: {} as any,
  readFile: async (f) => files[f] ?? "",
});
const run = (files: Record<string, string>) => new ErrorLeakDetector().detect(ctx(files));

describe("ErrorLeakDetector", () => {
  it("flags a shared error helper returning the stack and DB details", async () => {
    const f = await run({
      "lib/server/errors.ts": [
        'import { NextResponse } from "next/server";',
        "export function errorResponse(err: unknown, status = 500) {",
        "  const e = err as any;",
        "  return NextResponse.json(",
        "    {",
        "      error: e.message,",
        "      details: e.details,",
        "      hint: e.hint,",
        "      stack: e.stack,",
        "    },",
        "    { status },",
        "  );",
        "}",
      ].join("\n"),
    });
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({
      ruleId: "security_config/error-stack-leak",
      severity: "medium",
      confidence: "high",
      line: 9,
    });
    expectRubric(f);
  });

  it("flags Express stack responses and raw Postgres details (medium confidence)", async () => {
    const f = await run({
      "server/app.js": [
        'const express = require("express");',
        "app.use((err, req, res, next) => {",
        "  res.status(500).send(err.stack);",
        "});",
      ].join("\n"),
      "app/api/x/route.ts": [
        "export async function GET() {",
        '  const { error } = await db.from("t").select();',
        "  if (error) return Response.json({ message: error.message, details: error.details }, { status: 500 });",
        "}",
      ].join("\n"),
    });
    expect(f.map((x) => [x.file, x.line, x.confidence]).sort()).toEqual([
      ["app/api/x/route.ts", 3, "medium"],
      ["server/app.js", 3, "high"],
    ]);
    expectRubric(f);
  });

  it("does not flag generic messages, logged stacks or development-only details", async () => {
    const f = await run({
      "app/api/a/route.ts": [
        "export async function GET() {",
        "  try { work(); } catch (err) {",
        "    console.error(err.stack);",
        '    return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });',
        "  }",
        "}",
      ].join("\n"),
      "app/api/b/route.ts": [
        "export async function GET() {",
        "  return NextResponse.json({",
        '    error: "Failed",',
        '    stack: process.env.NODE_ENV === "development" ? err.stack : undefined,',
        "  });",
        "}",
      ].join("\n"),
    });
    expect(f).toEqual([]);
  });

  it("ignores comments, strings, client components and non-JS files", async () => {
    const f = await run({
      "app/api/c/route.ts":
        '// return NextResponse.json({ stack: e.stack })\nconst s = "Response.json({ stack: e.stack })";',
      "components/ErrorView.tsx":
        '"use client";\nexport function E({ error }) { console.log(error.stack); return Response.json({ stack: error.stack }); }',
      "app/views.py":
        "return JsonResponse({'stack': traceback.format_exc(), 'details': e.details})",
    });
    expect(f).toEqual([]);
  });

  it("keeps ids stable across runs", async () => {
    const files = {
      "app/api/d/route.ts":
        "export function GET() { return Response.json({ stack: new Error().stack }); }",
    };
    const a = await run(files);
    const b = await run(files);
    expect(a).toHaveLength(1);
    expect(b.map((x) => x.id)).toEqual(a.map((x) => x.id));
  });
});

describe("ErrorLeakDetector: review round 1", () => {
  it("does not flag Joi validation messages or non-error .stack fields", async () => {
    const f = await run({
      "app/api/items/route.ts": [
        'import { NextResponse } from "next/server";',
        "export async function POST(req: Request) {",
        "  const { error } = schema.validate(await req.json());",
        "  if (error) return NextResponse.json({ message: error.details[0].message }, { status: 400 });",
        "  if (error) return NextResponse.json({ errors: error.details.map((d) => d.message) });",
        "  return NextResponse.json({ stack: project.stack });",
        "}",
      ].join("\n"),
    });
    const rules = f.map((x) => [x.confidence, x.line]);
    expect(rules).toEqual([["medium", 6]]);
  });

  it("keeps high confidence for catch-bound errors", async () => {
    const f = await run({
      "app/api/x/route.ts": [
        'import { NextResponse } from "next/server";',
        "export async function GET() {",
        "  try { await go(); } catch (boom) {",
        "    return NextResponse.json({ stack: boom.stack });",
        "  }",
        "}",
      ].join("\n"),
    });
    expect(f.map((x) => x.confidence)).toEqual(["high"]);
  });
});
