import { describe, it, expect } from "vitest";
import { MissingValidationDetector } from "../../src/detectors/missing-validation-detector";
import type { ScanContext } from "@vibesafe/shared";

const ctx = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake",
  projectContext: {} as any,
  files: Object.keys(files),
  config: {} as any,
  readFile: async (f) => files[f] ?? "",
});

describe("MissingValidationDetector (library/call detection, inputs, lines)", () => {
  const detector = new MissingValidationDetector();
  const run = (src: string, file = "app/api/data/route.ts") => detector.detect(ctx({ [file]: src }));

  it("is not fooled by path.join containing 'joi'", async () => {
    const f = await run(`import path from "path";
export async function POST(req: Request) {
  const p = path.join("a", "b");
  const body = await req.json();
  return Response.json({ p, body });
}`);
    expect(f).toHaveLength(1);
    expect(f[0]!.line).toBe(4);
  });

  it("does not count JSON.parse as validation", async () => {
    const f = await run(`export async function POST(req: Request) {
  const text = await req.text();
  return Response.json(JSON.parse(text));
}`);
    expect(f).toHaveLength(1);
    expect(f[0]!.line).toBe(2);
  });

  it("does not count a validation import alone", async () => {
    const f = await run(`import { z } from "zod";
export async function POST(req: Request) { const b = await req.json(); return Response.json(b); }`);
    expect(f).toHaveLength(1);
  });

  it("accepts safeParse with an imported schema", async () => {
    const f = await run(`import { schema } from "@/schemas";
export async function POST(req: Request) { const r = schema.safeParse(await req.json()); return Response.json(r); }`);
    expect(f).toHaveLength(0);
  });

  it("treats formData, text, req.query and searchParams as input reads", async () => {
    expect(await run("export async function POST(request: Request) { await request.formData(); }")).toHaveLength(1);
    expect(await run("export async function POST(request: Request) { await request.text(); }")).toHaveLength(1);
    expect(await run("export default function h(req, res) { res.json(req.query.id); }", "pages/api/x.ts")).toHaveLength(1);
    expect(
      await run("export async function GET(request: Request) { const u = new URL(request.url).searchParams; }"),
    ).toHaveLength(1);
  });

  it("detects library usage via require", async () => {
    const f = await run(`const Joi = require("joi");
const s = Joi.object({});
module.exports = async (req, res) => { const v = s.validate(req.body); res.json(v); };`, "pages/api/y.js");
    expect(f).toHaveLength(0);
  });

  it("ignores non-route files", async () => {
    expect(await run("const b = await req.json();", "lib/api/helper.ts")).toHaveLength(0);
  });
});
