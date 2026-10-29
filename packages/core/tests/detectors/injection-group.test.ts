import { describe, it, expect } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { Severity } from "@talaljaber/vibesafe-shared";
import { DetectorRegistry } from "../../src/scanner/detector-registry.js";
import { ScannerPipeline } from "../../src/scanner/pipeline.js";
import { MissingValidationDetector } from "../../src/detectors/missing-validation-detector.js";
import { injectionDetectors, injectionPrecedence } from "../../src/detectors/groups/injection.js";
import { run } from "../helpers/injection.js";

const ROUTE = `export async function POST(req: Request) {
  const { name } = await req.json();
  const rows = await pool.query(\`SELECT * FROM users WHERE name = '\${name}'\`);
  return Response.json(rows);
}

export async function PUT(req: Request) {
  const body = await req.json();
  await save(body);
  return Response.json({ ok: true });
}
`;

async function scan(
  files: Record<string, string>,
  ruleOverrides?: Record<string, "off" | Severity>,
) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "vibesafe-inj-"));
  try {
    for (const [rel, content] of Object.entries(files)) {
      const abs = path.join(root, rel);
      await fs.mkdir(path.dirname(abs), { recursive: true });
      await fs.writeFile(abs, content);
    }
    const registry = new DetectorRegistry();
    registry.register(new MissingValidationDetector());
    for (const d of injectionDetectors()) registry.register(d);
    registry.registerPrecedence(injectionPrecedence);
    return await new ScannerPipeline(registry).scan({
      rootPath: root,
      useConfigFile: false,
      ...(ruleOverrides ? { ruleOverrides } : {}),
    });
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

describe("injection precedence over validation/missing-body-validation", () => {
  it("hides the generic finding of the handler that has the injection", async () => {
    const res = await scan({ "app/api/users/route.ts": ROUTE });
    expect(res.findings.map((f) => `${f.ruleId}@${f.line}`)).toEqual([
      "injection/sql-built-from-input@3",
    ]);
  });

  it("keeps the generic finding when the injection sits in another handler", async () => {
    const [post, put] = ROUTE.split("\n\n");
    const res = await scan({ "app/api/users/route.ts": `${put!.trimEnd()}\n\n${post!}\n` });
    expect(res.findings.map((f) => `${f.ruleId}@${f.line}`).sort()).toEqual([
      "injection/sql-built-from-input@9",
      "validation/missing-body-validation@2",
    ]);
  });

  it("brings the generic finding back when the winner is turned off", async () => {
    const res = await scan(
      { "app/api/users/route.ts": ROUTE },
      { "injection/sql-built-from-input": "off" },
    );
    expect(res.findings.map((f) => `${f.ruleId}@${f.line}`)).toEqual([
      "validation/missing-body-validation@2",
    ]);
  });

  it("sets endLine on the generic finding to the end of its handler", async () => {
    const findings = await run(new MissingValidationDetector(), {
      "app/api/users/route.ts": ROUTE,
    });
    const spans = findings.map((f) => [f.line, f.endLine]);
    expect(spans).toEqual([[2, 5]]);
  });

  it("sets endLine per Express handler", async () => {
    const findings = await run(new MissingValidationDetector(), {
      "server.js": `const express = require("express");
const app = express();
app.post("/a", (req, res) => {
  save(req.body);
  res.end();
});
app.post("/b", (req, res) => {
  save(req.body);
  res.end();
});`,
    });
    expect(findings.map((f) => [f.line, f.endLine])).toEqual([
      [4, 6],
      [8, 10],
    ]);
  });

  it("declares only winners that are never less severe than the loser", () => {
    const winners = injectionPrecedence.map((r) => r.winner);
    expect(winners.length).toBeGreaterThan(0);
    for (const rule of injectionPrecedence) {
      expect(rule.losers).toEqual(["validation/missing-body-validation"]);
      expect(rule.scope).toBe("enclosing");
    }
    // these rules can be `medium`, below the `high` loser, so they coexist with it
    expect(winners).not.toContain("injection/open-redirect");
    expect(winners).not.toContain("injection/postgrest-filter-interpolation");
    expect(winners).not.toContain("injection/sql-built-from-parameter");
  });
});

describe("missing-validation: validated file uploads", () => {
  it("accepts formData() with instanceof File, size and MIME checks", async () => {
    const findings = await run(new MissingValidationDetector(), {
      "app/api/upload/route.ts": `const TYPES = new Set(["image/png", "image/jpeg"]);
export async function POST(req: Request) {
  const form = await req.formData();
  const file = form.get("file");
  if (!(file instanceof File)) return new Response("no file", { status: 400 });
  if (file.size > 5_000_000) return new Response("too big", { status: 413 });
  if (!TYPES.has(file.type)) return new Response("bad type", { status: 415 });
  await store(file);
  return Response.json({ ok: true });
}`,
    });
    expect(findings).toHaveLength(0);
  });

  it("still flags uploads missing the size or MIME check, or also reading JSON", async () => {
    const noSize = `export async function POST(req: Request) {
  const form = await req.formData();
  const file = form.get("file");
  if (!(file instanceof File)) return new Response("no", { status: 400 });
  if (file.type !== "image/png") return new Response("bad", { status: 415 });
  await store(file);
  return Response.json({ ok: true });
}`;
    const alsoJson = `export async function POST(req: Request) {
  const meta = await req.json();
  const form = await req.formData();
  const file = form.get("file");
  if (!(file instanceof File) || file.size > 1000 || file.type !== "image/png") return new Response("no");
  await store(file, meta);
  return Response.json({ ok: true });
}`;
    const findings = await run(new MissingValidationDetector(), {
      "app/api/a/route.ts": noSize,
      "app/api/b/route.ts": alsoJson,
    });
    expect(findings.map((f) => f.file).sort()).toEqual([
      "app/api/a/route.ts",
      "app/api/b/route.ts",
    ]);
  });
});

describe("injection detectors skip signature-verified Stripe webhooks", () => {
  it("reports nothing on a verified webhook route", async () => {
    const files = {
      "app/api/webhooks/stripe/route.ts": `import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
export async function POST(req: Request) {
  const body = await req.text();
  const sig = req.headers.get("stripe-signature")!;
  const event = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET!);
  const obj = event.data.object as { id: string };
  await pool.query(\`UPDATE orders SET paid = true WHERE session_id = '\${obj.id}'\`);
  return new Response("ok");
}`,
    };
    for (const detector of injectionDetectors()) {
      expect(await run(detector, files), detector.id).toHaveLength(0);
    }
  });
});
