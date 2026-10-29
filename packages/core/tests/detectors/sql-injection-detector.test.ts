import { describe, it, expect } from "vitest";
import { SqlInjectionDetector } from "../../src/detectors/sql-injection-detector.js";
import { expectRubric } from "../helpers/rubric.js";
import { run } from "../helpers/injection.js";

const detector = new SqlInjectionDetector();
const byRule = (findings: { ruleId: string }[], ruleId: string) =>
  findings.filter((f) => f.ruleId === ruleId);

describe("SqlInjectionDetector: injection/sql-built-from-input", () => {
  it("flags a template literal query built from the request body (App Router)", async () => {
    const findings = await run(detector, {
      "app/api/search/route.ts": `import { pool } from "@/lib/db";
export async function POST(req: Request) {
  const { name } = await req.json();
  const rows = await pool.query(\`SELECT * FROM users WHERE name = '\${name}'\`);
  return Response.json(rows);
}`,
    });
    const hits = byRule(findings, "injection/sql-built-from-input");
    expect(hits).toHaveLength(1);
    expect(hits[0]!.severity).toBe("critical");
    expect(hits[0]!.confidence).toBe("high");
    expect(hits[0]!.line).toBe(4);
    expect(hits[0]!.deployBlocking).toBe(true);
    expectRubric(findings);
  });

  it("flags string concatenation and $queryRawUnsafe in Express handlers", async () => {
    const findings = await run(detector, {
      "server.js": `const express = require("express");
const app = express();
app.get("/orders", async (req, res) => {
  const sort = req.query.sort;
  const sql = "SELECT * FROM orders ORDER BY " + sort;
  const rows = await db.query(sql);
  res.json(rows);
});
app.post("/raw", async (req, res) => {
  const rows = await prisma.$queryRawUnsafe(\`SELECT * FROM t WHERE id = \${req.body.id}\`);
  res.json(rows);
});`,
    });
    const hits = byRule(findings, "injection/sql-built-from-input");
    expect(hits.map((f) => f.line ?? 0).sort((a, b) => a - b)).toEqual([6, 10]);
    expectRubric(findings);
  });

  it("does not flag bind parameters, tagged templates or allowlisted identifiers", async () => {
    const findings = await run(detector, {
      "app/api/search/route.ts": `import { sql } from "@/lib/db";
const SORT = new Map([["name", "name"], ["date", "created_at"]]);
export async function POST(req: Request) {
  const { name, sort } = await req.json();
  await pool.query("SELECT * FROM users WHERE name = $1", [name]);
  await sql\`SELECT * FROM users WHERE name = \${name}\`;
  await prisma.$queryRaw\`SELECT * FROM users WHERE name = \${name}\`;
  const col = SORT.get(sort) ?? "created_at";
  await pool.query(\`SELECT * FROM users ORDER BY \${col}\`);
  return Response.json({});
}`,
    });
    expect(findings).toHaveLength(0);
  });

  it("ignores queries that only appear in comments or strings", async () => {
    const findings = await run(detector, {
      "app/api/search/route.ts": `export async function POST(req: Request) {
  const { name } = await req.json();
  // await pool.query(\`SELECT * FROM users WHERE name = '\${name}'\`);
  const doc = "pool.query(\`SELECT * FROM users WHERE name = \${name}\`)";
  return Response.json({ doc });
}`,
    });
    expect(findings).toHaveLength(0);
  });

  it("does not run on client components, .py or .sql files", async () => {
    const findings = await run(detector, {
      "app/search/page.tsx": `"use client";
export default function Page({ q }: { q: string }) {
  const rows = db.query(\`SELECT * FROM users WHERE name = '\${req.query.q}'\`);
  return <div>{rows}</div>;
}`,
      "app/query.py": `cursor.execute(f"SELECT * FROM users WHERE name = '{request.args['q']}'")`,
      "db/seed.sql": `SELECT * FROM users WHERE name = '\${req.body.name}';`,
    });
    expect(findings).toHaveLength(0);
  });

  it("skips test files unless includeTests", async () => {
    const files = {
      "tests/api.test.ts": `export async function POST(req: Request) {
  const { name } = await req.json();
  return pool.query(\`SELECT * FROM users WHERE name = '\${name}'\`);
}`,
    };
    expect(await run(detector, files)).toHaveLength(0);
    expect(
      byRule(await run(detector, files, { includeTests: true }), "injection/sql-built-from-input"),
    ).toHaveLength(1);
  });

  it("produces stable ids across runs", async () => {
    const files = {
      "app/api/search/route.ts": `export async function POST(req: Request) {
  const { name } = await req.json();
  return pool.query(\`SELECT * FROM users WHERE name = '\${name}'\`);
}`,
    };
    const a = await run(detector, files);
    const b = await run(detector, files);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
    expect(a).toHaveLength(1);
  });
});

describe("SqlInjectionDetector: injection/sql-built-from-parameter", () => {
  it("flags an exported helper that interpolates its parameter into raw SQL", async () => {
    const findings = await run(detector, {
      "lib/reports.ts": `export async function findByEmail(email: string) {
  return pool.query(\`SELECT * FROM users WHERE email = '\${email}'\`);
}
export const search = async (term: string) =>
  db.$queryRawUnsafe("SELECT * FROM products WHERE name LIKE '%" + term + "%'");`,
    });
    const hits = byRule(findings, "injection/sql-built-from-parameter");
    expect(hits.map((f) => f.line)).toEqual([2, 5]);
    expect(hits[0]!.severity).toBe("medium");
    expect(hits[0]!.confidence).toBe("low");
    expectRubric(findings);
  });

  it("does not flag non-exported helpers, numeric parameters or bind parameters", async () => {
    const findings = await run(detector, {
      "lib/reports.ts": `async function internal(email: string) {
  return pool.query(\`SELECT * FROM users WHERE email = '\${email}'\`);
}
export async function page(limit: number) {
  return pool.query(\`SELECT * FROM users LIMIT \${limit}\`);
}
export async function byEmail(email: string) {
  return pool.query("SELECT * FROM users WHERE email = $1", [email]);
}`,
    });
    expect(byRule(findings, "injection/sql-built-from-parameter")).toHaveLength(0);
  });

  it("ignores helpers in comments", async () => {
    const findings = await run(detector, {
      "lib/reports.ts": `/*
export async function findByEmail(email: string) {
  return pool.query(\`SELECT * FROM users WHERE email = '\${email}'\`);
}
*/
export const x = 1;`,
    });
    expect(findings).toHaveLength(0);
  });
});

describe("SqlInjectionDetector: injection/postgrest-filter-interpolation", () => {
  it("flags a Supabase .or() filter built from the query string", async () => {
    const findings = await run(detector, {
      "app/api/products/route.ts": `import { NextRequest } from "next/server";
export async function GET(req: NextRequest) {
  const q = req.nextUrl.searchParams.get("q");
  const { data } = await supabase
    .from("products")
    .select("*")
    .or(\`name.ilike.%\${q}%,description.ilike.%\${q}%\`);
  return Response.json(data);
}`,
      "pages/api/find.ts": `export default async function handler(req, res) {
  const { data } = await supabase.from("t").select().or("title.eq." + req.query.title);
  res.json(data);
}`,
    });
    const hits = byRule(findings, "injection/postgrest-filter-interpolation");
    expect(hits).toHaveLength(2);
    expect(hits.every((f) => f.severity === "medium")).toBe(true);
    expectRubric(findings);
  });

  it("does not flag typed filters, literal filter strings or array .or()", async () => {
    const findings = await run(detector, {
      "app/api/products/route.ts": `export async function GET(req: Request) {
  const q = new URL(req.url).searchParams.get("q");
  await supabase.from("products").select("*").ilike("name", \`%\${q}%\`);
  await supabase.from("products").select("*").or("status.eq.active,status.eq.trial");
  const ok = [q].some(Boolean) || [1].or(q);
  return Response.json(ok);
}`,
    });
    expect(byRule(findings, "injection/postgrest-filter-interpolation")).toHaveLength(0);
  });

  it("ignores a filter in a comment", async () => {
    const findings = await run(detector, {
      "app/api/products/route.ts": `export async function GET(req: Request) {
  const q = new URL(req.url).searchParams.get("q");
  // supabase.from("p").select().or(\`name.ilike.%\${q}%\`)
  return Response.json(q);
}`,
    });
    expect(findings).toHaveLength(0);
  });
});
