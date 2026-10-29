import { describe, it, expect } from "vitest";
import { SsrfDetector } from "../../src/detectors/ssrf-detector.js";
import { PathTraversalDetector } from "../../src/detectors/path-traversal-detector.js";
import { SqlInjectionDetector } from "../../src/detectors/sql-injection-detector.js";
import { run } from "../helpers/injection.js";

const ssrf = new SsrfDetector();
const path = new PathTraversalDetector();
const sql = new SqlInjectionDetector();

const route = (body: string): string => `export async function POST(req: Request) {
  const { ids, q } = await req.json();
${body}
  return Response.json({});
}`;

describe("round 2: parameterized IN-lists", () => {
  for (const [name, body] of [
    [
      "zero-param map + join",
      `  const ph = ids.map(() => "?").join(",");\n  await pool.query(\`SELECT * FROM t WHERE id IN (\${ph})\`, ids);`,
    ],
    [
      "zero-param map without join",
      `  const ph = ids.map(() => "?");\n  await pool.query(\`SELECT * FROM t WHERE id IN (\${ph})\`, ids);`,
    ],
    [
      "inline map + join",
      `  await pool.query(\`SELECT * FROM t WHERE id IN (\${ids.map(() => "?").join(",")})\`, ids);`,
    ],
    [
      "inline map in prepare().all()",
      `  db.prepare(\`SELECT * FROM t WHERE id IN (\${ids.map((_) => "?").join(",")})\`).all(...ids);`,
    ],
  ] as const) {
    it(`is clean: ${name}`, async () => {
      const f = await run(sql, {
        "app/api/x/route.ts": `import { pool } from "./db";\n${route(body)}`,
      });
      expect(f).toHaveLength(0);
    });
  }

  it("still flags a callback that quotes the element", async () => {
    const f = await run(sql, {
      "app/api/x/route.ts": `import { pool } from "./db";\n${route(
        "  await pool.query(`SELECT * FROM t WHERE id IN (${ids.map((id) => `'${id}'`).join(\",\")})`);",
      )}`,
    });
    expect(f.length).toBeGreaterThan(0);
  });

  it("flags a verb that lives in a constant", async () => {
    const f = await run(sql, {
      "app/api/x/route.ts": `import { pool } from "./db";
const BASE = "SELECT * FROM users";
${route("  await pool.query(BASE + ` WHERE name = '${q}'`);")}`,
    });
    expect(f.length).toBeGreaterThan(0);
  });
});

describe("round 2: path prefix guard and axios baseURL", () => {
  it("flags a literal-prefix startsWith guard", async () => {
    const f = await run(path, {
      "app/api/f/route.ts": `import fs from "fs";
export async function POST(req: Request) {
  const { name } = await req.json();
  if (!name.startsWith("uploads/")) return Response.json({});
  return new Response(fs.readFileSync(name));
}`,
    });
    expect(f.length).toBeGreaterThan(0);
  });

  it("accepts a startsWith guard on a resolved path", async () => {
    const f = await run(path, {
      "app/api/f/route.ts": `import fs from "fs";
import p from "path";
export async function POST(req: Request) {
  const { name } = await req.json();
  const full = p.resolve("/srv/uploads", name);
  if (!full.startsWith("/srv/uploads/")) return Response.json({});
  return new Response(fs.readFileSync(full));
}`,
    });
    expect(f).toHaveLength(0);
  });

  it("flags axios({ baseURL: input })", async () => {
    const f = await run(ssrf, {
      "app/api/a/route.ts": `import axios from "axios";
export async function POST(req: Request) {
  const { host } = await req.json();
  await axios({ baseURL: host, url: "/x" });
  return Response.json({});
}`,
    });
    expect(f).toHaveLength(1);
  });
});
