import { describe, it, expect } from "vitest";
import { SsrfDetector } from "../../src/detectors/ssrf-detector.js";
import { PathTraversalDetector } from "../../src/detectors/path-traversal-detector.js";
import { SqlInjectionDetector } from "../../src/detectors/sql-injection-detector.js";
import { run } from "../helpers/injection.js";

const ssrf = new SsrfDetector();
const path = new PathTraversalDetector();
const sql = new SqlInjectionDetector();

describe("SSRF: request path members and config objects", () => {
  it("does not flag a proxy that appends the request pathname to a fixed origin", async () => {
    const f = await run(ssrf, {
      "app/api/proxy/route.ts": `import { NextRequest } from "next/server";
export async function GET(req: NextRequest) {
  return fetch(\`\${process.env.BACKEND_URL}\${req.nextUrl.pathname}\${req.nextUrl.search}\`);
}`,
    });
    expect(f).toHaveLength(0);
  });

  it("flags axios({ url }) and axios.request({ url }) with a user URL", async () => {
    const f = await run(ssrf, {
      "app/api/a/route.ts": `import axios from "axios";
export async function POST(req: Request) {
  const { url } = await req.json();
  await axios({ url, method: "get" });
  await axios.request({ method: "get", url: url });
  return Response.json({});
}`,
    });
    expect(f.map((x) => x.line).sort()).toEqual([4, 5]);
  });

  it("does not flag axios({ url }) with a literal URL", async () => {
    const f = await run(ssrf, {
      "app/api/a/route.ts": `import axios from "axios";
export async function POST(req: Request) {
  const { id } = await req.json();
  await axios({ url: "https://api.example.com/x", params: { id } });
  return Response.json({});
}`,
    });
    expect(f).toHaveLength(0);
  });
});

describe("path traversal: startsWith guard", () => {
  it("does not treat startsWith('/') as a guard", async () => {
    const f = await run(path, {
      "app/api/f/route.ts": `import fs from "fs";
export async function GET(req: Request) {
  const name = new URL(req.url).searchParams.get("name") ?? "";
  if (name.startsWith("/")) return new Response("no");
  return new Response(fs.readFileSync("uploads/" + name));
}`,
    });
    expect(f).toHaveLength(1);
  });

  it("still accepts a startsWith(base) check", async () => {
    const f = await run(path, {
      "app/api/f/route.ts": `import fs from "fs";
import nodePath from "path";
const BASE = "/srv/uploads";
export async function GET(req: Request) {
  const name = new URL(req.url).searchParams.get("name") ?? "";
  const full = nodePath.resolve(BASE, name);
  if (!full.startsWith(BASE)) return new Response("no");
  return new Response(fs.readFileSync(full));
}`,
    });
    expect(f).toHaveLength(0);
  });
});

describe("SQL: clause words in prose are not SQL", () => {
  it("does not flag logger.run with English containing 'where'", async () => {
    const f = await run(sql, {
      "app/api/l/route.ts": `export async function POST(req: Request) {
  const { q } = await req.json();
  logger.run(\`Search where user typed \${q}\`);
  return Response.json({});
}`,
    });
    expect(f).toHaveLength(0);
  });

  it("still flags db.run with a real statement", async () => {
    const f = await run(sql, {
      "app/api/l/route.ts": `export async function POST(req: Request) {
  const { q } = await req.json();
  db.run(\`DELETE FROM t WHERE name = '\${q}'\`);
  return Response.json({});
}`,
    });
    expect(f).toHaveLength(1);
  });
});

describe("finding ids are stable when earlier lines change", () => {
  it("keeps the id when a same-line-count edit shifts the byte offset", async () => {
    const mk = (c: string) => ({
      "app/api/s/route.ts": `// ${c}
export async function POST(req: Request) {
  const { name } = await req.json();
  return pool.query(\`SELECT * FROM users WHERE name = '\${name}'\`);
}`,
    });
    const a = await run(sql, mk("a"));
    const b = await run(sql, mk("a much longer comment"));
    expect(a).toHaveLength(1);
    expect(a[0]!.id).toBe(b[0]!.id);
  });
});
