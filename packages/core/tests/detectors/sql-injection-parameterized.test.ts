import { describe, it, expect } from "vitest";
import { SqlInjectionDetector } from "../../src/detectors/sql-injection-detector.js";
import { run } from "../helpers/injection.js";

const detector = new SqlInjectionDetector();
const hits = async (src: string) =>
  (await run(detector, { "app/api/x/route.ts": src })).filter(
    (f) => f.ruleId === "injection/sql-built-from-input",
  );

describe("SqlInjectionDetector: parameterized dynamic SQL stays clean", () => {
  it("accepts IN-list placeholders joined from a map", async () => {
    expect(
      await hits(`export async function POST(req: Request) {
  const { ids } = await req.json();
  const marks = ids.map((_: unknown, i: number) => \`$\${i + 1}\`).join(",");
  return pool.query(\`SELECT * FROM t WHERE id IN (\${marks})\`, ids);
}`),
    ).toHaveLength(0);
  });

  it("accepts optional filters that push params and append $n placeholders", async () => {
    expect(
      await hits(`export async function GET(req: Request) {
  const q = new URL(req.url).searchParams.get("q");
  const params: unknown[] = [];
  let sql = "SELECT * FROM t WHERE 1=1";
  if (q) {
    params.push(q);
    sql += \` AND name = $\${params.length}\`;
  }
  return pool.query(sql, params);
}`),
    ).toHaveLength(0);
  });

  it("accepts where-clause arrays with placeholder entries", async () => {
    expect(
      await hits(`export async function GET(req: Request) {
  const status = new URL(req.url).searchParams.get("status");
  const values: unknown[] = [];
  const where: string[] = [];
  if (status) {
    values.push(status);
    where.push(\`status = $\${values.length}\`);
  }
  const sql = "SELECT * FROM t WHERE " + where.join(" AND ");
  return pool.query(sql, values);
}`),
    ).toHaveLength(0);
  });

  it("still flags a tainted += append", async () => {
    expect(
      await hits(`export async function GET(req: Request) {
  const q = new URL(req.url).searchParams.get("q");
  let sql = "SELECT * FROM t WHERE 1=1";
  sql += \` AND name = '\${q}'\`;
  return pool.query(sql);
}`),
    ).toHaveLength(1);
  });
});
