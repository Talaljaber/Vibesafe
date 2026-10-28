import { describe, it, expect } from "vitest";
import { SupabaseRlsDetector, stripSqlNoise } from "../../src/detectors/supabase-rls-detector";
import type { ScanContext } from "@vibesafe/shared";

describe("SupabaseRlsDetector", () => {
  const detector = new SupabaseRlsDetector();

  const createContext = (files: Record<string, string>): ScanContext => ({
    rootPath: "/fake/path",
    projectContext: {} as any,
    files: Object.keys(files),
    config: {} as any,
    readFile: async (file) => files[file] ?? "",
  });

  const MIG = "supabase/migrations/001_init.sql";
  const run = (files: Record<string, string>) => detector.detect(createContext(files));
  const missing = (f: { ruleId: string }[]) => f.filter((x) => x.ruleId === "authorization/supabase-missing-rls");
  const permissive = (f: { ruleId: string }[]) =>
    f.filter((x) => x.ruleId === "authorization/supabase-permissive-policy");

  describe("missing RLS", () => {
    it("flags a table without RLS as high when no client usage exists", async () => {
      const findings = await run({ [MIG]: `create table public.todos (id int);\n` });
      expect(findings).toHaveLength(1);
      expect(findings[0]!.severity).toBe("high");
      expect(findings[0]!.deployBlocking).toBe(false);
      expect(findings[0]!.category).toBe("authorization");
      expect(findings[0]!.file).toBe(MIG);
      expect(findings[0]!.line).toBe(1);
      expect(findings[0]!.id).toMatch(/^AUTHZ-/);
    });

    it("is critical when client-side code uses Supabase", async () => {
      const findings = await run({
        [MIG]: `create table todos (id int);`,
        "src/lib/supabase.ts": `import { createClient } from "@supabase/supabase-js";\nexport const s = createClient(a, b);`,
        "components/List.tsx": `"use client";\nimport { createClient } from "@supabase/supabase-js";`,
      });
      expect(findings).toHaveLength(1);
      expect(findings[0]!.severity).toBe("critical");
      expect(findings[0]!.deployBlocking).toBe(true);
    });

    it("stays high when Supabase is only used in server-side ts", async () => {
      const findings = await run({
        [MIG]: `create table todos (id int);`,
        "src/server/db.ts": `import { createClient } from "@supabase/supabase-js";`,
      });
      expect(findings[0]!.severity).toBe("high");
    });

    it("treats NEXT_PUBLIC_SUPABASE env use as client-side", async () => {
      const findings = await run({
        [MIG]: `create table todos (id int);`,
        "src/lib/s.ts": `const url = process.env.NEXT_PUBLIC_SUPABASE_URL;`,
      });
      expect(findings[0]!.severity).toBe("critical");
    });

    it("does not flag a table with RLS enabled", async () => {
      const findings = await run({
        [MIG]: `create table public.todos (id int);\nalter table public.todos enable row level security;`,
      });
      expect(findings).toHaveLength(0);
    });

    it("finds RLS enabled in a later migration", async () => {
      const findings = await run({
        "supabase/migrations/001.sql": `create table todos (id int);`,
        "supabase/migrations/002.sql": `ALTER TABLE todos ENABLE ROW LEVEL SECURITY;`,
      });
      expect(findings).toHaveLength(0);
    });

    it("handles case, quoted identifiers, if not exists and extra whitespace", async () => {
      const sql = `CREATE TABLE IF NOT EXISTS "public"."Posts" (id int);
ALTER   TABLE  ONLY "public"."Posts"
  ENABLE ROW LEVEL SECURITY;
Create Table If Not Exists PUBLIC.Comments (id int);`;
      const findings = missing(await run({ [MIG]: sql }));
      expect(findings).toHaveLength(1);
      expect(findings[0]!.title).toContain("comments");
      expect(findings[0]!.line).toBe(4);
    });

    it("matches unquoted and quoted names case-insensitively only when unquoted", async () => {
      const findings = await run({
        [MIG]: `create table Todos (id int);\nalter table todos enable row level security;`,
      });
      expect(findings).toHaveLength(0);
    });

    it("ignores tables in other schemas", async () => {
      const findings = await run({
        [MIG]: `create table private.secrets (id int);\ncreate table auth.extra (id int);\ncreate table "internal"."x" (id int);`,
      });
      expect(findings).toHaveLength(0);
    });

    it("ignores commented-out and string-embedded statements", async () => {
      const sql = `-- create table public.a (id int);
/* create table public.b (id int);
   /* nested create table public.c (id int); */
*/
select 'create table public.d (id int)';
create function f() returns void as $$ begin create table public.e (id int); end $$ language plpgsql;
create table public.real (id int); -- trailing
`;
      const findings = await run({ [MIG]: sql });
      expect(findings).toHaveLength(1);
      expect(findings[0]!.title).toContain("real");
      expect(findings[0]!.line).toBe(7);
    });

    it("reports every table when a file has many statements", async () => {
      const sql = `create table a (id int);
create table b (id int);
alter table b enable row level security;
create table c (id int);
`;
      const findings = await run({ [MIG]: sql });
      expect(findings.map((f) => f.line)).toEqual([1, 4]);
    });

    it("does not flag a table that is later dropped", async () => {
      const findings = await run({
        "supabase/migrations/001.sql": `create table old_stuff (id int);`,
        "supabase/migrations/002.sql": `drop table if exists public.old_stuff;`,
      });
      expect(findings).toHaveLength(0);
    });

    it("flags a table whose RLS is later disabled", async () => {
      const findings = await run({
        [MIG]: `create table t (id int);\nalter table t enable row level security;\nalter table t disable row level security;`,
      });
      expect(findings).toHaveLength(1);
    });

    it("skips partitions of a parent table", async () => {
      const findings = await run({
        [MIG]: `create table events_2024 partition of events for values from ('2024-01-01') to ('2025-01-01');`,
      });
      expect(findings).toHaveLength(0);
    });

    it("does not treat temp tables as public tables", async () => {
      const findings = await run({ [MIG]: `create temp table scratch (id int);` });
      expect(findings).toHaveLength(0);
    });

    it("ignores sql files outside supabase/ when the project does not use Supabase", async () => {
      const findings = await run({
        "db/schema.sql": `create table users (id int);`,
        "src/app.ts": `console.log("hi");`,
      });
      expect(findings).toHaveLength(0);
    });

    it("scans sql files outside supabase/ when the project uses Supabase", async () => {
      const findings = await run({
        "db/schema.sql": `create table users (id int);`,
        "src/app.ts": `import { createClient } from "@supabase/supabase-js";`,
      });
      expect(findings).toHaveLength(1);
    });

    it("returns nothing when there are no sql files", async () => {
      expect(await run({ "a.ts": "x" })).toEqual([]);
    });

    it("redacts evidence through sanitizeEvidence", async () => {
      const findings = await run({ [MIG]: `create table t (id int);` });
      expect(findings[0]!.evidence).toBe("create table t (id int);");
    });
  });

  describe("permissive policies", () => {
    const base = `create table public.t (id int);\nalter table public.t enable row level security;\n`;

    it("flags using (true) on update", async () => {
      const findings = await run({
        [MIG]: base + `create policy "open" on public.t for update using (true);`,
      });
      expect(findings).toHaveLength(1);
      expect(findings[0]!.ruleId).toBe("authorization/supabase-permissive-policy");
      expect(findings[0]!.severity).toBe("high");
      expect(findings[0]!.line).toBe(3);
    });

    it("flags with check (true) on insert", async () => {
      const findings = await run({
        [MIG]: base + `CREATE POLICY p ON t FOR INSERT TO authenticated WITH CHECK (TRUE);`,
      });
      expect(permissive(findings)).toHaveLength(1);
    });

    it("flags delete and all, including default command and multi-line / nested parens", async () => {
      const findings = await run({
        [MIG]:
          base +
          `create policy a on t for delete using ( ( true ) );
create policy b on t
  for all
  to anon, authenticated
  using (true)
  with check (true);
create policy c on t using (true);`,
      });
      expect(permissive(findings)).toHaveLength(3);
      expect(permissive(findings).map((f) => (f as any).line)).toEqual([3, 4, 9]);
    });

    it("does not flag select policies", async () => {
      const findings = await run({ [MIG]: base + `create policy p on t for select using (true);` });
      expect(findings).toHaveLength(0);
    });

    it("does not flag restrictive policies or service_role-only policies", async () => {
      const findings = await run({
        [MIG]:
          base +
          `create policy a on t as restrictive for all using (true);
create policy b on t for all to service_role using (true) with check (true);`,
      });
      expect(findings).toHaveLength(0);
    });

    it("does not flag real conditions", async () => {
      const findings = await run({
        [MIG]:
          base +
          `create policy a on t for update using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy b on t for insert with check (is_active = true);
create policy c on t for all using ('true' = 'true');`,
      });
      expect(findings).toHaveLength(0);
    });

    it("ignores policies in comments", async () => {
      const findings = await run({ [MIG]: base + `-- create policy p on t for all using (true);` });
      expect(findings).toHaveLength(0);
    });

    it("reports both missing RLS and permissive policy", async () => {
      const findings = await run({
        [MIG]: `create table t (id int);\ncreate policy p on t for all using (true);`,
      });
      expect(missing(findings)).toHaveLength(1);
      expect(permissive(findings)).toHaveLength(1);
    });
  });

  describe("stripSqlNoise", () => {
    it("preserves length and newlines", () => {
      const src = "a -- c\n'x\ny' /* z\n*/ $$q\nr$$ \"id\"";
      const out = stripSqlNoise(src);
      expect(out).toHaveLength(src.length);
      expect(out.split("\n")).toHaveLength(src.split("\n").length);
      expect(out).toContain('"id"');
      expect(out).not.toContain("z");
    });
  });
});
