import { describe, it, expect } from "vitest";
import type { Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { SupabasePolicyDetector } from "../../src/detectors/supabase-policy-detector.js";
import { SupabaseRlsDetector } from "../../src/detectors/supabase-rls-detector.js";
import { supabaseDetectors, supabaseNonJsExempt } from "../../src/detectors/groups/supabase.js";
import { createDefaultRegistry } from "../../src/scanner/detector-registry.js";
import { expectRubric } from "../helpers/rubric.js";

const createContext = (files: Record<string, string>, only?: string[]): ScanContext => ({
  rootPath: "/fake/path",
  projectContext: {} as any,
  files: only ?? Object.keys(files),
  config: {} as any,
  readFile: async (file) => files[file] ?? "",
});

const detector = new SupabasePolicyDetector();
const run = async (files: Record<string, string>, only?: string[]): Promise<Finding[]> => {
  const findings = await detector.detect(createContext(files, only));
  expectRubric(findings);
  return findings;
};
const byRule = (findings: Finding[], slug: string) =>
  findings.filter((f) => f.ruleId === `authorization/${slug}`);

const SCHEMA = "supabase/migrations/001_schema.sql";
const MIG = "supabase/migrations/002_policies.sql";

const schema = `create table public.orders (
  id uuid primary key,
  org_id uuid not null,
  customer_email text,
  total_cents int
);
create table public.products (id uuid primary key, org_id uuid, name text, is_published bool);
create table public.plans (id uuid primary key, name text, stripe_price_id text);
create table public.notes (id uuid primary key, owner_id uuid, body text);
create table public.files (id uuid primary key, org_id uuid, path text);
create table public.profiles (
  id uuid primary key,
  username text,
  avatar_url text,
  is_platform_admin boolean not null default false
);
create table public.public_profiles (id uuid primary key, email text);
create table public.org_members (
  org_id uuid not null,
  user_id uuid not null,
  role text not null default 'member'
);
create table public.invoices (id uuid primary key, org_id uuid, amount int);
create table public.api_keys (id uuid primary key, org_id uuid, key_hash text);
create table public.leads (id uuid primary key, contact_email text);
create table public.wallets (id uuid primary key, user_id uuid, balance int);
`;
const rls = (...tables: string[]) =>
  tables.map((t) => `alter table public.${t} enable row level security;`).join("\n") + "\n";

describe("SupabasePolicyDetector", () => {
  describe("registration", () => {
    it("is registered in the supabase group with sql as its non-JS kind", () => {
      expect(supabaseDetectors().map((d) => d.id)).toEqual([
        "supabase-policy-detector",
        "firebase-rules-detector",
      ]);
      expect(supabaseNonJsExempt["supabase-policy-detector"]).toEqual(["sql"]);
      expect(
        createDefaultRegistry()
          .getDetectors()
          .map((d) => d.id),
      ).toContain("supabase-policy-detector");
      expect(detector.category).toBe("authorization");
    });

    it("returns nothing without sql files and never throws on garbage", async () => {
      expect(await run({ "a.ts": "create policy p on orders for select using (true);" })).toEqual(
        [],
      );
      const garbage = "create policy ((( on ; grant on to ; create function f( $$ unterminated";
      expect(await run({ [MIG]: garbage })).toEqual([]);
    });
  });

  describe("authorization/supabase-select-using-true", () => {
    it("is critical for a sensitive table readable by anon, anchored on the using line", async () => {
      const findings = await run({
        [SCHEMA]: schema,
        [MIG]:
          rls("orders") +
          `create policy "orders_select" on public.orders\n  for select using (true);\n`,
      });
      const hits = byRule(findings, "supabase-select-using-true");
      expect(hits).toHaveLength(1);
      expect(hits[0]).toMatchObject({
        severity: "critical",
        confidence: "high",
        deployBlocking: true,
        file: MIG,
        line: 3,
      });
      expect(hits[0]!.id).toMatch(/^AUTHZ-[0-9a-f]{10}$/);
      expect(hits[0]!.evidence).toContain("using (true)");
    });

    it("is high when only signed-in users are covered, and critical by sensitive columns", async () => {
      const findings = await run({
        [SCHEMA]: schema,
        [MIG]:
          rls("invoices", "leads") +
          `create policy a on invoices for select to authenticated using (true);\n` +
          `create policy b on leads for select using ((true));\n`,
      });
      const hits = byRule(findings, "supabase-select-using-true");
      expect(hits.map((f) => [f.line, f.severity])).toEqual([
        [3, "high"],
        [4, "critical"],
      ]);
    });

    it("is medium on ordinary or public-profile tables", async () => {
      const findings = await run({
        [SCHEMA]: schema,
        [MIG]:
          rls("files", "profiles") +
          `create policy a on files for select using (true);\ncreate policy b on profiles for select using (true);\n`,
      });
      const hits = byRule(findings, "supabase-select-using-true");
      expect(hits.map((f) => f.severity)).toEqual(["medium", "medium"]);
    });

    it("adds the read exposure for FOR ALL policies only on sensitive tables", async () => {
      const findings = await run({
        [SCHEMA]: schema,
        [MIG]:
          rls("orders", "notes") +
          `create policy a on orders for all using (true);\ncreate policy b on notes for all using (true);\n` +
          `create policy c on files for all using (1 = 1);\n`,
      });
      const hits = byRule(findings, "supabase-select-using-true");
      // notes: the rls detector already reports `for all using (true)`; files: it does
      // not treat `1 = 1` as permissive, so the read exposure is reported here.
      expect(hits.map((f) => [f.line, f.severity])).toEqual([
        [3, "critical"],
        [5, "medium"],
      ]);
      const rlsFindings = await new SupabaseRlsDetector().detect(
        createContext({
          [SCHEMA]: schema,
          [MIG]: rls("notes") + "create policy b on notes for all using (true);",
        }),
      );
      expect(
        rlsFindings.filter((f) => f.ruleId === "authorization/supabase-permissive-policy"),
      ).toHaveLength(1);
    });

    it("treats a table with unknown columns by its name (single-file scan)", async () => {
      const files = {
        [SCHEMA]: schema,
        [MIG]: `create policy p on public.payments for select using (true);\n`,
      };
      const hits = byRule(await run(files, [MIG]), "supabase-select-using-true");
      expect(hits).toHaveLength(1);
      expect(hits[0]!.severity).toBe("critical");
    });

    it("never flags catalog tables, published-row predicates or real conditions", async () => {
      const findings = await run({
        [SCHEMA]: schema,
        [MIG]:
          rls("products", "plans", "orders", "public_profiles") +
          `create policy a on products for select using (true);
create policy b on plans for select using (true);
create policy c on products for select using (is_published or public.is_org_member(org_id));
create policy d on orders for select using (public.is_org_member(org_id));
create policy e on public_profiles for select using (true);
create policy f on orders for select using ('true' = 'true');
`,
      });
      expect(byRule(findings, "supabase-select-using-true")).toEqual([]);
    });

    it("ignores restrictive, service-role, commented-out, string and replaced policies", async () => {
      const findings = await run({
        [SCHEMA]: schema,
        [MIG]:
          rls("orders", "invoices") +
          `create policy a on orders as restrictive for select using (true);
create policy b on orders for select to service_role using (true);
-- create policy c on orders for select using (true);
select 'create policy d on orders for select using (true)';
create policy e on invoices for select using (true);
`,
        "supabase/migrations/003_fix.sql": `drop policy e on public.invoices;\ncreate policy e on invoices for select using (public.is_org_member(org_id));\n`,
      });
      expect(byRule(findings, "supabase-select-using-true")).toEqual([]);
    });

    it("follows alter policy to and from true", async () => {
      const findings = await run({
        [SCHEMA]: schema,
        [MIG]:
          rls("orders", "invoices") +
          `create policy a on orders for select using (true);\ncreate policy b on invoices for select using (public.is_org_member(org_id));\n`,
        "supabase/migrations/003.sql": `alter policy a on orders using (public.is_org_member(org_id));\nalter policy b on invoices using (true);\n`,
      });
      const hits = byRule(findings, "supabase-select-using-true");
      expect(hits).toHaveLength(1);
      expect(hits[0]).toMatchObject({ file: "supabase/migrations/003.sql", line: 2 });
    });

    it("skips sql outside supabase/ when the project does not use Supabase", async () => {
      const findings = await run({
        "db/policies.sql": `create policy a on orders for select using (true);`,
        "src/app.ts": `console.log("hi");`,
      });
      expect(findings).toEqual([]);
      const used = await run({
        "db/policies.sql": `create policy a on orders for select using (true);`,
        "src/app.ts": `import { createClient } from "@supabase/supabase-js";`,
      });
      expect(byRule(used, "supabase-select-using-true")).toHaveLength(1);
    });
  });

  describe("authorization/supabase-grant-to-anon", () => {
    it("is critical for write grants on a known table without RLS", async () => {
      const findings = await run({
        [SCHEMA]: schema,
        "supabase/migrations/003_grants.sql": `grant usage on schema public to anon, authenticated;\ngrant all on table public.api_keys to anon, authenticated;\n`,
      });
      const hits = byRule(findings, "supabase-grant-to-anon");
      expect(hits).toHaveLength(1);
      expect(hits[0]).toMatchObject({ severity: "critical", confidence: "high", line: 2 });
      expect(hits[0]!.title).toContain("public.api_keys");
    });

    it("is critical for select on a sensitive table and high for writes on an unknown table", async () => {
      const findings = await run({
        [SCHEMA]: schema,
        [MIG]: `GRANT SELECT ON TABLE "public"."orders" TO "anon";\ngrant insert on audit_log to public;\n`,
      });
      const hits = byRule(findings, "supabase-grant-to-anon");
      expect(hits.map((f) => [f.line, f.severity, f.confidence])).toEqual([
        [1, "critical", "high"],
        [2, "high", "medium"],
      ]);
    });

    it("is medium for select on an ordinary table without RLS", async () => {
      const findings = await run({ [SCHEMA]: schema, [MIG]: `grant select on notes to anon;` });
      expect(byRule(findings, "supabase-grant-to-anon").map((f) => f.severity)).toEqual(["medium"]);
    });

    it("reports a blanket grant on all tables when some have no RLS", async () => {
      const findings = await run({
        [SCHEMA]: schema,
        [MIG]: `grant all on all tables in schema public to anon;`,
      });
      const hits = byRule(findings, "supabase-grant-to-anon");
      expect(hits).toHaveLength(1);
      expect(hits[0]!.severity).toBe("high");
    });

    it("stays silent for catalog tables, schema usage, RLS-protected tables and authenticated-only grants", async () => {
      const findings = await run({
        [SCHEMA]: schema,
        [MIG]: `grant usage on schema public to anon;
grant select on public.products to anon;
grant all on table public.orders to anon, authenticated;
grant all on table public.notes to authenticated;
grant select on unknown_lookup to anon;
grant execute on function public.f() to anon;
-- grant all on table public.api_keys to anon;
`,
        "supabase/migrations/004_rls.sql": rls("orders"),
      });
      expect(byRule(findings, "supabase-grant-to-anon")).toEqual([]);
    });

    it("forgets grants that are revoked or whose table is dropped", async () => {
      const findings = await run({
        [SCHEMA]: schema,
        [MIG]: `grant all on api_keys to anon;\ngrant select on leads to anon;\n`,
        "supabase/migrations/003.sql": `revoke all on table public.api_keys from anon;\ndrop table leads;\n`,
      });
      expect(byRule(findings, "supabase-grant-to-anon")).toEqual([]);
    });
  });

  describe("authorization/supabase-security-definer-no-search-path", () => {
    const fn = (opts: string, body = "select 1") =>
      `create or replace function public.do_thing(x uuid)\nreturns void\nlanguage sql\n${opts}\nas $$ ${body} $$;\n`;

    it("flags a definer function without search_path on the security definer line", async () => {
      const findings = await run({ [MIG]: fn("security definer") });
      const hits = byRule(findings, "supabase-security-definer-no-search-path");
      expect(hits).toHaveLength(1);
      expect(hits[0]).toMatchObject({ severity: "high", confidence: "high", line: 4, endLine: 5 });
      expect(hits[0]!.title).toContain("public.do_thing");
    });

    it("is medium for trigger functions and flags functions granted from another schema", async () => {
      const findings = await run({
        [MIG]: `create function public.on_signup() returns trigger language plpgsql security definer as $$ begin return new; end $$;
create function private.helper() returns void language sql security definer as $$ select 1 $$;
grant execute on function private.helper() to authenticated;
`,
      });
      const hits = byRule(findings, "supabase-security-definer-no-search-path");
      expect(hits.map((f) => [f.line, f.severity])).toEqual([
        [1, "medium"],
        [2, "high"],
      ]);
    });

    it("accepts a pinned search_path, a later alter function, or security invoker", async () => {
      const findings = await run({
        [MIG]:
          fn("security definer set search_path = ''") +
          `create function public.b() returns void language sql security definer as $$ select 1 $$;
create function public.c() returns void language sql security definer as $$ select 1 $$;
create function public.d() returns void language sql security invoker as $$ select 1 $$;
`,
        "supabase/migrations/003.sql": `alter function public.b() set search_path = public;\nalter function public.c() security invoker;\n`,
      });
      expect(byRule(findings, "supabase-security-definer-no-search-path")).toEqual([]);
    });

    it("is not fixed by an alter function that runs before the definition", async () => {
      const findings = await run({
        "supabase/migrations/001.sql": `alter function public.b() set search_path = public;`,
        "supabase/migrations/002.sql": `create or replace function public.b() returns void language sql security definer as $$ select 1 $$;`,
      });
      expect(byRule(findings, "supabase-security-definer-no-search-path")).toHaveLength(1);
    });

    it("skips functions the API roles cannot execute, and commented-out definitions", async () => {
      const findings = await run({
        [MIG]: `create function public.a() returns void language sql security definer as $$ select 1 $$;
revoke all on function public.a() from public, anon, authenticated;
grant execute on function public.a() to service_role;
create function private.b() returns void language sql security definer as $$ select 1 $$;
/* create function public.c() returns void language sql security definer as $$ select 1 $$; */
`,
      });
      expect(byRule(findings, "supabase-security-definer-no-search-path")).toEqual([]);
    });
  });

  describe("authorization/supabase-definer-missing-caller-check", () => {
    const definer = (name: string, body: string, extra = "") =>
      `create or replace function public.${name}(target_org uuid, target_user uuid, new_role text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
${body}
end;
$$;
${extra}`;

    it("flags a role change without a caller check", async () => {
      const findings = await run({
        [MIG]: definer(
          "set_member_role",
          "  update org_members\n     set role = new_role\n   where org_id = target_org and user_id = target_user;",
          "grant execute on function public.set_member_role(uuid, uuid, text) to authenticated;\n",
        ),
      });
      const hits = byRule(findings, "supabase-definer-missing-caller-check");
      expect(hits).toHaveLength(1);
      expect(hits[0]).toMatchObject({ severity: "high", confidence: "medium", line: 4 });
      expect(hits[0]!.plainEnglishProblem).toContain("authenticated");
      expect(byRule(findings, "supabase-security-definer-no-search-path")).toEqual([]);
    });

    it("flags membership inserts and balance or credit updates", async () => {
      const findings = await run({
        [MIG]:
          definer(
            "join_team",
            "  insert into public.team_members (team_id, user_id) values (target_org, target_user);",
          ) +
          definer(
            "add_credits",
            "  update wallets w set balance = balance + 100 where w.user_id = target_user;",
          ),
      });
      expect(byRule(findings, "supabase-definer-missing-caller-check")).toHaveLength(2);
    });

    it("accepts auth.uid(), jwt and helper checks, and ignores non-privileged writes", async () => {
      const findings = await run({
        [MIG]:
          definer(
            "a",
            "  if not exists (select 1 from org_members where org_id = target_org and user_id = auth.uid() and role = 'owner') then raise exception 'no'; end if;\n  update org_members set role = new_role where org_id = target_org;",
          ) +
          definer(
            "b",
            "  if not public.is_org_admin(target_org) then raise exception 'no'; end if;\n  update org_members set role = new_role;",
          ) +
          definer(
            "c",
            "  if current_setting('request.jwt.claims', true)::json->>'role' <> 'admin' then raise exception 'no'; end if;\n  update profiles set is_admin = true;",
          ) +
          definer("d", "  update profiles set last_seen_at = now() where id = target_user;") +
          definer("e", "  -- update org_members set role = new_role;\n  perform 1;"),
      });
      expect(byRule(findings, "supabase-definer-missing-caller-check")).toEqual([]);
    });

    it("skips trigger functions and functions the API cannot call", async () => {
      const findings = await run({
        [MIG]: `create function public.on_signup() returns trigger language plpgsql security definer set search_path = public as $$
begin insert into public.org_members (org_id, user_id, role) values (new.id, new.id, 'owner'); return new; end $$;
create function public.admin_set_role(u uuid) returns void language sql security definer set search_path = public as $$ update profiles set role = 'admin' where id = u $$;
revoke execute on function public.admin_set_role(uuid) from public, anon, authenticated;
`,
      });
      expect(byRule(findings, "supabase-definer-missing-caller-check")).toEqual([]);
    });
  });

  describe("authorization/supabase-self-referential-policy", () => {
    it("flags a subquery comparing the subquery table's column with itself, at that line", async () => {
      const findings = await run({
        [SCHEMA]: schema,
        [MIG]:
          rls("invoices") +
          `create policy "invoices_select_member" on public.invoices
  for select to authenticated using (
    exists (
      select 1 from public.org_members
      where org_members.org_id = org_id
        and org_members.user_id = auth.uid()
    )
  );
`,
      });
      const hits = byRule(findings, "supabase-self-referential-policy");
      expect(hits).toHaveLength(1);
      expect(hits[0]).toMatchObject({ severity: "high", confidence: "high", line: 6 });
      expect(hits[0]!.evidence).toContain("org_members.org_id = org_id");
    });

    it("flags t.c = t.c and is medium confidence when columns are unknown", async () => {
      const findings = await run({
        [MIG]: `create policy a on projects for update using (projects.owner_id = projects.owner_id);
create policy b on tasks for select using (exists (select 1 from team_members tm where tm.team_id = team_id and tm.user_id = auth.uid()));
`,
      });
      const hits = byRule(findings, "supabase-self-referential-policy");
      expect(hits.map((f) => [f.line, f.confidence])).toEqual([
        [1, "high"],
        [2, "medium"],
      ]);
    });

    it("never flags correctly qualified, outward-resolving or commented comparisons", async () => {
      const findings = await run({
        [SCHEMA]: schema,
        [MIG]: `create policy a on invoices for select using (exists (select 1 from org_members where org_members.org_id = invoices.org_id and org_members.user_id = auth.uid()));
create policy b on invoices for select using (exists (select 1 from org_members m where m.org_id = invoices.org_id));
create policy c on invoices for select using (exists (select 1 from org_members m where m.user_id = id));
-- create policy d on invoices for select using (org_id = org_id);
create policy e on invoices for select using (auth.uid() = (select user_id from org_members where org_members.org_id = invoices.org_id limit 1));
`,
      });
      expect(byRule(findings, "supabase-self-referential-policy")).toEqual([]);
    });
  });

  describe("authorization/supabase-policy-self-promotion", () => {
    it("flags an update policy that only checks ownership on a table with an admin flag", async () => {
      const findings = await run({
        [SCHEMA]: schema,
        [MIG]:
          rls("profiles") +
          `create policy "profiles_update_own" on public.profiles\n  for update using (auth.uid() = id);\n`,
      });
      const hits = byRule(findings, "supabase-policy-self-promotion");
      expect(hits).toHaveLength(1);
      expect(hits[0]).toMatchObject({ severity: "high", confidence: "medium", line: 3 });
      expect(hits[0]!.title).toContain("is_platform_admin");
    });

    it("flags self-insert into a membership table and FOR ALL owner policies on balances", async () => {
      const findings = await run({
        [SCHEMA]: schema,
        [MIG]:
          rls("org_members", "wallets") +
          `create policy "members_insert_self" on public.org_members
  for insert to authenticated with check (user_id = auth.uid());
create policy w on wallets for all using ((select auth.uid()) = user_id) with check ((select auth.uid()) = wallets.user_id);
`,
      });
      const hits = byRule(findings, "supabase-policy-self-promotion");
      expect(hits.map((f) => f.line)).toEqual([4, 5]);
    });

    it("stays silent when the check constrains the privileged column or delegates to a helper", async () => {
      const findings = await run({
        [SCHEMA]: schema,
        [MIG]:
          rls("org_members", "profiles") +
          `create policy a on org_members for insert with check (user_id = auth.uid() and role = 'member');
create policy b on org_members for update using (public.is_org_admin(org_id)) with check (public.is_org_admin(org_id));
create policy c on profiles for update using (auth.uid() = id) with check (auth.uid() = id and is_platform_admin = false);
create policy d on org_members for insert to authenticated with check (true);
-- create policy e on org_members for insert with check (user_id = auth.uid());
`,
      });
      expect(byRule(findings, "supabase-policy-self-promotion")).toEqual([]);
    });

    it("stays silent for tables without privilege columns, without RLS, or with unknown columns", async () => {
      const files = {
        [SCHEMA]: schema,
        [MIG]:
          rls("notes") +
          `create policy a on notes for update using (auth.uid() = owner_id);
create policy b on wallets for update using (auth.uid() = user_id);
create policy c on accounts for update using (auth.uid() = user_id);
`,
      };
      expect(byRule(await run(files), "supabase-policy-self-promotion")).toEqual([]);
      const single = {
        [SCHEMA]: schema,
        [MIG]: rls("profiles") + `create policy p on profiles for update using (auth.uid() = id);`,
      };
      expect(byRule(await run(single, [MIG]), "supabase-policy-self-promotion")).toEqual([]);
    });

    it("respects column privileges and guard triggers, but not unrelated triggers", async () => {
      const base =
        rls("profiles") + `create policy p on profiles for update using (auth.uid() = id);\n`;
      const columnGrant = await run({
        [SCHEMA]: schema,
        [MIG]:
          base +
          `revoke update on table public.profiles from authenticated;\ngrant update (username, avatar_url) on public.profiles to authenticated;\n`,
      });
      expect(byRule(columnGrant, "supabase-policy-self-promotion")).toEqual([]);
      const guard = await run({
        [SCHEMA]: schema,
        [MIG]:
          base +
          `create function public.protect_admin() returns trigger language plpgsql set search_path = public as $$
begin if new.is_platform_admin is distinct from old.is_platform_admin then raise exception 'no'; end if; return new; end $$;
create trigger protect before update on public.profiles for each row execute function public.protect_admin();
`,
      });
      expect(byRule(guard, "supabase-policy-self-promotion")).toEqual([]);
      const unrelated = await run({
        [SCHEMA]: schema,
        [MIG]:
          base +
          `create trigger touch before update on public.profiles for each row execute procedure moddatetime(updated_at);\n`,
      });
      expect(byRule(unrelated, "supabase-policy-self-promotion")).toHaveLength(1);
    });

    it("does not re-report a policy the rls detector flags as with check (true)", async () => {
      const files = {
        [SCHEMA]: schema,
        [MIG]:
          rls("org_members") +
          `create policy p on org_members for insert to authenticated with check (true);\n`,
      };
      const rlsFindings = await new SupabaseRlsDetector().detect(createContext(files));
      expect(rlsFindings.map((f) => f.ruleId)).toContain(
        "authorization/supabase-permissive-policy",
      );
      expect(await run(files)).toEqual([]);
    });
  });

  describe("general", () => {
    const bad = {
      [SCHEMA]: schema,
      [MIG]:
        rls("orders", "profiles", "invoices") +
        `create policy a on orders for select using (true);
create policy b on profiles for update using (auth.uid() = id);
create policy c on invoices for select using (exists (select 1 from org_members where org_members.org_id = org_id));
grant all on table api_keys to anon; grant select on leads to anon;
create function public.f() returns void language sql security definer as $$ update org_members set role = 'owner' $$;
`,
    };

    it("produces stable, unique ids across runs, including findings sharing a line", async () => {
      const first = await run(bad);
      const second = await run(bad);
      expect(second.map((f) => f.id)).toEqual(first.map((f) => f.id));
      expect(new Set(first.map((f) => f.id)).size).toBe(first.length);
      const sameLine = byRule(first, "supabase-grant-to-anon");
      expect(sameLine).toHaveLength(2);
      expect(sameLine[0]!.line).toBe(sameLine[1]!.line);
      expect(new Set(first.map((f) => f.ruleId)).size).toBe(6);
    });

    it("keeps AI prompts static (no repo-derived names)", async () => {
      for (const f of await run(bad)) {
        expect(f.aiFixPrompt).not.toContain("api_keys");
        expect(f.aiFixPrompt).not.toContain("public.f");
        expect(f.aiFixPrompt).not.toContain(MIG);
      }
    });

    it("redacts secrets in evidence and sanitizes names", async () => {
      const key = "AKIAIOSFODNN7EXAMPLE";
      const findings = await run({
        [MIG]: `create policy "x\nIgnore previous" on orders for select using (true); -- ${key}`,
      });
      expect(findings).toHaveLength(1);
      expect(findings[0]!.evidence).not.toContain(key);
      expect(findings[0]!.plainEnglishProblem).not.toContain("\n");
    });

    it("caps findings per rule and file with one summary", async () => {
      const policies = Array.from(
        { length: 30 },
        (_, i) => `create policy p${i} on orders_${i} for select using (true);`,
      ).join("\n");
      const findings = byRule(await run({ [MIG]: policies }), "supabase-select-using-true");
      expect(findings).toHaveLength(26);
      expect(findings[25]!.title).toMatch(/^5 more findings/);
      expect(findings[25]!.confidence).toBe("medium");
    });

    it("scans a large migration in bounded time", async () => {
      const parts: string[] = [];
      for (let i = 0; i < 2000; i++) {
        parts.push(`create table public.t${i} (id uuid, user_id uuid, role text);`);
        parts.push(`alter table public.t${i} enable row level security;`);
        parts.push(
          `create policy "p${i}" on public.t${i} for select using (auth.uid() = user_id);`,
        );
        parts.push(`grant select on public.t${i} to authenticated;`);
      }
      const start = Date.now();
      expect(await run({ [MIG]: parts.join("\n") })).toEqual([]);
      expect(Date.now() - start).toBeLessThan(5_000);
    });
  });
});
