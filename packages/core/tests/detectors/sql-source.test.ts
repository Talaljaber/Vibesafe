import { describe, it, expect } from "vitest";
import {
  createLineLocator,
  extractEqualities,
  functionSearchPathFixes,
  isAfter,
  isAlwaysTrueExpr,
  parseAlterFunction,
  parseAlterTable,
  parseCreateFunction,
  parseCreateTable,
  parseGrant,
  parsePolicy,
  qualifiedKey,
  splitSqlStatements,
  splitTopLevelAnd,
  stripSqlNoise,
  type QualifiedName,
} from "../../src/detectors/utils/sql-source.js";
import { stripSqlNoise as reexported } from "../../src/detectors/supabase-rls-detector.js";

const one = (sql: string) => {
  const stmts = splitSqlStatements(sql);
  expect(stmts).toHaveLength(1);
  return stmts[0]!;
};

describe("stripSqlNoise", () => {
  it("is re-exported unchanged from the rls detector", () => {
    expect(reexported).toBe(stripSqlNoise);
  });

  it("preserves length and newlines and blanks comments, strings and dollar bodies", () => {
    const src = "a -- c\n'x\ny' /* z /* n */\n*/ $q$ body\n $q$ \"id;\" b";
    const out = stripSqlNoise(src);
    expect(out).toHaveLength(src.length);
    expect(out.split("\n")).toHaveLength(src.split("\n").length);
    expect(out).toContain('"id;"');
    for (const hidden of ["body", "x", "z", "c\n"]) expect(out).not.toContain(hidden);
    expect(out.startsWith("a ")).toBe(true);
    expect(out.trimEnd().endsWith("b")).toBe(true);
  });

  it("honours backslash escapes in E'' strings only", () => {
    const e = stripSqlNoise("select E'it\\'s; ok', 'a''b';");
    expect(e).not.toContain("ok");
    expect(e).not.toContain("s;");
    const plain = stripSqlNoise("select 'a\\', b;");
    expect(plain).toContain(" b;");
  });

  it("does not treat positional parameters as dollar quotes", () => {
    expect(stripSqlNoise("select $1, $2 from t")).toBe("select $1, $2 from t");
  });
});

describe("splitSqlStatements", () => {
  it("splits at top-level semicolons and keeps a final statement without one", () => {
    const sql = "create table a (id int);\n\nselect 1;\nselect 2";
    const s = splitSqlStatements(sql);
    expect(s.map((x) => x.text)).toEqual(["create table a (id int)", "select 1", "select 2"]);
    expect(sql.slice(s[1]!.start, s[1]!.end)).toBe("select 1");
    expect(s[0]!.code).toHaveLength(s[0]!.text.length);
  });

  it("ignores semicolons inside strings, E'' escapes, quoted identifiers and comments", () => {
    const sql = [
      "insert into t values ('a;b', E'c\\';d', \"we;ird\");",
      "-- comment; here",
      "/* block; /* nested; */ still; */ select 2;",
    ].join("\n");
    const s = splitSqlStatements(sql);
    expect(s).toHaveLength(2);
    expect(s[1]!.text).toBe("select 2");
  });

  it("keeps dollar-quoted function bodies and BEGIN ATOMIC bodies in one statement", () => {
    const sql = `create function f() returns int language plpgsql as $fn$
begin
  perform 1; return 2;
end;
$fn$;
create function g() returns int language sql
begin atomic
  select case when true then 1 else 2 end;
  select 3;
end;
select 4;`;
    const s = splitSqlStatements(sql);
    expect(s).toHaveLength(3);
    expect(s[1]!.text).toMatch(/^create function g[\s\S]*end$/);
    expect(s[2]!.text).toBe("select 4");
  });

  it("skips COPY ... FROM stdin data and psql meta-commands", () => {
    const sql = [
      "\\set ON_ERROR_STOP on",
      "COPY public.t (a, b) FROM stdin;",
      "1\tit's; weird $$",
      "2\t-- not a comment",
      "\\.",
      "\\connect app",
      "create table x (id int);",
    ].join("\n");
    const s = splitSqlStatements(sql);
    expect(s.map((x) => x.text)).toEqual([
      "COPY public.t (a, b) FROM stdin",
      "create table x (id int)",
    ]);
  });

  it("ignores semicolons inside parentheses", () => {
    expect(splitSqlStatements("select (1;2); select 3;")).toHaveLength(2);
  });

  it("returns nothing for empty or comment-only input", () => {
    expect(splitSqlStatements("")).toEqual([]);
    expect(splitSqlStatements("-- only\n/* c */\n")).toEqual([]);
  });
});

describe("createLineLocator", () => {
  it("maps offsets to 1-based lines", () => {
    const locate = createLineLocator("a\nbb\nccc");
    expect(locate(0)).toBe(1);
    expect(locate(2)).toBe(2);
    expect(locate(5)).toBe(3);
  });
});

describe("parsePolicy", () => {
  it("parses clauses in any order with quoted names, roles and nested parens", () => {
    const p = parsePolicy(
      one(
        `CREATE POLICY "Read own" ON "public"."Orders" AS PERMISSIVE FOR SELECT TO "anon", authenticated USING ((auth.uid() = user_id)) WITH CHECK (true);`,
      ),
    )!;
    expect(p.op).toBe("create");
    expect(p.name).toBe("Read own");
    expect(p.table).toEqual({ schema: "public", name: "Orders" });
    expect(p.restrictive).toBe(false);
    expect(p.cmd).toBe("select");
    expect(p.roles).toEqual(["anon", "authenticated"]);
    expect(p.using!.expr).toBe("(auth.uid() = user_id)");
    expect(p.check!.expr).toBe("true");
  });

  it("parses alter, rename and drop", () => {
    expect(parsePolicy(one("alter policy p on t using (true)"))!.using!.expr).toBe("true");
    const r = parsePolicy(one(`alter policy p on t rename to "new name"`))!;
    expect(r.op).toBe("rename");
    expect(r.newName).toBe("new name");
    expect(parsePolicy(one("drop policy if exists p on public.t"))!.op).toBe("drop");
  });

  it("returns null for other statements", () => {
    expect(parsePolicy(one("create table policy (id int)"))).toBeNull();
    expect(parsePolicy(one("select 'create policy p on t'"))).toBeNull();
  });
});

describe("parseGrant", () => {
  it("parses table grants with several objects and grantees", () => {
    const g = parseGrant(
      one('grant select, insert on table public.a, b to anon, "authenticated";'),
    )!;
    expect(g.action).toBe("grant");
    expect(g.privileges).toEqual(["select", "insert"]);
    expect(g.targetType).toBe("table");
    expect(g.objects).toEqual([
      { schema: "public", name: "a" },
      { schema: undefined, name: "b" },
    ]);
    expect(g.grantees).toEqual(["anon", "authenticated"]);
  });

  it("parses all privileges, column grants, revokes and function grants", () => {
    expect(parseGrant(one("GRANT ALL PRIVILEGES ON t TO public"))!.privileges).toEqual(["all"]);
    const col = parseGrant(one("grant update (name, avatar_url) on profiles to authenticated"))!;
    expect(col.columnLevel).toBe(true);
    expect(col.privileges).toEqual(["update"]);
    const rev = parseGrant(one("revoke all on function public.f(uuid, text) from public, anon"))!;
    expect(rev.action).toBe("revoke");
    expect(rev.targetType).toBe("function");
    expect(rev.objects).toEqual([{ schema: "public", name: "f" }]);
    expect(rev.grantees).toEqual(["public", "anon"]);
    const all = parseGrant(one("grant all on all tables in schema public to anon"))!;
    expect(all.targetType).toBe("all-tables");
    expect(all.objects).toEqual([{ schema: undefined, name: "public" }]);
  });

  it("classifies schema grants and ignores role membership grants", () => {
    expect(parseGrant(one("grant usage on schema public to anon"))!.targetType).toBe("schema");
    expect(parseGrant(one("grant admin_role to bob"))).toBeNull();
    expect(parseGrant(one("grant select on tokens to anon with grant option"))!.grantees).toEqual([
      "anon",
    ]);
  });
});

describe("parseCreateFunction", () => {
  it("reads security definer, search_path and the dollar-quoted body", () => {
    const f = parseCreateFunction(
      one(`create or replace function public.f(a uuid default null) returns void
language plpgsql security definer set search_path = '' as $$ begin update t set role = 'x'; end $$;`),
    )!;
    expect(f.fn).toEqual({ schema: "public", name: "f" });
    expect(f.securityDefiner).toBe(true);
    expect(f.searchPath).toBe(true);
    expect(f.returnsTrigger).toBe(false);
    expect(f.body).toContain("update t set role");
  });

  it("handles pg_dump quoting, options after the body and trigger functions", () => {
    const f = parseCreateFunction(
      one(
        `CREATE FUNCTION "public"."h"() RETURNS "trigger" LANGUAGE "plpgsql" SECURITY DEFINER SET "search_path" TO 'public' AS $_$ begin return new; end $_$;`,
      ),
    )!;
    expect(f.searchPath).toBe(true);
    expect(f.returnsTrigger).toBe(true);
    const g = parseCreateFunction(
      one(`create function g() returns int as 'select 1' language sql security definer;`),
    )!;
    expect(g.body).toBe("select 1");
    expect(g.securityDefiner).toBe(true);
    expect(g.searchPath).toBe(false);
  });

  it("does not read security definer or search_path from inside the body", () => {
    const f = parseCreateFunction(
      one(`create function f() returns void as $$ -- security definer
 select set_config('search_path', 'x', true); $$ language sql;`),
    )!;
    expect(f.securityDefiner).toBe(false);
    expect(f.searchPath).toBe(false);
  });

  it("reads BEGIN ATOMIC bodies", () => {
    const f = parseCreateFunction(
      one(
        "create function f() returns int language sql security definer begin atomic select 1; end;",
      ),
    )!;
    expect(f.body).toMatch(/^begin atomic/);
  });
});

describe("parseAlterFunction and functionSearchPathFixes", () => {
  it("parses set/reset search_path, security and rename", () => {
    expect(
      parseAlterFunction(one("alter function public.f(uuid) set search_path = public")),
    ).toEqual({
      fn: { schema: "public", name: "f" },
      searchPath: true,
      security: undefined,
      renameTo: undefined,
    });
    expect(parseAlterFunction(one("alter function f reset search_path"))!.searchPath).toBe(false);
    expect(parseAlterFunction(one("alter function f() security invoker"))!.security).toBe(
      "invoker",
    );
    expect(
      parseAlterFunction(one("alter function f() owner to postgres"))!.searchPath,
    ).toBeUndefined();
  });

  it("tracks the last effective fix across files sorted by name", () => {
    const files = [
      {
        file: "b.sql",
        statements: splitSqlStatements("alter function public.f() reset search_path;"),
      },
      {
        file: "a.sql",
        statements: splitSqlStatements(
          "select 1; alter function f() set search_path = '';\nalter function g() set search_path = '';",
        ),
      },
    ];
    const fixes = functionSearchPathFixes(files);
    expect(fixes.has("public.f")).toBe(false);
    expect(fixes.get("public.g")).toEqual({ file: "a.sql", fileIndex: 0, index: 2 });
    expect(
      isAfter({ file: "b", fileIndex: 1, index: 0 }, { file: "a", fileIndex: 0, index: 9 }),
    ).toBe(true);
    expect(
      isAfter({ file: "a", fileIndex: 0, index: 1 }, { file: "a", fileIndex: 0, index: 1 }),
    ).toBe(false);
  });
});

describe("parseCreateTable and parseAlterTable", () => {
  it("collects column names and skips table constraints", () => {
    const t = parseCreateTable(
      one(`create table if not exists public.org_members (
  org_id uuid references orgs (id),
  "Role" text check (role in ('a', 'b')),
  primary key (org_id),
  constraint c unique (org_id)
);`),
    )!;
    expect(t.table).toEqual({ schema: "public", name: "org_members" });
    expect(t.ifNotExists).toBe(true);
    expect(t.columns).toEqual(["org_id", "Role"]);
  });

  it("flags partitions and temp tables", () => {
    expect(
      parseCreateTable(one("create table e2 partition of e for values in (1)"))!.partition,
    ).toBe(true);
    expect(parseCreateTable(one("create temp table s (id int)"))!.temporary).toBe(true);
  });

  it("parses rls, add/drop/rename column and table rename", () => {
    const a = parseAlterTable(
      one(
        "alter table only public.t enable row level security, add column if not exists is_admin bool, drop column old",
      ),
    )!;
    expect(a.rls).toBe("enable");
    expect(a.addColumns).toEqual(["is_admin"]);
    expect(a.dropColumns).toEqual(["old"]);
    expect(parseAlterTable(one("alter table t rename column a to b"))!.renameColumn).toEqual({
      from: "a",
      to: "b",
    });
    expect(parseAlterTable(one("alter table t rename to u"))!.renameTo).toBe("u");
  });
});

describe("extractEqualities", () => {
  const cols: Record<string, string[]> = {
    "public.invoices": ["id", "org_id"],
    "public.org_members": ["org_id", "user_id", "role"],
  };
  const lookup = (q: QualifiedName) => cols[qualifiedKey(q)];
  const invoices = { schema: "public", name: "invoices" };
  const same = (expr: string, table: QualifiedName = invoices, l = lookup) =>
    extractEqualities(expr, table, l).filter((e) => e.sameColumn);

  it("finds an unqualified column that resolves to the subquery's own table", () => {
    const expr = `exists (select 1 from public.org_members where org_members.org_id = org_id and org_members.user_id = auth.uid())`;
    const hits = same(expr);
    expect(hits).toHaveLength(1);
    expect(hits[0]!.certain).toBe(true);
    expect(expr.slice(hits[0]!.offset)).toMatch(/^org_members\.org_id = org_id/);
  });

  it("finds t.c = t.c and c = c and alias self-comparisons", () => {
    expect(same("invoices.org_id = invoices.org_id")).toHaveLength(1);
    expect(same("org_id = org_id")).toHaveLength(1);
    expect(same("exists (select 1 from org_members m where m.org_id = org_id)")).toHaveLength(1);
  });

  it("never matches fully qualified cross-table comparisons", () => {
    expect(
      same("exists (select 1 from org_members where org_members.org_id = invoices.org_id)"),
    ).toEqual([]);
    expect(same("exists (select 1 from org_members m where m.org_id = invoices.org_id)")).toEqual(
      [],
    );
  });

  it("resolves outward when the subquery table lacks the column", () => {
    expect(same("exists (select 1 from org_members m where m.user_id = id)")).toEqual([]);
  });

  it("does not confuse two aliases of the same table or function calls", () => {
    expect(
      same("exists (select 1 from org_members a join org_members b on a.org_id = b.org_id)"),
    ).toEqual([]);
    expect(same("auth.uid() = user_id")).toEqual([]);
    expect(same("lower(org_id) = org_id")).toEqual([]);
    expect(same("x + org_id = org_id")).toEqual([]);
  });

  it("marks resolutions through tables with unknown columns as uncertain", () => {
    const hits = same(
      "exists (select 1 from team_members where team_members.team_id = team_id)",
      { schema: undefined, name: "projects" },
      () => undefined,
    );
    expect(hits).toHaveLength(1);
    expect(hits[0]!.certain).toBe(false);
  });

  it("binds derived-table aliases and keeps parsing the outer FROM after them", () => {
    const aliased = same(
      "exists (select 1 from (select org_id from org_members) s where s.org_id = org_id)",
    );
    expect(aliased).toHaveLength(1);
    expect(aliased[0]!.certain).toBe(false);
    // `m` comes after the derived table; the derived table's columns are unknown,
    // so the match is reported as uncertain.
    const after = same(
      "exists (select 1 from (select org_id from org_members) s, org_members m where m.org_id = org_id)",
    );
    expect(after).toHaveLength(1);
    expect(after[0]!.certain).toBe(false);
    expect(
      same(
        "exists (select 1 from (select org_id from org_members) s, org_members m where m.org_id = s.org_id)",
      ),
    ).toEqual([]);
  });
});

describe("small helpers", () => {
  it("isAlwaysTrueExpr", () => {
    expect(isAlwaysTrueExpr(" ( (TRUE) ) ")).toBe(true);
    expect(isAlwaysTrueExpr("1 = 1")).toBe(true);
    expect(isAlwaysTrueExpr("(true) and (x)")).toBe(false);
    expect(isAlwaysTrueExpr("is_published = true")).toBe(false);
    expect(isAlwaysTrueExpr(undefined)).toBe(false);
  });

  it("splitTopLevelAnd", () => {
    expect(splitTopLevelAnd("a = 1 and (b = 2 and c = 3) AND band = 4")).toEqual([
      "a = 1",
      "(b = 2 and c = 3)",
      "band = 4",
    ]);
  });
});
