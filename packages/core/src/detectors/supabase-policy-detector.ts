// ─────────────────────────────────────────────────────────────────────────────
// Supabase Policy, Grant and Function Detector
//
// Replays SQL migrations in file-name order (tables, columns, row level
// security, policies, grants, functions, triggers) and flags, on the final
// state:
//   - permissive SELECT policies that are just `using (true)`
//   - table privileges granted to `anon` / PUBLIC on tables without RLS
//   - SECURITY DEFINER functions without a pinned search_path
//   - SECURITY DEFINER functions that change roles / memberships without
//     checking the caller
//   - policy comparisons of a column with itself (always true)
//   - insert / update policies on tables with privilege columns whose check
//     only ties the row to its owner (users can promote themselves)
// The write-side `using (true)` / `with check (true)` policies and missing RLS
// stay with the supabase-rls detector; this detector never re-reports them.
// ─────────────────────────────────────────────────────────────────────────────

import type {
  Confidence,
  Detector,
  Finding,
  ScanContext,
  Severity,
} from "@talaljaber/vibesafe-shared";
import { makeFinding } from "./utils/finding.js";
import { detectSupabaseUsage } from "./supabase-rls-detector.js";
import {
  SQL_IDENT,
  createLineLocator,
  extractEqualities,
  functionSearchPathFixes,
  isAfter,
  isAlwaysTrueExpr,
  normalizeSqlIdent,
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
  type PolicyCommand,
  type QualifiedName,
  type SqlFileStatements,
  type SqlPosition,
  type SqlStatement,
} from "./utils/sql-source.js";

const MAX_NAME = 63;
const MAX_PER_RULE_FILE = 25;
const API_ROLES = new Set(["public", "anon", "authenticated"]);
const ANON_ROLES = new Set(["public", "anon"]);
const WRITE_PRIVS = ["insert", "update", "delete", "truncate"];
const ALL_TABLE_PRIVS = [
  "select",
  "insert",
  "update",
  "delete",
  "truncate",
  "references",
  "trigger",
];

/** Reference / catalog tables that are public by design. */
const CATALOG_TABLES = new Set([
  "product",
  "products",
  "plan",
  "plans",
  "price",
  "prices",
  "pricing",
  "category",
  "categories",
  "tag",
  "tags",
  "country",
  "countries",
  "currency",
  "currencies",
  "language",
  "languages",
  "faq",
  "faqs",
  "feature",
  "features",
  "announcement",
  "announcements",
]);
const CATALOG_PREFIX_RE = /^(?:products?|public|catalog)_/;
/** Table-name segments that always mean tenant or financial data. */
const SENSITIVE_SEGMENTS = new Set([
  "order",
  "orders",
  "invoice",
  "invoices",
  "payment",
  "payments",
  "message",
  "messages",
  "subscription",
  "subscriptions",
  "customer",
  "customers",
  "secret",
  "secrets",
  "token",
  "tokens",
  "credential",
  "credentials",
  "transaction",
  "transactions",
  "payout",
  "payouts",
  "billing",
]);
/** Person tables: sensitive unless their known columns hold nothing private. */
const PERSON_SEGMENTS = new Set(["user", "users", "profile", "profiles", "member", "members"]);
const SENSITIVE_COLUMN_RE =
  /^(?:.*_)?(?:e_?mail|phone|mobile|address|token|key|secret|password|passwd|ssn|iban|dob)(?:_.*)?$|^(?:stripe|customer)_/;
/** Columns that grant power: roles, admin flags, plans, money. */
const PRIVILEGE_COLUMN_RE =
  /^(?:role|roles|user_role|is_admin|admin|is_[a-z0-9_]*admin|is_superuser|superuser|is_staff|permissions?|plan|tier|credits?|balance|subscription_(?:tier|plan|status))$/;
const MEMBERSHIP_TABLE_RE = /(?:^|_)(?:members?|memberships?|roles?|admins?|permissions?)$/;
const CALLER_CHECK_RE =
  /\bauth\s*\.\s*(?:uid|jwt|role|email)\s*\(|\b(?:current_user|session_user|current_role)\b|\b(?:is|has|check|assert|require|ensure|can)_\w*(?:admin|owner|role|permission|member|access|manager)\w*\s*\(/i;
const JWT_SETTING_RE = /current_setting\s*\(\s*'request\.jwt/i;

const QUAL = String.raw`(?:(${SQL_IDENT})\s*\.\s*)?(${SQL_IDENT})`;
const TRIGGER_RE = new RegExp(
  String.raw`^create\s+(?:or\s+replace\s+)?(?:constraint\s+)?trigger\s+${SQL_IDENT}\s+(?:before|after|instead\s+of)\s+([\w\s,]{1,200}?)\s+on\s+${QUAL}[\s\S]{0,600}?\bexecute\s+(?:function|procedure)\s+${QUAL}`,
  "i",
);
const DROP_TABLE_RE = /^drop\s+table\s+(?:if\s+exists\s+)?/i;
const DROP_FUNCTION_RE = new RegExp(
  String.raw`^drop\s+(?:function|procedure|routine)\s+(?:if\s+exists\s+)?${QUAL}`,
  "i",
);
const UPDATE_RE = new RegExp(
  String.raw`\bupdate\s+(?:only\s+)?${QUAL}(?:\s+(?:as\s+)?${SQL_IDENT})?\s+set\s`,
  "gi",
);
const INSERT_RE = new RegExp(String.raw`\binsert\s+into\s+${QUAL}\s*(\([^()]{0,800}\))?`, "gi");
const DELETE_RE = new RegExp(String.raw`\bdelete\s+from\s+(?:only\s+)?${QUAL}`, "gi");

const AUTH_UID = String.raw`(?:\(\s*select\s+auth\s*\.\s*uid\s*\(\s*\)\s*\)|auth\s*\.\s*uid\s*\(\s*\))(?:\s*::\s*\w+)?`;
const COLUMN_REF = String.raw`[a-z_][\w$]*(?:\s*\.\s*[a-z_][\w$]*){0,2}(?:\s*::\s*\w+)?`;
const OWNERSHIP_RES = [
  new RegExp(`^${AUTH_UID}\\s*=\\s*${COLUMN_REF}$`, "i"),
  new RegExp(`^${COLUMN_REF}\\s*=\\s*${AUTH_UID}$`, "i"),
  new RegExp(`^${AUTH_UID}\\s+is\\s+not\\s+null$`, "i"),
  /^(?:\(\s*select\s+auth\s*\.\s*role\s*\(\s*\)\s*\)|auth\s*\.\s*role\s*\(\s*\))\s*=\s*'\s*'$/i,
];

interface Loc {
  file: string;
  line: number;
}

interface ClauseState extends Loc {
  expr: string;
  /** Absolute offset of the expression in `file`. */
  exprAbs: number;
}

interface PolicyState extends Loc {
  name: string;
  table: QualifiedName;
  tableKey: string;
  restrictive: boolean;
  cmd: PolicyCommand;
  roles: string[] | undefined;
  using: ClauseState | undefined;
  check: ClauseState | undefined;
}

interface TableState {
  columns: Set<string>;
  rls: boolean;
}

interface GrantRecord extends Loc {
  table: QualifiedName;
  tableKey: string;
  /** grantee -> privileges still in effect */
  privs: Map<string, Set<string>>;
}

interface AllTablesGrant extends Loc {
  schema: string;
  privs: Set<string>;
  tables: string[];
}

interface FunctionState extends Loc {
  fn: QualifiedName;
  endLine: number;
  definer: boolean;
  searchPath: boolean;
  returnsTrigger: boolean;
  body: string;
  pos: SqlPosition;
}

interface TriggerState {
  tableKey: string;
  events: string;
  fnKey: string;
}

interface FileText {
  lines: string[];
  locate: (offset: number) => number;
}

/** Display-safe identifier: control chars stripped, capped at the Postgres identifier limit. */
function display(name: string): string {
  const clean = name
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return clean.length > MAX_NAME ? clean.slice(0, MAX_NAME) + "..." : clean;
}

function displayQual(q: QualifiedName): string {
  return display(q.schema ? `${q.schema}.${q.name}` : q.name);
}

const segmentsOf = (name: string): string[] => name.toLowerCase().split(/[_\s]+/);

type TableClass = "catalog" | "sensitive" | "person" | "other";

export class SupabasePolicyDetector implements Detector {
  id = "supabase-policy-detector";
  name = "Supabase Policy and Grant Checks";
  category = "authorization" as const;
  description =
    "Detects Supabase policies that expose every row, grants to anon on unprotected tables, unsafe SECURITY DEFINER functions, always-true policy comparisons and policies that let users promote themselves.";

  async detect(context: ScanContext): Promise<Finding[]> {
    try {
      return await this.run(context);
    } catch {
      return [];
    }
  }

  private async run(context: ScanContext): Promise<Finding[]> {
    const sqlFiles = context.files.filter((f) => /\.sql$/i.test(f)).sort();
    if (sqlFiles.length === 0) return [];

    const inSupabaseDir = (f: string) => f.replace(/\\/g, "/").split("/").includes("supabase");
    let usage: { used: boolean; client: boolean } | undefined;

    const texts = new Map<string, FileText>();
    const parsed: SqlFileStatements[] = [];
    for (const file of sqlFiles) {
      if (!inSupabaseDir(file) && !(usage ??= await detectSupabaseUsage(context)).used) continue;
      const raw = await context.readFile(file);
      if (raw === "") continue;
      texts.set(file, { lines: raw.split("\n"), locate: createLineLocator(raw) });
      parsed.push({ file, statements: splitSqlStatements(raw) });
    }
    if (parsed.length === 0) return [];

    const tables = new Map<string, TableState>();
    const policies = new Map<string, PolicyState>();
    const grants: GrantRecord[] = [];
    const allTablesGrants: AllTablesGrant[] = [];
    const functions = new Map<string, FunctionState>();
    const fnGranted = new Map<string, Set<string>>();
    const fnRevoked = new Map<string, Set<string>>();
    let defaultExecuteRevoked = false;
    const triggers: TriggerState[] = [];
    const columnGuards = new Set<string>();
    const policyKey = (tableKey: string, name: string) => `${tableKey}\u0000${name}`;

    parsed.forEach(({ file, statements }, fileIndex) => {
      const ft = texts.get(file)!;
      const loc = (stmt: SqlStatement, rel: number): Loc => ({
        file,
        line: ft.locate(stmt.start + Math.max(0, rel)),
      });
      statements.forEach((stmt, index) => {
        const head = stmt.code.slice(0, 120).toLowerCase().replace(/\s+/g, " ");
        if (/^create\s+(?:(?:global|local)\s+)?(?:temp|temporary|unlogged)?\s*table\b/.test(head)) {
          const t = parseCreateTable(stmt);
          if (!t || t.partition || t.temporary) return;
          const key = qualifiedKey(t.table);
          if (t.ifNotExists && tables.has(key)) return;
          tables.set(key, { columns: new Set(t.columns), rls: false });
          return;
        }
        if (head.startsWith("alter table")) {
          const a = parseAlterTable(stmt);
          if (!a) return;
          const key = qualifiedKey(a.table);
          const t = tables.get(key);
          if (a.renameTo !== undefined) {
            const to = `${a.table.schema ?? "public"}.${a.renameTo}`;
            if (t) {
              tables.delete(key);
              tables.set(to, t);
            }
            for (const [k, p] of [...policies]) {
              if (p.tableKey !== key) continue;
              policies.delete(k);
              p.tableKey = to;
              p.table = { schema: a.table.schema, name: a.renameTo };
              policies.set(policyKey(to, p.name), p);
            }
            for (const g of grants) {
              if (g.tableKey !== key) continue;
              g.tableKey = to;
              g.table = { schema: a.table.schema, name: a.renameTo };
            }
            return;
          }
          if (!t) return;
          if (a.rls) t.rls = a.rls === "enable";
          for (const c of a.addColumns) t.columns.add(c);
          for (const c of a.dropColumns) t.columns.delete(c);
          if (a.renameColumn) {
            t.columns.delete(a.renameColumn.from);
            t.columns.add(a.renameColumn.to);
          }
          return;
        }
        if (head.startsWith("drop table")) {
          const list = stmt.code
            .replace(DROP_TABLE_RE, "")
            .replace(/(?<=[\w"$,])\s+(?:cascade|restrict)\s*$/i, "");
          for (const q of list.matchAll(new RegExp(QUAL, "g"))) {
            const key = qualifiedKey({
              schema: q[1] === undefined ? undefined : normalizeSqlIdent(q[1]),
              name: normalizeSqlIdent(q[2]!),
            });
            tables.delete(key);
            for (const [k, p] of [...policies]) if (p.tableKey === key) policies.delete(k);
            for (let g = grants.length - 1; g >= 0; g--)
              if (grants[g]!.tableKey === key) grants.splice(g, 1);
          }
          return;
        }
        if (/^(?:create|alter|drop)\s+(?:or\s+replace\s+)?policy\b/.test(head)) {
          this.applyPolicy(stmt, loc, policies, policyKey);
          return;
        }
        if (head.startsWith("grant") || head.startsWith("revoke")) {
          const g = parseGrant(stmt);
          if (!g) return;
          const at = loc(stmt, 0);
          const privs = g.privileges.flatMap((p) => (p === "all" ? ALL_TABLE_PRIVS : [p]));
          if (g.targetType === "table") {
            for (const obj of g.objects) {
              const tableKey = qualifiedKey(obj);
              const writes = privs.some((p) => p === "insert" || p === "update");
              if (
                writes &&
                g.grantees.some((r) => API_ROLES.has(r)) &&
                (g.columnLevel || g.action === "revoke")
              )
                columnGuards.add(tableKey);
              if (g.action === "grant") {
                const map = new Map<string, Set<string>>();
                for (const r of g.grantees) map.set(r, new Set(privs));
                grants.push({ ...at, table: obj, tableKey, privs: map });
              } else {
                for (const rec of grants) {
                  if (rec.tableKey !== tableKey) continue;
                  for (const r of g.grantees) {
                    const set = rec.privs.get(r);
                    if (set) for (const p of privs) set.delete(p);
                  }
                }
              }
            }
          } else if (g.targetType === "all-tables" && g.action === "grant") {
            if (!g.grantees.some((r) => ANON_ROLES.has(r))) return;
            for (const schema of g.objects) {
              const prefix = `${schema.name}.`;
              allTablesGrants.push({
                ...at,
                schema: schema.name,
                privs: new Set(privs),
                tables: [...tables.keys()].filter((k) => k.startsWith(prefix)),
              });
            }
          } else if (
            g.targetType === "function" &&
            g.privileges.some((p) => p === "execute" || p === "all")
          ) {
            for (const obj of g.objects) {
              const key = qualifiedKey(obj);
              const target = g.action === "grant" ? fnGranted : fnRevoked;
              const other = g.action === "grant" ? fnRevoked : fnGranted;
              const set = target.get(key) ?? new Set<string>();
              for (const r of g.grantees) {
                set.add(r);
                other.get(key)?.delete(r);
              }
              target.set(key, set);
            }
          }
          return;
        }
        if (/^create\s+(?:or\s+replace\s+)?(?:function|procedure)\b/.test(head)) {
          const f = parseCreateFunction(stmt);
          if (!f) return;
          const key = qualifiedKey(f.fn);
          functions.set(key, {
            ...loc(stmt, f.definerOffset === -1 ? 0 : f.definerOffset),
            fn: f.fn,
            endLine: ft.locate(stmt.end),
            definer: f.securityDefiner,
            searchPath: f.searchPath,
            returnsTrigger: f.returnsTrigger,
            body: f.body,
            pos: { file, fileIndex, index },
          });
          return;
        }
        if (/^alter\s+(?:function|procedure|routine)\b/.test(head)) {
          const a = parseAlterFunction(stmt);
          if (!a) return;
          const key = qualifiedKey(a.fn);
          const f = functions.get(key);
          if (!f) return;
          if (a.security) f.definer = a.security === "definer";
          if (a.renameTo !== undefined) {
            functions.delete(key);
            f.fn = { schema: a.fn.schema, name: a.renameTo };
            functions.set(qualifiedKey(f.fn), f);
          }
          return;
        }
        if (/^drop\s+(?:function|procedure|routine)\b/.test(head)) {
          const m = DROP_FUNCTION_RE.exec(stmt.code);
          if (m) {
            functions.delete(
              qualifiedKey({
                schema: m[1] === undefined ? undefined : normalizeSqlIdent(m[1]),
                name: normalizeSqlIdent(m[2]!),
              }),
            );
          }
          return;
        }
        if (/^create\s+(?:or\s+replace\s+)?(?:constraint\s+)?trigger\b/.test(head)) {
          const m = TRIGGER_RE.exec(stmt.code.slice(0, 2000));
          if (!m) return;
          triggers.push({
            events: m[1]!.toLowerCase(),
            tableKey: qualifiedKey({
              schema: m[2] === undefined ? undefined : normalizeSqlIdent(m[2]),
              name: normalizeSqlIdent(m[3]!),
            }),
            fnKey: qualifiedKey({
              schema: m[4] === undefined ? undefined : normalizeSqlIdent(m[4]),
              name: normalizeSqlIdent(m[5]!),
            }),
          });
          return;
        }
        if (head.startsWith("alter default privileges")) {
          if (
            /\brevoke\s+(?:execute|all)\b[\s\S]{0,200}\bon\s+(?:functions|routines)\s+from\s+([\w\s,"]+)/i.test(
              stmt.code,
            )
          ) {
            const who = /\bfrom\s+([\w\s,"]+)$/i.exec(stmt.code)?.[1] ?? "";
            if (/\b(?:public|anon|authenticated)\b/i.test(who)) defaultExecuteRevoked = true;
          }
        }
      });
    });

    const columnsOf = (q: QualifiedName): readonly string[] | undefined => {
      const t = tables.get(qualifiedKey(q));
      return t ? [...t.columns] : undefined;
    };
    const classify = (q: QualifiedName): TableClass => {
      const name = q.name.toLowerCase();
      if (CATALOG_TABLES.has(name) || CATALOG_PREFIX_RE.test(name)) return "catalog";
      const segs = segmentsOf(name);
      if (segs.some((s) => SENSITIVE_SEGMENTS.has(s)) || /(?:^|_)api_keys?(?:_|$)/.test(name))
        return "sensitive";
      const cols = columnsOf(q);
      if (cols?.some((c) => SENSITIVE_COLUMN_RE.test(c.toLowerCase()))) return "sensitive";
      if (segs.some((s) => PERSON_SEGMENTS.has(s)))
        return cols === undefined ? "sensitive" : "person";
      return "other";
    };
    const evidence = (l: Loc): string => texts.get(l.file)?.lines[l.line - 1] ?? "";

    const findings: Finding[] = [];
    for (const p of policies.values()) {
      const f = this.checkSelectUsingTrue(p, classify, evidence);
      if (f) findings.push(f);
    }
    for (const g of grants) {
      const f = this.checkTableGrant(g, tables, classify, evidence);
      if (f) findings.push(f);
    }
    for (const g of allTablesGrants) {
      const f = this.checkAllTablesGrant(g, tables, evidence);
      if (f) findings.push(f);
    }

    const fixes = functionSearchPathFixes(parsed);
    const reachable = (f: FunctionState): string[] => {
      const key = qualifiedKey(f.fn);
      const granted = [...(fnGranted.get(key) ?? [])].filter((r) => API_ROLES.has(r));
      if (granted.length > 0) return granted;
      const revoked = fnRevoked.get(key);
      const schema = f.fn.schema ?? "public";
      if (
        schema === "public" &&
        !defaultExecuteRevoked &&
        ![...(revoked ?? [])].some((r) => API_ROLES.has(r))
      )
        return ["public"];
      return [];
    };
    for (const f of functions.values()) {
      if (!f.definer) continue;
      const callers = reachable(f);
      if (callers.length === 0) continue;
      const fix = fixes.get(qualifiedKey(f.fn));
      if (!f.searchPath && !(fix && isAfter(fix, f.pos))) {
        findings.push(this.searchPathFinding(f, evidence(f)));
      }
      if (!f.returnsTrigger) {
        const finding = this.callerCheckFinding(f, callers, evidence(f));
        if (finding) findings.push(finding);
      }
    }

    for (const p of policies.values()) {
      findings.push(...this.checkSelfReference(p, columnsOf, texts, evidence));
      const f = this.checkSelfPromotion(p, tables, triggers, functions, columnGuards, evidence);
      if (f) findings.push(f);
    }
    return capPerRuleAndFile(findings);
  }

  private applyPolicy(
    stmt: SqlStatement,
    loc: (stmt: SqlStatement, rel: number) => Loc,
    policies: Map<string, PolicyState>,
    policyKey: (tableKey: string, name: string) => string,
  ): void {
    const p = parsePolicy(stmt);
    if (!p) return;
    const tableKey = qualifiedKey(p.table);
    const key = policyKey(tableKey, p.name);
    const clause = (c: { expr: string; offset: number; exprOffset: number } | undefined) => {
      if (!c) return undefined;
      const at = loc(stmt, c.offset);
      return { ...at, expr: c.expr, exprAbs: stmt.start + c.exprOffset };
    };
    if (p.op === "create") {
      policies.set(key, {
        ...loc(stmt, 0),
        name: p.name,
        table: p.table,
        tableKey,
        restrictive: p.restrictive ?? false,
        cmd: p.cmd ?? "all",
        roles: p.roles,
        using: clause(p.using),
        check: clause(p.check),
      });
    } else if (p.op === "drop") {
      policies.delete(key);
    } else {
      const cur = policies.get(key);
      if (!cur) return;
      if (p.op === "rename" && p.newName !== undefined) {
        policies.delete(key);
        cur.name = p.newName;
        policies.set(policyKey(tableKey, p.newName), cur);
        return;
      }
      if (p.roles !== undefined) cur.roles = p.roles;
      if (p.using) cur.using = clause(p.using);
      if (p.check) cur.check = clause(p.check);
    }
  }

  // ── authorization/supabase-select-using-true ─────────────────────────────

  private checkSelectUsingTrue(
    p: PolicyState,
    classify: (q: QualifiedName) => TableClass,
    evidence: (l: Loc) => string,
  ): Finding | null {
    if (p.restrictive || (p.cmd !== "select" && p.cmd !== "all")) return null;
    const reach = rolesReach(p.roles);
    if (!reach || !p.using || !isAlwaysTrueExpr(p.using.expr)) return null;
    const cls = classify(p.table);
    if (cls === "catalog") return null;
    // A FOR ALL policy with `using (true)` is already reported by the supabase-rls
    // detector (permissive policy); only add the read exposure when the data is sensitive.
    if (p.cmd === "all" && cls !== "sensitive" && isLiteralTrue(p.using.expr)) return null;
    const table = displayQual(p.table);
    let severity: Severity = "medium";
    if (cls === "sensitive") severity = reach === "anon" ? "critical" : "high";
    const who =
      reach === "anon"
        ? "anyone holding your public anon key (no login needed)"
        : "every signed-in user";
    return makeFinding({
      category: "authorization",
      ruleId: "authorization/supabase-select-using-true",
      title: `Supabase policy lets ${reach === "anon" ? "anyone" : "every user"} read all rows of ${table}`,
      severity,
      confidence: "high",
      file: p.using.file,
      line: p.using.line,
      evidence: evidence(p.using),
      discriminator: `${p.tableKey}|${p.name}`,
      plainEnglishProblem: `The policy "${display(p.name)}" on "${table}" allows reads with \`using (true)\`, so ${who} can read every row of the table through the Supabase API.`,
      whyItMatters:
        cls === "sensitive"
          ? "Row level security is on, but this policy makes every row visible. Policies are combined with OR, so other, stricter select policies on the table do not help: one request returns all tenants' and customers' data."
          : cls === "person"
            ? "Every row of this table is readable. That is sometimes intended for public profile fields, but any column added later (emails, roles, flags) becomes public too."
            : "Every row of this table is readable through the API. Unless the table only holds data meant to be public, this leaks other users' records.",
      fixSteps: [
        "Replace `using (true)` with a condition that ties each row to the caller, e.g. `using (auth.uid() = user_id)` or a membership check such as `using (public.is_org_member(org_id))`.",
        "If some rows are meant to be public, restrict the policy to them (e.g. `using (is_published)`) and keep private rows behind an owner or membership policy.",
        "Add `to authenticated` (or a narrower role) so anonymous visitors are not covered by the policy.",
      ],
      aiFixPrompt:
        "A Supabase row level security SELECT policy uses `using (true)`, so every row is readable by anyone with the anon key. Rewrite the policy so it only returns rows the caller owns or belongs to (for example `auth.uid() = user_id`, or a SECURITY DEFINER membership helper with a pinned search_path for org-scoped tables), add `to authenticated`, and keep a separate narrow policy only for rows that are intentionally public. Do not change other policies.",
    });
  }

  // ── authorization/supabase-grant-to-anon ─────────────────────────────────

  private checkTableGrant(
    g: GrantRecord,
    tables: Map<string, TableState>,
    classify: (q: QualifiedName) => TableClass,
    evidence: (l: Loc) => string,
  ): Finding | null {
    const grantees = [...g.privs.entries()].filter(([r, s]) => ANON_ROLES.has(r) && s.size > 0);
    if (grantees.length === 0) return null;
    const privs = new Set(grantees.flatMap(([, s]) => [...s]));
    const t = tables.get(g.tableKey);
    if (t?.rls) return null; // the normal Supabase setup: RLS policies decide
    const cls = classify(g.table);
    const writes = WRITE_PRIVS.filter((p) => privs.has(p));
    const known = t !== undefined;
    let severity: Severity;
    let confidence: Confidence;
    if (writes.length > 0) {
      [severity, confidence] = known ? ["critical", "high"] : ["high", "medium"];
    } else if (privs.has("select")) {
      if (cls === "catalog") return null;
      if (cls === "sensitive" || cls === "person") {
        [severity, confidence] = known ? ["critical", "high"] : ["high", "medium"];
      } else if (known) {
        [severity, confidence] = ["medium", "high"];
      } else return null;
    } else return null;
    if ((g.table.schema ?? "public") !== "public" && severity === "critical") {
      [severity, confidence] = ["high", "medium"];
    }
    const table = displayQual(g.table);
    const roles = grantees.map(([r]) => (r === "public" ? "PUBLIC" : r)).join(", ");
    const what =
      writes.length > 0
        ? `${["select", ...writes].filter((p) => privs.has(p)).join(", ")}`
        : "select";
    return makeFinding({
      category: "authorization",
      ruleId: "authorization/supabase-grant-to-anon",
      title: `${table} is granted to ${roles} without row level security`,
      severity,
      confidence,
      file: g.file,
      line: g.line,
      evidence: evidence(g),
      discriminator: `${g.tableKey}|${roles}`,
      plainEnglishProblem: `A migration grants ${what} on "${table}" to ${roles}, and ${known ? "the table never gets row level security enabled" : "no migration here enables row level security on it"}. The anon role is what every visitor uses with your public Supabase key.`,
      whyItMatters:
        writes.length > 0
          ? "Without RLS the grant is the only access control, so anyone with the public anon key can read, insert, change or delete rows in this table, for every tenant."
          : "Without RLS the grant is the only access control, so anyone with the public anon key can download every row of this table.",
      fixSteps: [
        "Enable row level security on the table and add policies that scope rows to their owner or organization.",
        "Remove the grant to anon / PUBLIC (`revoke all on table ... from anon;`) unless logged-out visitors really need it, and grant only the privileges a role needs.",
        "Keep server-only tables (API keys, billing) reachable only through the service role or SECURITY DEFINER functions that check the caller.",
      ],
      aiFixPrompt:
        "A Supabase migration grants table privileges to the anon role (or PUBLIC) on a table that has no row level security, so anyone with the public anon key can read or modify it. Write a migration that enables row level security on the table, adds owner- or organization-scoped policies, revokes the anon / PUBLIC grant and grants authenticated only the privileges it needs. Do not grant anything to anon on tables that hold private data.",
    });
  }

  private checkAllTablesGrant(
    g: AllTablesGrant,
    tables: Map<string, TableState>,
    evidence: (l: Loc) => string,
  ): Finding | null {
    const open = g.tables.filter((k) => {
      const t = tables.get(k);
      return t !== undefined && !t.rls;
    });
    if (open.length === 0) return null;
    const names = open.slice(0, 5).map((k) => display(k.slice(k.indexOf(".") + 1)));
    return makeFinding({
      category: "authorization",
      ruleId: "authorization/supabase-grant-to-anon",
      title: `All tables in schema ${display(g.schema)} are granted to anon`,
      severity: "high",
      confidence: "high",
      file: g.file,
      line: g.line,
      evidence: evidence(g),
      discriminator: `all-tables|${g.schema}`,
      plainEnglishProblem: `A migration grants privileges on every table in schema "${display(g.schema)}" to anon / PUBLIC, and ${open.length} of them have no row level security (${names.join(", ")}${open.length > names.length ? ", ..." : ""}).`,
      whyItMatters:
        "Tables without RLS are protected only by grants. With this blanket grant anyone holding your public anon key can reach them.",
      fixSteps: [
        "Enable row level security on every table in the schema and add owner-scoped policies.",
        "Replace the blanket grant with per-table grants for the roles that need them.",
      ],
      aiFixPrompt:
        "A Supabase migration grants privileges on all tables in a schema to anon or PUBLIC while some tables have no row level security. Enable RLS on every table in that schema with owner- or organization-scoped policies, and replace the blanket grant with explicit per-table grants limited to what each role needs.",
    });
  }

  // ── SECURITY DEFINER functions ───────────────────────────────────────────

  private searchPathFinding(f: FunctionState, evidence: string): Finding {
    const fn = displayQual(f.fn);
    return makeFinding({
      category: "authorization",
      ruleId: "authorization/supabase-security-definer-no-search-path",
      title: `SECURITY DEFINER function ${fn} has no fixed search_path`,
      severity: f.returnsTrigger ? "medium" : "high",
      confidence: "high",
      file: f.file,
      line: f.line,
      endLine: f.endLine,
      evidence,
      discriminator: qualifiedKey(f.fn),
      plainEnglishProblem: `The function "${fn}" runs with its owner's privileges (SECURITY DEFINER) but does not pin \`search_path\`, so the tables and functions it names without a schema are looked up in the caller's search path.`,
      whyItMatters:
        "A caller who can create objects in a schema on the search path (including their temporary schema) can shadow a table or function the definer uses and run code with the owner's rights, which in Supabase usually bypasses row level security.",
      fixSteps: [
        "Add `set search_path = ''` (or `= public`) to the function definition and schema-qualify every table and function it uses (e.g. `public.org_members`).",
        "If the function does not need elevated rights, make it `security invoker` instead.",
      ],
      aiFixPrompt:
        "A Postgres SECURITY DEFINER function in a Supabase migration does not set search_path. Recreate it with `set search_path = ''` and schema-qualify every table, function and type it references (for example public.my_table, auth.uid()). Keep its behaviour otherwise unchanged; if it does not need owner privileges, switch it to SECURITY INVOKER.",
    });
  }

  private callerCheckFinding(
    f: FunctionState,
    callers: string[],
    evidence: string,
  ): Finding | null {
    const body = stripSqlNoise(f.body);
    const write = privilegedWrite(body);
    if (!write) return null;
    if (CALLER_CHECK_RE.test(body) || JWT_SETTING_RE.test(f.body)) return null;
    const fn = displayQual(f.fn);
    const who = callers.map((r) => (r === "public" ? "PUBLIC" : r)).join(", ");
    return makeFinding({
      category: "authorization",
      ruleId: "authorization/supabase-definer-missing-caller-check",
      title: `SECURITY DEFINER function ${fn} changes ${write} without checking the caller`,
      severity: "high",
      confidence: "medium",
      file: f.file,
      line: f.line,
      endLine: f.endLine,
      evidence,
      discriminator: qualifiedKey(f.fn),
      plainEnglishProblem: `The function "${fn}" runs as its owner (bypassing row level security) and changes ${write}, but never checks who is calling it (no \`auth.uid()\`, JWT or role check). It is executable by ${who}.`,
      whyItMatters:
        "Any user can call it through the API (`supabase.rpc(...)`) with arguments of their choosing, for example to make themselves an owner or admin of any organization or to demote the real owners.",
      fixSteps: [
        "At the start of the function, verify the caller: e.g. raise an exception unless `exists (select 1 from public.org_members where org_id = target_org and user_id = auth.uid() and role in ('owner', 'admin'))`.",
        "Revoke execute from PUBLIC, anon and authenticated (`revoke execute on function ... from public, anon, authenticated;`) and grant it only to the roles that should call it.",
        "Pin `set search_path = ''` and schema-qualify the tables it touches.",
      ],
      aiFixPrompt:
        "A Supabase SECURITY DEFINER function changes roles, memberships or account privileges without checking who calls it, and it is executable through the API. Add a caller check at the top of the function (compare auth.uid() against an owner/admin membership of the target organization or account and raise an exception otherwise), pin `set search_path = ''`, schema-qualify table names, and revoke EXECUTE from public and anon so only intended roles can call it.",
    });
  }

  // ── authorization/supabase-self-referential-policy ───────────────────────

  private checkSelfReference(
    p: PolicyState,
    columnsOf: (q: QualifiedName) => readonly string[] | undefined,
    texts: Map<string, FileText>,
    evidence: (l: Loc) => string,
  ): Finding[] {
    const out: Finding[] = [];
    const clauses: [string, ClauseState | undefined][] = [
      ["using", p.using],
      ["check", p.check],
    ];
    for (const [kind, c] of clauses) {
      if (!c) continue;
      const ft = texts.get(c.file);
      if (!ft) continue;
      extractEqualities(c.expr, p.table, columnsOf).forEach((eq, i) => {
        if (!eq.sameColumn) return;
        const at: Loc = { file: c.file, line: ft.locate(c.exprAbs + eq.offset) };
        const left = display(eq.left.parts.join("."));
        const right = display(eq.right.parts.join("."));
        const table = displayQual(p.table);
        out.push(
          makeFinding({
            category: "authorization",
            ruleId: "authorization/supabase-self-referential-policy",
            title: `Policy on ${table} compares a column with itself`,
            severity: "high",
            confidence: eq.certain ? "high" : "medium",
            file: at.file,
            line: at.line,
            evidence: evidence(at),
            discriminator: `${p.tableKey}|${p.name}|${kind}|${i}`,
            plainEnglishProblem: `In the policy "${display(p.name)}" on "${table}", \`${left} = ${right}\` compares a column with itself: inside the subquery the unqualified name resolves to the subquery's own table, not to "${table}". The condition is always true.`,
            whyItMatters:
              "The policy was meant to match rows to the caller's organization or owner, but as written it matches every row, so any user who passes the rest of the check (for example, belongs to any organization) can read or change every tenant's rows.",
            fixSteps: [
              `Qualify both sides with their table names, e.g. \`org_members.org_id = ${table.split(".").pop()}.org_id\`.`,
              "Prefer a SECURITY DEFINER membership helper such as `public.is_org_member(org_id)` so the policy cannot pick the wrong column.",
            ],
            aiFixPrompt:
              "A Supabase row level security policy compares a column with itself (for example `org_members.org_id = org_id` inside a subquery on org_members, where the unqualified name resolves to org_members), which is always true. Rewrite the condition so one side refers to the policy's table explicitly (for example `org_members.org_id = invoices.org_id`) and keep the membership and auth.uid() checks.",
          }),
        );
      });
    }
    return out;
  }

  // ── authorization/supabase-policy-self-promotion ─────────────────────────

  private checkSelfPromotion(
    p: PolicyState,
    tables: Map<string, TableState>,
    triggers: TriggerState[],
    functions: Map<string, FunctionState>,
    columnGuards: Set<string>,
    evidence: (l: Loc) => string,
  ): Finding | null {
    if (p.restrictive || (p.cmd !== "insert" && p.cmd !== "update" && p.cmd !== "all")) return null;
    if (!rolesReach(p.roles)) return null;
    // `using (true)` / `with check (true)` write policies are the rls detector's finding.
    if (isAlwaysTrueExpr(p.using?.expr) || isAlwaysTrueExpr(p.check?.expr)) return null;
    const clause = p.cmd === "insert" ? p.check : (p.check ?? p.using);
    if (!clause) return null;
    const t = tables.get(p.tableKey);
    if (!t || !t.rls) return null;
    const privCols = [...t.columns].filter((c) => PRIVILEGE_COLUMN_RE.test(c.toLowerCase()));
    if (privCols.length === 0) return null;
    const expr = clause.expr;
    const mentions = (c: string) =>
      new RegExp(
        `(?:^|[^\\w$])"?${c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"?(?![\\w$])`,
        "i",
      ).test(expr);
    if (privCols.some(mentions)) return null;
    const conjuncts = splitTopLevelAnd(expr).map(unwrapParens);
    if (conjuncts.length === 0) return null;
    if (!conjuncts.every((c) => OWNERSHIP_RES.some((re) => re.test(c)))) return null;
    if (!conjuncts.some((c) => /auth\s*\.\s*uid/i.test(c))) return null;
    if (columnGuards.has(p.tableKey)) return null;
    const verbs = p.cmd === "all" ? ["insert", "update"] : [p.cmd];
    const guarded = triggers.some((tr) => {
      if (tr.tableKey !== p.tableKey || !verbs.some((v) => tr.events.includes(v))) return false;
      const body = functions.get(tr.fnKey)?.body;
      return body !== undefined && privCols.some((c) => new RegExp(`\\b${c}\\b`, "i").test(body));
    });
    if (guarded) return null;
    const table = displayQual(p.table);
    const cols = privCols.slice(0, 4).map(display).join(", ");
    const action =
      p.cmd === "insert"
        ? "insert a row"
        : p.cmd === "update"
          ? "update their row"
          : "write their rows";
    return makeFinding({
      category: "authorization",
      ruleId: "authorization/supabase-policy-self-promotion",
      title: `Users can set ${cols} on ${table} themselves`,
      severity: "high",
      confidence: "medium",
      file: clause.file,
      line: clause.line,
      evidence: evidence(clause),
      discriminator: `${p.tableKey}|${p.name}`,
      plainEnglishProblem: `The ${p.cmd} policy "${display(p.name)}" on "${table}" only checks that the row belongs to the caller, so a user can ${action} with any value in ${cols}.`,
      whyItMatters:
        "Row level security checks which rows a user may write, not which values. A user can call the API directly and set their own role, admin flag, plan or balance, or add themselves to another organization as owner.",
      fixSteps: [
        "Constrain the privileged columns in WITH CHECK (e.g. `with check (user_id = auth.uid() and role = 'member')`), or",
        "Use column privileges: `revoke update on table ... from authenticated; grant update (name, avatar_url) on table ... to authenticated;`, or a BEFORE trigger that rejects changes to those columns by non-admins.",
        "Change roles, plans and balances only through server code or a SECURITY DEFINER function that checks the caller.",
      ],
      aiFixPrompt:
        "A Supabase insert/update row level security policy only checks ownership (auth.uid() = user_id), but the table has privilege columns (role, is_admin, plan, credits, balance), so users can set them on their own rows or join other organizations with any role. Restrict those columns: add them to WITH CHECK with safe fixed values for self-service writes, or revoke table-level INSERT/UPDATE from authenticated and grant only the safe columns, and move role or plan changes into a server route or SECURITY DEFINER function that verifies the caller is an admin.",
    });
  }
}

/** Which API audience a policy's role list reaches: anon (incl. PUBLIC), authenticated only, or none. */
/** `true` in parentheses: exactly what the supabase-rls detector treats as permissive. */
function isLiteralTrue(expr: string): boolean {
  return /^true$/i.test(unwrapParens(expr));
}

function rolesReach(roles: string[] | undefined): "anon" | "authenticated" | null {
  if (roles === undefined) return "anon";
  if (roles.some((r) => ANON_ROLES.has(r))) return "anon";
  if (roles.includes("authenticated")) return "authenticated";
  return null;
}

function unwrapParens(e: string): string {
  let s = e.trim().replace(/\s+/g, " ");
  while (s.startsWith("(") && s.endsWith(")")) {
    let depth = 0;
    let balanced = true;
    for (let i = 0; i < s.length; i++) {
      if (s[i] === "(") depth++;
      else if (s[i] === ")" && --depth === 0 && i < s.length - 1) {
        balanced = false;
        break;
      }
    }
    if (!balanced) break;
    s = s.slice(1, -1).trim();
  }
  return s;
}

/** A short description of the role / membership change a function body makes, or null. */
function privilegedWrite(body: string): string | null {
  const name = (q: RegExpMatchArray) => normalizeSqlIdent(q[2]!);
  for (const m of body.matchAll(UPDATE_RE)) {
    const setStart = m.index + m[0].length;
    const tail = body.slice(setStart, setStart + 800);
    const end = /\b(?:where|from|returning)\b|;/i.exec(tail);
    const setList = end ? tail.slice(0, end.index) : tail;
    for (const a of setList.matchAll(new RegExp(`(?:^|,)\\s*(${SQL_IDENT})\\s*=`, "g"))) {
      const col = normalizeSqlIdent(a[1]!).toLowerCase();
      if (PRIVILEGE_COLUMN_RE.test(col)) return `${display(col)} in ${display(name(m))}`;
    }
  }
  for (const m of body.matchAll(INSERT_RE)) {
    const table = name(m).toLowerCase();
    if (MEMBERSHIP_TABLE_RE.test(table)) return `memberships in ${display(table)}`;
    const cols = (m[3] ?? "").replace(/[()]/g, "").split(",");
    const hit = cols.map((c) => normalizeSqlIdent(c.trim() || "_").toLowerCase());
    const priv = hit.find((c) => PRIVILEGE_COLUMN_RE.test(c));
    if (priv) return `${display(priv)} in ${display(table)}`;
  }
  for (const m of body.matchAll(DELETE_RE)) {
    const table = name(m).toLowerCase();
    if (MEMBERSHIP_TABLE_RE.test(table)) return `memberships in ${display(table)}`;
  }
  return null;
}

/** Keeps at most MAX_PER_RULE_FILE findings per (rule, file) and adds one summary for the rest. */
function capPerRuleAndFile(findings: Finding[]): Finding[] {
  const groups = new Map<string, Finding[]>();
  for (const f of findings) {
    const k = `${f.ruleId}\u0000${f.file ?? ""}`;
    const list = groups.get(k);
    if (list) list.push(f);
    else groups.set(k, [f]);
  }
  const out: Finding[] = [];
  for (const list of groups.values()) {
    if (list.length <= MAX_PER_RULE_FILE) {
      out.push(...list);
      continue;
    }
    list.sort((a, b) => (a.line ?? 0) - (b.line ?? 0));
    const kept = list.slice(0, MAX_PER_RULE_FILE);
    const rest = list.slice(MAX_PER_RULE_FILE);
    out.push(...kept);
    const first = rest[0]!;
    out.push(
      makeFinding({
        category: "authorization",
        ruleId: first.ruleId,
        title: `${rest.length} more findings like "${first.title}"`,
        severity: rest.some((f) => f.severity === "critical" || f.severity === "high")
          ? "high"
          : "medium",
        confidence: "medium",
        file: first.file,
        line: first.line,
        evidence: first.evidence,
        discriminator: `summary|${first.ruleId}`,
        plainEnglishProblem: `${rest.length} further occurrences of this problem in the same file were not listed individually.`,
        whyItMatters: first.whyItMatters,
        fixSteps: first.fixSteps,
        aiFixPrompt: first.aiFixPrompt ?? "",
      }),
    );
  }
  return out;
}
