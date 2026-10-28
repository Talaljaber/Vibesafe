// ─────────────────────────────────────────────────────────────────────────────
// Supabase Row Level Security Detector
//
// Parses SQL migrations and flags:
//   - tables in the public schema that never get row level security enabled
//   - permissive policies (`using (true)` / `with check (true)`) on writes
// ─────────────────────────────────────────────────────────────────────────────

import type { Detector, Finding, ScanContext, Severity } from "@vibesafe/shared";
import { CATEGORY_PREFIX, createFindingId } from "@vibesafe/shared";
import { sanitizeEvidence } from "./utils/sanitize-evidence.js";
import { isClientFile } from "./utils/file-classifier.js";

const IDENT = String.raw`(?:"(?:[^"]|"")+"|[A-Za-z_][\w$]*)`;
const QUAL = String.raw`(?:(${IDENT})\s*\.\s*)?(${IDENT})`;

const MAX_STMT = 2048;
const MAX_NAME = 63;

const CREATE_TABLE_RE = new RegExp(
  String.raw`\bcreate\s+(?:unlogged\s+)?table\s+(if\s+not\s+exists\s+)?${QUAL}`,
  "gi",
);
const ENABLE_RLS_RE = new RegExp(
  String.raw`\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?${QUAL}\s+(enable|disable)\s+row\s+level\s+security\b`,
  "gi",
);
const RENAME_TABLE_RE = new RegExp(
  String.raw`\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?${QUAL}\s+rename\s+to\s+(${IDENT})`,
  "gi",
);
const DROP_TABLE_RE = /\bdrop\s+table\s+(?:if\s+exists\s+)?/gi;
const DROP_POLICY_RE = new RegExp(
  String.raw`\bdrop\s+policy\s+(?:if\s+exists\s+)?(${IDENT})\s+on\s+${QUAL}`,
  "gi",
);
const ALTER_POLICY_RE = new RegExp(String.raw`\balter\s+policy\s+(${IDENT})\s+on\s+${QUAL}`, "gi");
const POLICY_RE = new RegExp(
  String.raw`\bcreate\s+(?:or\s+replace\s+)?policy\s+(${IDENT})\s+on\s+${QUAL}`,
  "gi",
);
const QUAL_G = new RegExp(QUAL, "g");

const SUPABASE_IMPORT_RE = /@supabase\/(?:supabase-js|ssr|auth-helpers[\w-]*)/;
const SUPABASE_ENV_RE = /(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC)_SUPABASE_/;
const JS_FILE_RE = /\.(?:[cm]?[jt]sx?)$/;

/** Replaces comments and string/dollar-quoted bodies with spaces, preserving offsets and newlines. */
/** @internal Exported for tests only. */
export function stripSqlNoise(sql: string): string {
  const out: string[] = [];
  const blank = (s: string) => s.replace(/[^\n]/g, " ");
  let i = 0;
  while (i < sql.length) {
    const c = sql[i]!;
    const next = sql[i + 1];
    if (c === "-" && next === "-") {
      let j = i;
      while (j < sql.length && sql[j] !== "\n") j++;
      out.push(blank(sql.slice(i, j)));
      i = j;
    } else if (c === "/" && next === "*") {
      let depth = 1;
      let j = i + 2;
      while (j < sql.length && depth > 0) {
        if (sql[j] === "/" && sql[j + 1] === "*") {
          depth++;
          j += 2;
        } else if (sql[j] === "*" && sql[j + 1] === "/") {
          depth--;
          j += 2;
        } else j++;
      }
      out.push(blank(sql.slice(i, j)));
      i = j;
    } else if (c === "'") {
      let j = i + 1;
      while (j < sql.length) {
        if (sql[j] === "'") {
          if (sql[j + 1] === "'") {
            j += 2;
            continue;
          }
          break;
        }
        j++;
      }
      out.push("'" + blank(sql.slice(i + 1, j)) + (j < sql.length ? "'" : ""));
      i = j + 1;
    } else if (c === '"') {
      let j = i + 1;
      while (j < sql.length) {
        if (sql[j] === '"') {
          if (sql[j + 1] === '"') {
            j += 2;
            continue;
          }
          break;
        }
        j++;
      }
      out.push(sql.slice(i, j + 1));
      i = j + 1;
    } else if (c === "$" && !/[\w$]/.test(sql[i - 1] ?? "")) {
      const m = /^\$([A-Za-z_]\w*)?\$/.exec(sql.slice(i, i + 64));
      if (m) {
        const tag = m[0];
        const end = sql.indexOf(tag, i + tag.length);
        const stop = end === -1 ? sql.length : end + tag.length;
        out.push(blank(sql.slice(i, stop)));
        i = stop;
      } else {
        out.push(c);
        i++;
      }
    } else {
      out.push(c);
      i++;
    }
  }
  return out.join("");
}

function normalizeIdent(raw: string): string {
  return raw.startsWith('"') ? raw.slice(1, -1).replace(/""/g, '"') : raw.toLowerCase();
}

/** Key for a table in the public schema, or null for any other schema. */
function tableKey(schema: string | undefined, name: string): string | null {
  const s = schema === undefined ? "public" : normalizeIdent(schema);
  if (s !== "public") return null;
  return `public.${normalizeIdent(name)}`;
}

function lineAt(text: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

/** Returns the balanced-paren contents following `keywordRe` in the statement, if any. */
function parenAfter(stmt: string, keywordRe: RegExp): string | null {
  const m = keywordRe.exec(stmt);
  if (!m) return null;
  let i = m.index + m[0].length;
  while (i < stmt.length && /\s/.test(stmt[i]!)) i++;
  if (stmt[i] !== "(") return null;
  let depth = 0;
  for (let j = i; j < stmt.length; j++) {
    if (stmt[j] === "(") depth++;
    else if (stmt[j] === ")" && --depth === 0) return stmt.slice(i + 1, j);
  }
  return null;
}

function isAlwaysTrue(expr: string | null): boolean {
  if (expr === null) return false;
  let e = expr.trim();
  while (e.startsWith("(") && e.endsWith(")")) e = e.slice(1, -1).trim();
  return /^true$/i.test(e);
}

/** Statement text following `from`, capped and cut at the first semicolon. */
function statementAfter(sql: string, from: number): string {
  const window = sql.slice(from, from + MAX_STMT);
  const semi = window.indexOf(";");
  return semi === -1 ? window : window.slice(0, semi);
}

/** Display-safe identifier: control chars stripped, capped at the Postgres identifier limit. */
function displayName(name: string): string {
  // eslint-disable-next-line no-control-regex
  const clean = name.replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim();
  return clean.length > MAX_NAME ? clean.slice(0, MAX_NAME) + "..." : clean;
}

interface PolicyData {
  restrictive: boolean;
  cmd: string;
  roles: string[] | undefined;
  using: string | null;
  check: string | null;
}

function parsePolicyClauses(rest: string): Partial<PolicyData> {
  const out: Partial<PolicyData> = {};
  if (/\bas\s+restrictive\b/i.test(rest)) out.restrictive = true;
  else if (/\bas\s+permissive\b/i.test(rest)) out.restrictive = false;
  const cmd = /\bfor\s+(all|select|insert|update|delete)\b/i.exec(rest)?.[1];
  if (cmd) out.cmd = cmd.toLowerCase();
  const roles = /\bto\s+([\s\S]*?)(?=\busing\b|\bwith\s+check\b|$)/i.exec(rest)?.[1];
  if (roles !== undefined) out.roles = roles.split(",").map((r) => r.trim().replace(/^"|"$/g, "").toLowerCase());
  const using = parenAfter(rest, /\busing\b/i);
  if (using !== null) out.using = using;
  const check = parenAfter(rest, /\bwith\s+check\b/i);
  if (check !== null) out.check = check;
  return out;
}

type SqlEvent =
  | { kind: "create"; offset: number; key: string; line: number; text: string; ifNotExists: boolean }
  | { kind: "rls"; offset: number; key: string; enabled: boolean }
  | { kind: "drop"; offset: number; key: string }
  | { kind: "rename"; offset: number; from: string; to: string }
  | {
      kind: "policy";
      offset: number;
      tableKey: string;
      pname: string;
      op: "create" | "alter" | "drop" | "rename";
      line: number;
      text: string;
      tableName: string;
      rest: string;
      newName?: string;
    };

interface TableState {
  file: string;
  line: number;
  text: string;
  rls: boolean;
}

interface PolicyState extends PolicyData {
  file: string;
  line: number;
  text: string;
  tableName: string;
}
export class SupabaseRlsDetector implements Detector {
  id = "supabase-rls-detector";
  name = "Supabase Row Level Security Detection";
  category = "authorization" as const;
  description =
    "Detects Supabase tables without row level security and policies that allow everyone to write.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const sqlFiles = context.files.filter((f) => /\.sql$/i.test(f)).sort();
    if (sqlFiles.length === 0) return [];

    const inSupabaseDir = (f: string) => f.replace(/\\/g, "/").split("/").includes("supabase");
    let usage: { used: boolean; client: boolean } | undefined;
    const getUsage = async () => (usage ??= await this.detectSupabaseUsage(context));

    const findings: Finding[] = [];
    const tables = new Map<string, TableState>();
    const policies = new Map<string, PolicyState>();
    const policyKey = (tableKey: string, name: string) => `${tableKey}\u0000${name}`;

    for (const file of sqlFiles) {
      if (!inSupabaseDir(file) && !(await getUsage()).used) continue;
      const raw = await context.readFile(file);
      const sql = stripSqlNoise(raw);
      const rawLines = raw.split("\n");
      const lineText = (line: number) => rawLines[line - 1] ?? "";
      const events: SqlEvent[] = [];
      const polTable = (schema: string | undefined, name: string) =>
        `${schema === undefined ? "public" : normalizeIdent(schema)}.${normalizeIdent(name)}`;

      for (const m of sql.matchAll(CREATE_TABLE_RE)) {
        // Partitions are reached through their (protected) parent table.
        const after = sql.slice(m.index + m[0].length, m.index + m[0].length + 400);
        if (/^[^;(]*\bpartition\s+of\b/i.test(after)) continue;
        const key = tableKey(m[2], m[3]!);
        if (!key) continue;
        const line = lineAt(sql, m.index);
        events.push({
          kind: "create",
          offset: m.index,
          key,
          line,
          text: lineText(line),
          ifNotExists: m[1] !== undefined,
        });
      }
      for (const m of sql.matchAll(ENABLE_RLS_RE)) {
        const key = tableKey(m[1], m[2]!);
        if (key) {
          events.push({ kind: "rls", offset: m.index, key, enabled: m[3]!.toLowerCase() === "enable" });
        }
      }
      for (const m of sql.matchAll(RENAME_TABLE_RE)) {
        const from = tableKey(m[1], m[2]!);
        const to = tableKey(m[1], m[3]!);
        if (from && to) events.push({ kind: "rename", offset: m.index, from, to });
      }
      for (const m of sql.matchAll(DROP_TABLE_RE)) {
        const list = statementAfter(sql, m.index + m[0].length).replace(/\b(?:cascade|restrict)\s*$/i, "");
        for (const q of list.matchAll(QUAL_G)) {
          const key = tableKey(q[1], q[2]!);
          if (key) events.push({ kind: "drop", offset: m.index, key });
        }
      }
      for (const m of sql.matchAll(POLICY_RE)) {
        const line = lineAt(sql, m.index);
        events.push({
          kind: "policy",
          offset: m.index,
          tableKey: polTable(m[2], m[3]!),
          pname: normalizeIdent(m[1]!),
          op: "create",
          line,
          text: lineText(line),
          tableName: (m[2] ? `${normalizeIdent(m[2])}.` : "") + normalizeIdent(m[3]!),
          rest: statementAfter(sql, m.index + m[0].length),
        });
      }
      for (const m of sql.matchAll(ALTER_POLICY_RE)) {
        const rest = statementAfter(sql, m.index + m[0].length);
        const ren = /^\s*rename\s+to\s+(\S+)/i.exec(rest);
        const line = lineAt(sql, m.index);
        events.push({
          kind: "policy",
          offset: m.index,
          tableKey: polTable(m[2], m[3]!),
          pname: normalizeIdent(m[1]!),
          op: ren ? "rename" : "alter",
          line,
          text: lineText(line),
          tableName: "",
          rest,
          ...(ren ? { newName: normalizeIdent(ren[1]!) } : {}),
        });
      }
      for (const m of sql.matchAll(DROP_POLICY_RE)) {
        events.push({
          kind: "policy",
          offset: m.index,
          tableKey: polTable(m[2], m[3]!),
          pname: normalizeIdent(m[1]!),
          op: "drop",
          line: 0,
          text: "",
          tableName: "",
          rest: "",
        });
      }

      events.sort((a, b) => a.offset - b.offset);
      for (const ev of events) {
        if (ev.kind === "create") {
          // `create table if not exists` on a known table is a no-op in SQL.
          if (ev.ifNotExists && tables.has(ev.key)) continue;
          tables.set(ev.key, { file, line: ev.line, text: ev.text, rls: false });
        } else if (ev.kind === "rls") {
          const t = tables.get(ev.key);
          if (t) t.rls = ev.enabled;
        } else if (ev.kind === "drop") {
          tables.delete(ev.key);
          for (const k of [...policies.keys()]) if (k.startsWith(ev.key + "\u0000")) policies.delete(k);
        } else if (ev.kind === "rename") {
          const t = tables.get(ev.from);
          if (!t) continue;
          tables.delete(ev.from);
          tables.set(ev.to, t);
          for (const [k, p] of [...policies.entries()]) {
            if (!k.startsWith(ev.from + "\u0000")) continue;
            policies.delete(k);
            policies.set(ev.to + k.slice(ev.from.length), p);
          }
        } else {
          const pk = policyKey(ev.tableKey, ev.pname);
          if (ev.op === "create") {
            policies.set(pk, {
              restrictive: false,
              cmd: "all",
              roles: undefined,
              using: null,
              check: null,
              ...parsePolicyClauses(ev.rest),
              file,
              line: ev.line,
              text: ev.text,
              tableName: ev.tableName,
            });
          } else if (ev.op === "drop") {
            policies.delete(pk);
          } else {
            const p = policies.get(pk);
            if (!p) continue;
            if (ev.op === "rename" && ev.newName) {
              policies.delete(pk);
              policies.set(policyKey(ev.tableKey, ev.newName), p);
            } else {
              Object.assign(p, parsePolicyClauses(ev.rest));
            }
          }
        }
      }
    }

    const missing = [...tables.entries()].filter(([, t]) => !t.rls);
    if (missing.length > 0) {
      const clientSide = (await getUsage()).client;
      const severity: Severity = clientSide ? "critical" : "high";
      for (const [key, t] of missing) {
        findings.push(this.missingRlsFinding(displayName(key.slice("public.".length)), t, severity, clientSide));
      }
    }
    for (const p of policies.values()) {
      const f = this.checkPolicy(p);
      if (f) findings.push(f);
    }
    return findings;
  }

  private checkPolicy(p: PolicyState): Finding | null {
    if (p.restrictive) return null;
    const cmd = p.cmd;
    if (cmd === "select") return null;
    if (p.roles !== undefined) {
      if (!p.roles.some((r) => r === "public" || r === "anon" || r === "authenticated")) return null;
    }
    // A permissive `with check (true)` is flagged even when `using` is restrictive:
    // it still lets any row be written through that command.
    if (!isAlwaysTrue(p.using) && !isAlwaysTrue(p.check)) return null;

    const { file, line, text } = p;
    const tableName = displayName(p.tableName);
    const ruleId = "authorization/supabase-permissive-policy";
    const action = cmd === "all" ? "every operation" : cmd;
    return {
      id: createFindingId(CATEGORY_PREFIX.authorization, ruleId, file, line),
      ruleId,
      title: `Permissive Supabase policy on ${tableName}`,
      severity: "high",
      category: "authorization",
      deployBlocking: false,
      confidence: "high",
      file,
      line,
      evidence: sanitizeEvidence(text),
      plainEnglishProblem: `A row level security policy on "${tableName}" allows ${action} on any row, because its condition is just "true".`,
      whyItMatters:
        "Row level security is turned on, but this policy cancels it out: anyone with your public Supabase key can change or delete every row in this table.",
      fixSteps: [
        "Replace `true` with a condition that ties the row to the user, e.g. `auth.uid() = user_id`.",
        "If only your server should write here, limit the policy with `to service_role` or remove it.",
      ],
      autoFixAvailable: false,
      aiFixPrompt: `The Supabase policy on ${tableName} in ${file} uses "true" as its condition for ${action}. Rewrite it so only the row owner (auth.uid() = user_id) can access the rows.`,
      tags: ["supabase", "rls"],
    };
  }
  private missingRlsFinding(table: string, t: TableState, severity: Severity, clientSide: boolean): Finding {
    const ruleId = "authorization/supabase-missing-rls";
    return {
      id: createFindingId(CATEGORY_PREFIX.authorization, ruleId, t.file, t.line),
      ruleId,
      title: `Supabase table "${table}" has no row level security`,
      severity,
      category: "authorization",
      deployBlocking: severity === "critical",
      confidence: "high",
      file: t.file,
      line: t.line,
      evidence: sanitizeEvidence(t.text),
      plainEnglishProblem: `The table "${table}" is created without row level security (RLS), so it has no per-user access rules.`,
      whyItMatters: clientSide
        ? "Your app talks to Supabase from the browser, so the public key is visible to everyone. Without RLS anyone can read, change or delete every row in this table."
        : "Supabase exposes tables in the public schema through its API. Without RLS anyone holding your public key can read, change or delete every row in this table.",
      fixSteps: [
        `Add \`alter table public.${table} enable row level security;\` to a migration.`,
        "Add policies that only let users access their own rows, e.g. `using (auth.uid() = user_id)`.",
      ],
      autoFixAvailable: false,
      aiFixPrompt: `The table public.${table} (${t.file}) has no row level security. Write a migration that enables RLS on it and adds policies restricting each user to their own rows.`,
      tags: ["supabase", "rls"],
    };
  }

  /** Whether the project uses Supabase in code, and whether that code runs in the browser. */
  private async detectSupabaseUsage(context: ScanContext): Promise<{ used: boolean; client: boolean }> {
    let used = false;
    for (const file of context.files) {
      if (!JS_FILE_RE.test(file)) continue;
      const content = await context.readFile(file);
      const hasImport = SUPABASE_IMPORT_RE.test(content);
      const hasEnv = SUPABASE_ENV_RE.test(content);
      if (!hasImport && !hasEnv) continue;
      used = true;
      const serverOnly = /(?:^|\/)(?:server|api|functions|scripts)\//.test(file.replace(/\\/g, "/"));
      if (
        isClientFile(file, content) ||
        /createBrowserClient\s*\(/.test(content) ||
        (hasEnv && !serverOnly)
      ) {
        return { used, client: true };
      }
    }    return { used, client: false };
  }
}
