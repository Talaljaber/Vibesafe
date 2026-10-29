import {
  ID_COLUMN_RE,
  IDENTITY_NAME_RE,
  IDENTITY_VALUE_RE,
  OWNER_COLUMN_RE,
} from "../patterns/auth-patterns.js";
import type { JsSource } from "./js-source.js";
import type { TaintPath, TaintState } from "./taint.js";

/**
 * Database query chains over a {@link JsSource}, regex/bracket based (no AST):
 *
 * - Supabase: `client.from("table").select(...).eq("id", x).single()`, multi-line, with the
 *   write verb (`insert/update/upsert/delete`), its payload and the `.eq/.neq/.in/.is/.match/
 *   .filter` filters. `q = q.eq(...)` refinements of a chain bound to `q` are merged in.
 * - Prisma: `prisma.order.findUnique({ where, data })` and the other model methods.
 * - Drizzle: `db.update(t).set(x).where(eq(t.id, id))`, `db.insert(t).values(x)`,
 *   `db.delete(t).where(...)` and `db.select().from(t).where(...)`.
 *
 * Analysis runs on `src.code` (comments and strings blanked); literal values (table and
 * column names) are read from `src.text` at the same offsets. Filters whose shape cannot be
 * read (`.or("...")`, `where: filter`, nested relation filters) set `opaqueFilter` so
 * callers can stay silent instead of guessing.
 */

export type QueryOrm = "supabase" | "prisma" | "drizzle";
export type QueryVerb = "select" | "insert" | "update" | "upsert" | "delete";
/**
 * - `service-role`: a Supabase client created with the service-role key (bypasses RLS).
 * - `rls`: a Supabase client bound to the user's session or the anon key (RLS applies).
 * - `direct`: an ORM talking to the database directly (no RLS).
 * - `unknown`: a Supabase client whose origin cannot be told from this file.
 */
export type QueryClientKind = "service-role" | "rls" | "direct" | "unknown";

/** A file range with its raw text. */
export interface QueryRange {
  start: number;
  end: number;
  text: string;
}

export interface QueryFilter {
  /** Column as written (`id`, `orders.org_id`, `userId`). */
  column: string;
  /** The compared value expression. */
  value: QueryRange;
  /** 1-indexed line of the filter. */
  line: number;
}

export interface QueryChain {
  orm: QueryOrm;
  /** Offset of the receiver (`adminDb`, `prisma`) and just past the last call of the chain. */
  start: number;
  end: number;
  line: number;
  /** Receiver identifier (`adminDb`, `supabase`, `prisma`, `createAdminClient`). */
  receiver: string;
  /** Table or model name, when literal. */
  table: string | undefined;
  verb: QueryVerb;
  /** Offset and line of the verb call (`.update(`, `prisma.user.update(`). */
  verbOffset: number;
  verbLine: number;
  /** Row data written (`.update(x)`, `data: x`, `.set(x)`, `.values(x)`). */
  payload: QueryRange | undefined;
  filters: QueryFilter[];
  /** Some filter could not be read (callers should not claim the query is unscoped). */
  opaqueFilter: boolean;
  client: QueryClientKind;
}

const WRITE_VERBS: ReadonlySet<QueryVerb> = new Set(["insert", "update", "upsert", "delete"]);
const SUPABASE_VERBS: ReadonlySet<string> = new Set([
  "select",
  "insert",
  "update",
  "upsert",
  "delete",
]);
const SUPABASE_FILTERS: ReadonlySet<string> = new Set([
  "eq",
  "neq",
  "in",
  "is",
  "match",
  "filter",
  "contains",
  "like",
  "ilike",
]);
const PRISMA_VERB: Readonly<Record<string, QueryVerb>> = {
  findUnique: "select",
  findUniqueOrThrow: "select",
  findFirst: "select",
  findFirstOrThrow: "select",
  findMany: "select",
  create: "insert",
  createMany: "insert",
  update: "update",
  updateMany: "update",
  upsert: "upsert",
  delete: "delete",
  deleteMany: "delete",
};
const PRISMA_CALL_RE =
  /\b([A-Za-z_$][\w$]*)\s*\.\s*([A-Za-z_$][\w$]*)\s*\.\s*(findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|findMany|create|createMany|update|updateMany|upsert|delete|deleteMany)\s*\(/g;
const PRISMA_RECEIVER_RE = /^(?:prisma|db|tx|prismaClient)$/;
const DRIZZLE_WRITE_RE =
  /\b([A-Za-z_$][\w$]*)\s*\.\s*(update|insert|delete)\s*\(\s*([A-Za-z_$][\w$.]*)\s*\)/g;
const DRIZZLE_RECEIVER_RE = /^(?:db|tx|database|drizzle)$/i;
const MAX_CHAIN_CALLS = 30;

/** True for write verbs (`insert`, `update`, `upsert`, `delete`). */
export function isWriteVerb(verb: QueryVerb): boolean {
  return WRITE_VERBS.has(verb);
}

/** Last segment of a column (`orders.org_id` gives `org_id`). */
export function columnName(column: string): string {
  const parts = column.split(".");
  return parts[parts.length - 1] ?? column;
}

/** Tenant/user scoping column (`org_id`, `userId`, `owner`, `orders.org_id`). */
export function isOwnerColumn(column: string): boolean {
  return OWNER_COLUMN_RE.test(columnName(column));
}

/** Column identifying one row (`id`, `order_id`, `invoiceId`). */
export function isIdColumn(column: string): boolean {
  return ID_COLUMN_RE.test(columnName(column));
}

function range(src: JsSource, start: number, end: number): QueryRange {
  return { start, end, text: src.text.slice(start, end) };
}

function trimRange(src: JsSource, start: number, end: number): QueryRange {
  let s = start;
  let e = end;
  while (s < e && /\s/.test(src.code[s]!)) s++;
  while (e > s && /\s/.test(src.code[e - 1]!)) e--;
  return range(src, s, e);
}

/** Top-level comma-separated ranges of `src.code[start, end)`. */
function splitRanges(src: JsSource, start: number, end: number): QueryRange[] {
  const out: QueryRange[] = [];
  let depth = 0;
  let last = start;
  for (let i = start; i < end; i++) {
    const c = src.code[i]!;
    if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") depth--;
    else if (c === "," && depth === 0) {
      out.push(trimRange(src, last, i));
      last = i + 1;
    }
  }
  const tail = trimRange(src, last, end);
  if (tail.text !== "" || out.length > 0) out.push(tail);
  return out.filter((r) => r.text !== "");
}

/** Arguments of the call whose `(` is at `open` (empty when unbalanced). */
export function callArgs(src: JsSource, open: number): QueryRange[] {
  const close = src.matchOf(open);
  if (close <= open) return [];
  return splitRanges(src, open + 1, close);
}

/** String literal content of a range (`"orders"` gives `orders`), or undefined. */
export function literalOf(r: QueryRange | undefined): string | undefined {
  const m = r === undefined ? null : /^(["'`])([^"'`$\\]*)\1$/.exec(r.text.trim());
  return m ? m[2] : undefined;
}

export interface ObjectProp {
  /** Property key; undefined for a spread. */
  key: string | undefined;
  /** Value range (for a spread: the spread expression; for shorthand: the name). */
  value: QueryRange;
  spread: boolean;
  /** Offset of the property. */
  start: number;
}

/** Top-level properties of the object literal whose `{` is at `open` (empty when unbalanced). */
export function objectProps(src: JsSource, open: number): ObjectProp[] {
  const close = src.matchOf(open);
  if (src.code[open] !== "{" || close <= open) return [];
  const props: ObjectProp[] = [];
  for (const part of splitRanges(src, open + 1, close)) {
    const code = src.code.slice(part.start, part.end);
    if (code.startsWith("...")) {
      props.push({
        key: undefined,
        value: trimRange(src, part.start + 3, part.end),
        spread: true,
        start: part.start,
      });
      continue;
    }
    const km = /^(?:([A-Za-z_$][\w$]*)|(["'])[^"']*\2)\s*:/.exec(code);
    if (km) {
      const keyText =
        km[1] ?? src.text.slice(part.start + 1, part.start + km[0].indexOf(km[2]!, 1));
      props.push({
        key: keyText,
        value: trimRange(src, part.start + km[0].length, part.end),
        spread: false,
        start: part.start,
      });
      continue;
    }
    if (/^[A-Za-z_$][\w$]*$/.test(code)) {
      props.push({ key: code, value: part, spread: false, start: part.start });
    }
  }
  return props;
}

interface ChainCall {
  name: string;
  /** Offset of the `.` before the name, of the `(` and of the matching `)`. */
  dot: number;
  open: number;
  close: number;
}

/** `.name(args)` calls following offset `from` (just past a `)`), in order. */
function followingCalls(src: JsSource, from: number, limit: number): ChainCall[] {
  const calls: ChainCall[] = [];
  const re = /^\s*(?:\?\s*)?\.\s*([A-Za-z_$][\w$]*)\s*(?:<[^<>()]*>\s*)?\(/;
  let at = from;
  while (calls.length < MAX_CHAIN_CALLS && at < limit) {
    const m = re.exec(src.code.slice(at, Math.min(limit, at + 200)));
    if (!m) break;
    const open = at + m[0].length - 1;
    const close = src.matchOf(open);
    if (close <= open) break;
    calls.push({ name: m[1]!, dot: at + m[0].indexOf("."), open, close });
    at = close + 1;
  }
  return calls;
}

/** Receiver expression ending just before offset `dot`: an identifier or `name(...)` call. */
function receiverBefore(src: JsSource, dot: number): { name: string; start: number } | undefined {
  let i = dot - 1;
  while (i >= 0 && /\s/.test(src.code[i]!)) i--;
  if (i < 0) return undefined;
  if (src.code[i] === ")") {
    const open = src.matchOf(i);
    if (open < 0) return undefined;
    // `(await createClient()).from(...)`: look inside the parentheses
    const inner = /(?:await\s+)?([A-Za-z_$][\w$]*)\s*\(\s*\)\s*$/.exec(src.code.slice(open + 1, i));
    if (inner && /^\s*(?:await\s+)?[A-Za-z_$]/.test(src.code.slice(open + 1, i))) {
      return { name: inner[1]!, start: open };
    }
    const callee = /([A-Za-z_$][\w$]*)\s*$/.exec(src.code.slice(Math.max(0, open - 80), open));
    if (!callee) return undefined;
    return { name: callee[1]!, start: open - callee[0].length };
  }
  const id = /([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)$/.exec(
    src.code.slice(Math.max(0, i - 120), i + 1),
  );
  if (!id) return undefined;
  const name = id[1]!.split(".").pop()!.trim();
  return { name, start: i + 1 - id[0].length };
}

const SERVICE_NAME_RE = /admin|service|elevated|privileged|sudo|superuser/i;
const SERVICE_KEY_RE =
  /SERVICE_ROLE|service_?role|serviceRole|SERVICE_KEY|SUPABASE_SECRET|secretKey|SECRET_KEY/;
const RLS_FACTORY_RE =
  /\bcreate(?:\w*Server\w*|Route\w*|Browser\w*|\w*Component\w*|Middleware\w*)Client\s*\(|ANON|anon_?[kK]ey|PUBLISHABLE|\bcookies\s*\(/;

/**
 * How a Supabase receiver reaches the database: by its name (`adminDb`, `supabaseAdmin`,
 * `createAdminClient`), its declaration in the file (`createClient(url,
 * process.env.SUPABASE_SERVICE_ROLE_KEY)`, `createServerClient(...)`) or the module it is
 * imported from (`@/lib/supabase/admin`).
 */
export function resolveSupabaseClient(src: JsSource, receiver: string): QueryClientKind {
  if (SERVICE_NAME_RE.test(receiver)) return "service-role";
  if (/^create\w*(?:Server|Route|Browser|Component|Middleware)\w*Client$/.test(receiver))
    return "rls";
  const esc = receiver.replace(/\$/g, "\\$");
  const decl = new RegExp(String.raw`\b(?:const|let|var)\s+${esc}\s*(?::[^=;]+)?=\s*`).exec(
    src.code,
  );
  if (decl) {
    const rhsEnd = Math.min(src.text.length, decl.index + decl[0].length + 400);
    const rhs = src.text.slice(decl.index + decl[0].length, rhsEnd).split(";")[0] ?? "";
    if (SERVICE_KEY_RE.test(rhs) || /\bcreate\w*(?:Admin|Service)\w*\s*\(/i.test(rhs))
      return "service-role";
    if (RLS_FACTORY_RE.test(rhs) || /^\s*await\s+createClient\s*\(\s*\)/.test(rhs)) return "rls";
    return "unknown";
  }
  const imp = new RegExp(
    String.raw`\bimport\s+(?:type\s+)?(?:\{[^}]*\b${esc}\b[^}]*\}|${esc})[^;]*?from\s*["']([^"']+)["']`,
  ).exec(src.text);
  if (imp && SERVICE_NAME_RE.test(imp[1]!)) return "service-role";
  return "unknown";
}

/** Filters of supabase calls (`eq`, `match`, `filter`, ...); sets `opaque` for `or`/unreadable ones. */
function supabaseFilters(src: JsSource, calls: readonly ChainCall[], out: QueryFilter[]): boolean {
  let opaque = false;
  for (const c of calls) {
    if (c.name === "or" || c.name === "not") {
      opaque = true;
      continue;
    }
    if (!SUPABASE_FILTERS.has(c.name)) continue;
    const args = callArgs(src, c.open);
    if (c.name === "match") {
      const arg = args[0];
      if (arg === undefined || src.code[arg.start] !== "{") {
        opaque = true;
        continue;
      }
      for (const p of objectProps(src, arg.start)) {
        if (p.spread || p.key === undefined) opaque = true;
        else out.push({ column: p.key, value: p.value, line: src.lineAt(p.start) });
      }
      continue;
    }
    const column = literalOf(args[0]);
    const value = c.name === "filter" ? args[2] : args[1];
    if (column === undefined || value === undefined) {
      opaque = true;
      continue;
    }
    out.push({ column, value, line: src.lineAt(c.dot) });
  }
  return opaque;
}

/** Merges `q = q.eq(...)` / `q.eq(...)` refinements of a chain bound to `name` (before `limit`). */
function refinements(src: JsSource, name: string, from: number, limit: number): ChainCall[] {
  const esc = name.replace(/\$/g, "\\$");
  const re = new RegExp(String.raw`\b${esc}(?=\s*\??\.\s*[A-Za-z_$][\w$]*\s*\()`, "g");
  re.lastIndex = from;
  const calls: ChainCall[] = [];
  const code = src.code.slice(0, limit);
  for (let m = re.exec(code); m; m = re.exec(code)) {
    const end = m.index + m[0].length;
    calls.push(...followingCalls(src, end, limit));
    if (calls.length > MAX_CHAIN_CALLS) break;
  }
  return calls;
}

function boundName(src: JsSource, start: number): string | undefined {
  const m = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;]+)?=\s*(?:await\s+)?$/.exec(
    src.code.slice(Math.max(0, start - 120), start),
  );
  return m?.[1];
}

function supabaseChains(src: JsSource, from: number, to: number, out: QueryChain[]): void {
  const re = /\.\s*from\s*\(/g;
  re.lastIndex = from;
  for (let m = re.exec(src.code); m && m.index < to; m = re.exec(src.code)) {
    const dot = m.index;
    const open = dot + m[0].length - 1;
    const tableArg = callArgs(src, open)[0];
    const table = literalOf(tableArg);
    if (table === undefined) continue; // drizzle `.from(table)` or not a query
    const recv = receiverBefore(src, dot);
    if (recv === undefined || recv.name === "storage") continue;
    const close = src.matchOf(open);
    if (close < 0) continue;
    const calls = followingCalls(src, close + 1, src.code.length);
    const verbCall = calls.find((c) => SUPABASE_VERBS.has(c.name));
    if (verbCall === undefined && !calls.some((c) => SUPABASE_FILTERS.has(c.name))) continue;
    const verb = (verbCall?.name ?? "select") as QueryVerb;
    const filters: QueryFilter[] = [];
    let opaque = supabaseFilters(src, calls, filters);
    const end = calls.length > 0 ? calls[calls.length - 1]!.close + 1 : close + 1;
    const bound = boundName(src, recv.start);
    if (bound !== undefined) {
      const more = refinements(src, bound, end, Math.min(src.code.length, end + 4000));
      opaque = supabaseFilters(src, more, filters) || opaque;
    }
    const payloadArg =
      verbCall && isWriteVerb(verb) && verb !== "delete"
        ? callArgs(src, verbCall.open)[0]
        : undefined;
    const verbOffset = verbCall?.dot ?? dot;
    out.push({
      orm: "supabase",
      start: recv.start,
      end,
      line: src.lineAt(recv.start),
      receiver: recv.name,
      table,
      verb,
      verbOffset,
      verbLine: src.lineAt(verbOffset),
      payload: payloadArg,
      filters,
      opaqueFilter: opaque,
      client: resolveSupabaseClient(src, recv.name),
    });
  }
}

/**
 * Filters of a Prisma `where: { ... }` object. Operator objects (`id: { equals: x }`) are
 * read; relation filters, compound keys, `AND/OR/NOT` and spreads make it opaque.
 */
function prismaWhere(src: JsSource, where: QueryRange | undefined, out: QueryFilter[]): boolean {
  if (where === undefined) return false;
  if (src.code[where.start] !== "{") return true;
  let opaque = false;
  for (const p of objectProps(src, where.start)) {
    if (p.spread || p.key === undefined || /^(?:AND|OR|NOT)$/.test(p.key)) {
      opaque = true;
      continue;
    }
    if (src.code[p.value.start] === "{") {
      const inner = objectProps(src, p.value.start);
      const eq = inner.find((q) => q.key === "equals");
      if (
        eq !== undefined &&
        inner.every((q) => !q.spread && /^(?:equals|mode)$/.test(q.key ?? ""))
      )
        out.push({ column: p.key, value: eq.value, line: src.lineAt(p.start) });
      else opaque = true;
      continue;
    }
    out.push({ column: p.key, value: p.value, line: src.lineAt(p.start) });
  }
  return opaque;
}

function prismaChains(src: JsSource, from: number, to: number, out: QueryChain[]): void {
  PRISMA_CALL_RE.lastIndex = from;
  for (
    let m = PRISMA_CALL_RE.exec(src.code);
    m && m.index < to;
    m = PRISMA_CALL_RE.exec(src.code)
  ) {
    const receiver = m[1]!;
    if (!PRISMA_RECEIVER_RE.test(receiver)) continue;
    const verb = PRISMA_VERB[m[3]!]!;
    const open = m.index + m[0].length - 1;
    const close = src.matchOf(open);
    if (close < 0) continue;
    const arg = callArgs(src, open)[0];
    const filters: QueryFilter[] = [];
    let opaque = false;
    let payload: QueryRange | undefined;
    if (arg !== undefined && src.code[arg.start] === "{") {
      const props = objectProps(src, arg.start);
      const where = props.find((p) => p.key === "where");
      opaque = prismaWhere(src, where?.value, filters);
      if (where === undefined && verb !== "insert" && props.some((p) => p.spread)) opaque = true;
      payload = props.find((p) => p.key === "data")?.value;
      if (verb === "upsert") payload = props.find((p) => p.key === "create")?.value ?? payload;
    } else if (arg !== undefined) {
      opaque = true;
    }
    const verbOffset = m.index + m[0].lastIndexOf(m[3]!);
    out.push({
      orm: "prisma",
      start: m.index,
      end: close + 1,
      line: src.lineAt(m.index),
      receiver,
      table: m[2]!,
      verb,
      verbOffset,
      verbLine: src.lineAt(verbOffset),
      payload,
      filters,
      opaqueFilter: opaque,
      client: "direct",
    });
  }
}

/** `eq(t.col, value)` comparisons inside a Drizzle `.where(...)`; `or(`/`sql` make it opaque. */
function drizzleWhere(src: JsSource, call: ChainCall | undefined, out: QueryFilter[]): boolean {
  if (call === undefined) return false;
  const body = src.code.slice(call.open + 1, call.close);
  if (/\b(?:or|not|sql)\s*[(`]/.test(body)) return true;
  const re = /\beq\s*\(/g;
  for (let m = re.exec(body); m; m = re.exec(body)) {
    const open = call.open + 1 + m.index + m[0].length - 1;
    const args = callArgs(src, open);
    const col = /\.\s*([A-Za-z_$][\w$]*)\s*$/.exec(args[0]?.text ?? "");
    if (!col || args[1] === undefined) return true;
    out.push({ column: col[1]!, value: args[1], line: src.lineAt(open) });
  }
  return false;
}

function drizzleChains(src: JsSource, from: number, to: number, out: QueryChain[]): void {
  DRIZZLE_WRITE_RE.lastIndex = from;
  for (
    let m = DRIZZLE_WRITE_RE.exec(src.code);
    m && m.index < to;
    m = DRIZZLE_WRITE_RE.exec(src.code)
  ) {
    if (!DRIZZLE_RECEIVER_RE.test(m[1]!)) continue;
    const open = m.index + m[0].indexOf("(");
    const close = src.matchOf(open);
    if (close < 0) continue;
    const calls = followingCalls(src, close + 1, src.code.length);
    const verb = m[2] as QueryVerb;
    const filters: QueryFilter[] = [];
    const opaque = drizzleWhere(
      src,
      calls.find((c) => c.name === "where"),
      filters,
    );
    const pc = calls.find((c) => c.name === (verb === "insert" ? "values" : "set"));
    const verbOffset = m.index + m[0].indexOf(m[2]!);
    out.push({
      orm: "drizzle",
      start: m.index,
      end: calls.length > 0 ? calls[calls.length - 1]!.close + 1 : close + 1,
      line: src.lineAt(m.index),
      receiver: m[1]!,
      table: m[3]!.split(".").pop(),
      verb,
      verbOffset,
      verbLine: src.lineAt(verbOffset),
      payload: pc ? callArgs(src, pc.open)[0] : undefined,
      filters,
      opaqueFilter: opaque,
      client: "direct",
    });
  }
  const sel = /\b([A-Za-z_$][\w$]*)\s*\.\s*select\s*\(/g;
  sel.lastIndex = from;
  for (let m = sel.exec(src.code); m && m.index < to; m = sel.exec(src.code)) {
    if (!DRIZZLE_RECEIVER_RE.test(m[1]!)) continue;
    const open = m.index + m[0].length - 1;
    const close = src.matchOf(open);
    if (close < 0) continue;
    const calls = followingCalls(src, close + 1, src.code.length);
    const fromCall = calls[0];
    if (fromCall?.name !== "from") continue;
    const tableArg = callArgs(src, fromCall.open)[0];
    if (tableArg === undefined || literalOf(tableArg) !== undefined) continue;
    const filters: QueryFilter[] = [];
    const opaque = drizzleWhere(
      src,
      calls.find((c) => c.name === "where"),
      filters,
    );
    out.push({
      orm: "drizzle",
      start: m.index,
      end: calls[calls.length - 1]!.close + 1,
      line: src.lineAt(m.index),
      receiver: m[1]!,
      table: tableArg.text.split(".").pop(),
      verb: "select",
      verbOffset: m.index,
      verbLine: src.lineAt(m.index),
      payload: undefined,
      filters,
      opaqueFilter: opaque,
      client: "direct",
    });
  }
}

/**
 * Query chains whose start lies in `[from, to)` (default: the whole file), in source order.
 * Never throws: unbalanced or unreadable calls are skipped.
 */
export function extractQueryChains(src: JsSource, from = 0, to = src.text.length): QueryChain[] {
  const out: QueryChain[] = [];
  try {
    if (src.code.includes("from")) supabaseChains(src, from, to, out);
    if (/\.\s*(?:find|create|update|upsert|delete)/.test(src.code))
      prismaChains(src, from, to, out);
    if (/\.\s*(?:update|insert|delete|select)\s*\(/.test(src.code))
      drizzleChains(src, from, to, out);
  } catch {
    // best effort: never throw from a detector helper
  }
  return out.filter((c) => c.start >= from && c.start < to).sort((a, b) => a.start - b.start);
}

/** `range` of `src` as a {@link QueryRange} (exported for detectors building ranges). */
export function queryRange(src: JsSource, start: number, end: number): QueryRange {
  return range(src, start, end);
}

/** Where a query value comes from, when the request controls it. */
export interface RequestValue {
  path: TaintPath;
  /** Human label (`route parameters`, `query string`, `request body`). */
  label: string;
}

/**
 * Sources whose `indirect` hits are still the caller's choice: server action arguments are
 * seeded as parameters (any client can call the action with any value).
 */
export const SEEDED_SOURCES: ReadonlySet<string> = new Set(["server-action-argument"]);

const REQUEST_TEXT_RE =
  /\b(?:params|searchParams|query)\b|\b(?:req|request)\s*\.\s*(?:body|query|params)\b/;

function declarationOf(src: JsSource, name: string, before: number): string | undefined {
  const esc = name.replace(/\$/g, "\\$&");
  const re = new RegExp(
    String.raw`\b(?:const|let|var)\s+(?:\{[^}]*\b${esc}\b[^}]*\}|\[[^\]]*\b${esc}\b[^\]]*\]|${esc})\s*(?::[^=;\n]+)?=\s*([^;\n]+)`,
    "g",
  );
  let rhs: string | undefined;
  for (const m of src.text.slice(Math.max(0, before - 4000), before).matchAll(re)) rhs = m[1];
  return rhs;
}

/**
 * The request origin of value `r` inside a handler analysed by `state`: route params, the
 * query string, the body or a server action argument, through any path (schema validation
 * does not matter here: a validated id is still chosen by the caller). Values derived from
 * the authenticated identity (`session.user.id`, `user.id`, `req.user.id`, a local bound
 * from them) are never request values. Numeric coercion (`Number(params.id)`) is seen through.
 */
export function requestValue(
  state: TaintState,
  src: JsSource,
  r: QueryRange,
): RequestValue | undefined {
  const text = r.text.trim();
  if (text === "" || IDENTITY_VALUE_RE.test(text)) return undefined;
  const hit = state.exprTaint(r.start, r.end);
  // `indirect` through an unknown call (`const row = await db.find(id)`) is the call's
  // result, not the caller's choice; server action arguments are the caller's choice
  // whatever the path.
  if (
    hit !== undefined &&
    hit.trust === "remote" &&
    (hit.path !== "indirect" || SEEDED_SOURCES.has(hit.source.id))
  ) {
    if (hit.via !== undefined) {
      if (IDENTITY_NAME_RE.test(hit.via)) return undefined;
      const rhs = declarationOf(src, hit.via, r.start);
      if (rhs !== undefined && IDENTITY_VALUE_RE.test(rhs)) return undefined;
    }
    return { path: hit.path, label: hit.source.label };
  }
  if (REQUEST_TEXT_RE.test(text)) return { path: "direct", label: "request data" };
  const id = /^[A-Za-z_$][\w$]*$/.exec(text);
  if (id) {
    const rhs = declarationOf(src, id[0], r.start);
    if (rhs !== undefined && !IDENTITY_VALUE_RE.test(rhs) && REQUEST_TEXT_RE.test(rhs))
      return { path: "binding", label: "request data" };
  }
  return undefined;
}
