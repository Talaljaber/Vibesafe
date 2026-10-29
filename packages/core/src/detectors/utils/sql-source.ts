// ─────────────────────────────────────────────────────────────────────────────
// SQL source helpers for the Supabase / Postgres detectors.
//
// Line-and-token level only (no SQL grammar): statement splitting that respects
// strings, E'' escapes, quoted identifiers, dollar-quoted bodies, nested
// comments, BEGIN ATOMIC bodies, COPY ... FROM stdin data and psql
// meta-commands, plus small parsers for the statements the detectors reason
// about (policies, grants, functions, tables) and an equality extractor for
// policy expressions. Every function is total: malformed input yields `null`
// or an empty result, never an exception.
// ─────────────────────────────────────────────────────────────────────────────

/** Matches one SQL identifier, quoted (`"Foo"""`) or bare (`foo$1`). */
export const SQL_IDENT = String.raw`(?:"(?:[^"]|"")+"|[A-Za-z_][\w$]*)`;
/** Optional `schema.` followed by a name; captures (schema, name). */
const QUAL = String.raw`(?:(${SQL_IDENT})\s*\.\s*)?(${SQL_IDENT})`;

const isIdentStart = (c: string | undefined): boolean => c !== undefined && /[A-Za-z_]/.test(c);
const isIdentChar = (c: string | undefined): boolean => c !== undefined && /[\w$]/.test(c);

/** Index just past the closing quote of the `'...'` string opening at `i` (sql.length if unclosed). */
function skipString(sql: string, i: number): number {
  const escapes = (sql[i - 1] === "e" || sql[i - 1] === "E") && !isIdentChar(sql[i - 2]);
  let j = i + 1;
  while (j < sql.length) {
    const c = sql[j];
    if (escapes && c === "\\") {
      j += 2;
      continue;
    }
    if (c === "'") {
      if (sql[j + 1] === "'") {
        j += 2;
        continue;
      }
      return j + 1;
    }
    j++;
  }
  return sql.length;
}

/** Index just past the closing quote of the `"..."` identifier opening at `i`. */
function skipQuotedIdent(sql: string, i: number): number {
  let j = i + 1;
  while (j < sql.length) {
    if (sql[j] === '"') {
      if (sql[j + 1] === '"') {
        j += 2;
        continue;
      }
      return j + 1;
    }
    j++;
  }
  return sql.length;
}

/** The `$tag$` opening at `i`, or null when `$` does not start a dollar quote there. */
function dollarTagAt(sql: string, i: number): string | null {
  if (sql[i] !== "$" || isIdentChar(sql[i - 1])) return null;
  const m = /^\$(?:[A-Za-z_]\w*)?\$/.exec(sql.slice(i, i + 64));
  return m ? m[0] : null;
}

/** Index just past the comment starting at `i` (`--` or nested `/* *\/`). */
function skipComment(sql: string, i: number): number {
  if (sql[i + 1] === "-") {
    const nl = sql.indexOf("\n", i);
    return nl === -1 ? sql.length : nl;
  }
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
  return j;
}

const isCommentStart = (sql: string, i: number): boolean =>
  (sql[i] === "-" && sql[i + 1] === "-") || (sql[i] === "/" && sql[i + 1] === "*");

/**
 * Replaces comments and string / dollar-quoted bodies with spaces, preserving
 * offsets and newlines. String quotes are kept (`'   '`); quoted identifiers are
 * kept verbatim. E'' strings honour backslash escapes.
 */
export function stripSqlNoise(sql: string): string {
  const out: string[] = [];
  const blank = (s: string) => s.replace(/[^\n]/g, " ");
  let i = 0;
  while (i < sql.length) {
    const c = sql[i]!;
    if (isCommentStart(sql, i)) {
      const j = skipComment(sql, i);
      out.push(blank(sql.slice(i, j)));
      i = j;
    } else if (c === "'") {
      const j = skipString(sql, i);
      const closed = j <= sql.length && sql[j - 1] === "'" && j - 1 > i;
      out.push("'" + blank(sql.slice(i + 1, closed ? j - 1 : j)) + (closed ? "'" : ""));
      i = j;
    } else if (c === '"') {
      const j = skipQuotedIdent(sql, i);
      out.push(sql.slice(i, j));
      i = j;
    } else if (c === "$") {
      const tag = dollarTagAt(sql, i);
      if (tag) {
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

/** One top-level SQL statement. */
export interface SqlStatement {
  /** Offset of the statement's first character in the file. */
  start: number;
  /** Offset just past its last character (the terminating `;` is excluded). */
  end: number;
  /** Raw statement text. */
  text: string;
  /** `text` with comments and string / dollar bodies blanked (same length). */
  code: string;
}

/**
 * Splits a SQL file into top-level statements at `;` outside parentheses,
 * strings, quoted identifiers, dollar-quoted bodies, comments and
 * `BEGIN ATOMIC ... END` bodies. `COPY ... FROM stdin` data (up to the `\.`
 * line) and psql meta-commands (`\connect`, `\set`, ...) are skipped. A final
 * statement without `;` is kept.
 */
export function splitSqlStatements(sql: string): SqlStatement[] {
  const out: SqlStatement[] = [];
  let i = 0;
  let start = -1;
  let depth = 0;
  let atomic = 0;
  let prevWord = "";

  const emit = (endExclusive: number): SqlStatement | null => {
    if (start < 0) return null;
    let end = endExclusive;
    while (end > start && /\s/.test(sql[end - 1]!)) end--;
    const text = sql.slice(start, end);
    const stmt = { start, end, text, code: stripSqlNoise(text) };
    out.push(stmt);
    start = -1;
    depth = 0;
    atomic = 0;
    prevWord = "";
    return stmt;
  };

  while (i < sql.length) {
    const c = sql[i]!;
    if (/\s/.test(c)) {
      i++;
      continue;
    }
    if (isCommentStart(sql, i)) {
      i = skipComment(sql, i);
      continue;
    }
    if (start < 0 && c === "\\") {
      // psql meta-command: runs to the end of the line.
      const nl = sql.indexOf("\n", i);
      i = nl === -1 ? sql.length : nl + 1;
      continue;
    }
    if (start < 0) start = i;
    if (c === "'") {
      i = skipString(sql, i);
      prevWord = "";
      continue;
    }
    if (c === '"') {
      i = skipQuotedIdent(sql, i);
      prevWord = "";
      continue;
    }
    if (c === "$") {
      const tag = dollarTagAt(sql, i);
      if (tag) {
        const close = sql.indexOf(tag, i + tag.length);
        i = close === -1 ? sql.length : close + tag.length;
        prevWord = "";
        continue;
      }
    }
    if (isIdentStart(c) && !isIdentChar(sql[i - 1])) {
      let j = i + 1;
      while (isIdentChar(sql[j])) j++;
      const word = sql.slice(i, j).toLowerCase();
      if (atomic > 0) {
        if (word === "case") atomic++;
        else if (word === "end") atomic--;
      } else if (word === "atomic" && prevWord === "begin") {
        atomic = 1;
      }
      prevWord = word;
      i = j;
      continue;
    }
    if (c === "(") depth++;
    else if (c === ")") depth = Math.max(0, depth - 1);
    else if (c === ";" && depth === 0 && atomic === 0) {
      const stmt = emit(i);
      i++;
      if (stmt && /^copy\b/i.test(stmt.code) && /\bfrom\s+stdin\b/i.test(stmt.code)) {
        // Skip the data block, which ends with a line holding only `\.`.
        let nl = sql.indexOf("\n", i);
        while (nl !== -1) {
          const next = sql.indexOf("\n", nl + 1);
          const line = sql.slice(nl + 1, next === -1 ? sql.length : next).replace(/\r$/, "");
          if (line === "\\.") {
            nl = next;
            break;
          }
          nl = next;
        }
        i = nl === -1 ? sql.length : nl + 1;
      }
      continue;
    }
    prevWord = "";
    i++;
  }
  emit(sql.length);
  return out;
}

/** Maps file offsets to 1-based line numbers. */
export function createLineLocator(text: string): (offset: number) => number {
  const newlines: number[] = [];
  for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1)) newlines.push(i);
  return (offset: number) => {
    let lo = 0;
    let hi = newlines.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (newlines[mid]! < offset) lo = mid + 1;
      else hi = mid;
    }
    return lo + 1;
  };
}

/** Unquotes a quoted identifier (case kept) or lower-cases a bare one. */
export function normalizeSqlIdent(raw: string): string {
  return raw.startsWith('"') ? raw.slice(1, -1).replace(/""/g, '"') : raw.toLowerCase();
}

/** A possibly schema-qualified object name, normalized. */
export interface QualifiedName {
  /** Explicit schema, or undefined when unqualified. */
  schema: string | undefined;
  name: string;
}

/** `schema.name` key; unqualified names default to `public`. */
export function qualifiedKey(q: QualifiedName): string {
  return `${q.schema ?? "public"}.${q.name}`;
}

const qual = (schema: string | undefined, name: string): QualifiedName => ({
  schema: schema === undefined ? undefined : normalizeSqlIdent(schema),
  name: normalizeSqlIdent(name),
});

/** Index of the `)` matching the `(` at `open` in stripped code, or -1. */
function matchParen(code: string, open: number): number {
  let depth = 0;
  for (let j = open; j < code.length; j++) {
    const c = code[j];
    if (c === '"') {
      j = skipQuotedIdent(code, j) - 1;
    } else if (c === "(") depth++;
    else if (c === ")" && --depth === 0) return j;
  }
  return -1;
}

/** Splits `text` at top-level commas (outside parentheses and quoted identifiers). */
function splitTopLevel(text: string, sep = ","): { part: string; offset: number }[] {
  const out: { part: string; offset: number }[] = [];
  let depth = 0;
  let last = 0;
  for (let j = 0; j < text.length; j++) {
    const c = text[j];
    if (c === '"') j = skipQuotedIdent(text, j) - 1;
    else if (c === "(") depth++;
    else if (c === ")") depth--;
    else if (c === sep && depth === 0) {
      out.push({ part: text.slice(last, j), offset: last });
      last = j + 1;
    }
  }
  out.push({ part: text.slice(last), offset: last });
  return out;
}

/** True when an expression is literally `true` (or `1 = 1`), ignoring parentheses. */
export function isAlwaysTrueExpr(expr: string | null | undefined): boolean {
  if (expr === null || expr === undefined) return false;
  let e = expr.trim();
  while (e.startsWith("(") && e.endsWith(")") && matchParen(e, 0) === e.length - 1) {
    e = e.slice(1, -1).trim();
  }
  return /^true$/i.test(e) || /^1\s*=\s*1$/.test(e);
}

// ── Policies ────────────────────────────────────────────────────────────────

/** A `using (...)` or `with check (...)` clause. */
export interface PolicyClause {
  /** Expression inside the parentheses (stripped code). */
  expr: string;
  /** Offset of the clause keyword in the statement. */
  offset: number;
  /** Offset of the expression's first character in the statement. */
  exprOffset: number;
}

export type PolicyCommand = "all" | "select" | "insert" | "update" | "delete";

/** A parsed `create / alter / drop policy` statement. */
export interface ParsedPolicy {
  op: "create" | "alter" | "drop" | "rename";
  name: string;
  table: QualifiedName;
  restrictive: boolean | undefined;
  cmd: PolicyCommand | undefined;
  /** Lower-cased role names (quotes removed), or undefined when no `to` clause. */
  roles: string[] | undefined;
  using: PolicyClause | undefined;
  check: PolicyClause | undefined;
  newName: string | undefined;
}

const POLICY_HEAD_RE = new RegExp(
  String.raw`^(create\s+(?:or\s+replace\s+)?|alter\s+|drop\s+)policy\s+(?:if\s+exists\s+)?(${SQL_IDENT})\s+on\s+${QUAL}`,
  "i",
);

/** Parses a policy statement, or returns null for any other statement. */
export function parsePolicy(stmt: SqlStatement): ParsedPolicy | null {
  const code = stmt.code;
  const m = POLICY_HEAD_RE.exec(code);
  if (!m) return null;
  const verb = m[1]!.trim().split(/\s+/)[0]!.toLowerCase();
  const policy: ParsedPolicy = {
    op: verb === "create" ? "create" : verb === "drop" ? "drop" : "alter",
    name: normalizeSqlIdent(m[2]!),
    table: qual(m[3], m[4]!),
    restrictive: undefined,
    cmd: undefined,
    roles: undefined,
    using: undefined,
    check: undefined,
    newName: undefined,
  };
  if (policy.op === "drop") return policy;
  let i = m[0].length;
  for (let guard = 0; guard < 16 && i < code.length; guard++) {
    while (i < code.length && /\s/.test(code[i]!)) i++;
    const rest = code.slice(i);
    let k: RegExpExecArray | null;
    if ((k = /^as\s+(permissive|restrictive)\b/i.exec(rest))) {
      policy.restrictive = k[1]!.toLowerCase() === "restrictive";
      i += k[0].length;
    } else if ((k = /^for\s+(all|select|insert|update|delete)\b/i.exec(rest))) {
      policy.cmd = k[1]!.toLowerCase() as PolicyCommand;
      i += k[0].length;
    } else if ((k = /^rename\s+to\s+/i.exec(rest))) {
      const n = new RegExp(`^${SQL_IDENT}`).exec(rest.slice(k[0].length));
      if (!n) break;
      policy.op = "rename";
      policy.newName = normalizeSqlIdent(n[0]);
      i += k[0].length + n[0].length;
    } else if ((k = /^to\s+/i.exec(rest))) {
      const list = new RegExp(String.raw`^${SQL_IDENT}(?:\s*,\s*${SQL_IDENT})*`).exec(
        rest.slice(k[0].length),
      );
      if (!list) break;
      policy.roles = list[0].split(",").map((r) => normalizeSqlIdent(r.trim()).toLowerCase());
      i += k[0].length + list[0].length;
    } else if ((k = /^(using|with\s+check)\s*\(/i.exec(rest))) {
      const open = i + k[0].length - 1;
      const close = matchParen(code, open);
      if (close === -1) break;
      const clause: PolicyClause = {
        expr: code.slice(open + 1, close),
        offset: i,
        exprOffset: open + 1,
      };
      if (/^using/i.test(k[1]!)) policy.using = clause;
      else policy.check = clause;
      i = close + 1;
    } else break;
  }
  return policy;
}

// ── Grants ──────────────────────────────────────────────────────────────────

/** A parsed `grant ... on ... to ...` / `revoke ... on ... from ...` statement. */
export interface ParsedGrant {
  action: "grant" | "revoke";
  /** Lower-cased privileges; `all` / `all privileges` become `all`. */
  privileges: string[];
  /** True when any privilege carries a column list (`update (a, b)`). */
  columnLevel: boolean;
  targetType: "table" | "all-tables" | "function" | "all-functions" | "schema" | "other";
  /** Named objects (tables or functions) or, for `all ... in schema` and `schema`, schemas. */
  objects: QualifiedName[];
  /** Lower-cased grantees (quotes removed); `public` is the PUBLIC pseudo-role. */
  grantees: string[];
}

const PRIV_WORDS = new Set([
  "all",
  "privileges",
  "select",
  "insert",
  "update",
  "delete",
  "truncate",
  "references",
  "trigger",
  "execute",
  "usage",
  "create",
  "connect",
  "temporary",
  "temp",
  "maintain",
]);

/** Parses a grant / revoke of object privileges; role-membership grants return null. */
export function parseGrant(stmt: SqlStatement): ParsedGrant | null {
  const code = stmt.code;
  const head = /^(grant|revoke)\s+(?:grant\s+option\s+for\s+)?/i.exec(code);
  if (!head) return null;
  const action = head[1]!.toLowerCase() as "grant" | "revoke";
  // Privilege list up to the top-level `on`.
  let i = head[0].length;
  let depth = 0;
  let onAt = -1;
  for (let j = i; j < code.length; j++) {
    const c = code[j];
    if (c === "(") depth++;
    else if (c === ")") depth--;
    else if (
      depth === 0 &&
      /\s/.test(code[j - 1] ?? " ") &&
      /^on\s/i.test(code.slice(j, j + 3)) &&
      !isIdentChar(code[j - 1])
    ) {
      onAt = j;
      break;
    }
  }
  if (onAt === -1) return null;
  const privText = code.slice(i, onAt);
  const privileges: string[] = [];
  let columnLevel = false;
  for (const { part } of splitTopLevel(privText)) {
    const p = part.trim();
    if (p === "") continue;
    if (p.includes("(")) columnLevel = true;
    const word = /^[A-Za-z]+/.exec(p)?.[0]?.toLowerCase();
    if (!word || !PRIV_WORDS.has(word)) return null;
    privileges.push(word === "privileges" ? "all" : word);
  }
  if (privileges.length === 0) return null;

  i = onAt + 2;
  const rest = code.slice(i);
  const toRe = action === "grant" ? /\bto\b/i : /\bfrom\b/i;
  let targetType: ParsedGrant["targetType"] = "table";
  let objText: string;
  let kw: RegExpExecArray | null;
  if (
    (kw = /^\s*all\s+(tables|functions|routines|procedures|sequences)\s+in\s+schema\s+/i.exec(rest))
  ) {
    const kind = kw[1]!.toLowerCase();
    targetType =
      kind === "tables" ? "all-tables" : kind === "sequences" ? "other" : "all-functions";
    objText = rest.slice(kw[0].length);
  } else if ((kw = /^\s*(function|procedure|routine)\s+/i.exec(rest))) {
    targetType = "function";
    objText = rest.slice(kw[0].length);
  } else if ((kw = /^\s*schema\s+/i.exec(rest))) {
    targetType = "schema";
    objText = rest.slice(kw[0].length);
  } else if ((kw = /^\s*table\s+/i.exec(rest))) {
    objText = rest.slice(kw[0].length);
  } else if (
    /^\s*(?:sequence|database|domain|foreign|language|large|parameter|tablespace|type)\b/i.test(
      rest,
    )
  ) {
    targetType = "other";
    objText = rest;
  } else {
    objText = rest;
  }

  // Object list up to the top-level `to` / `from`.
  depth = 0;
  let toAt = -1;
  for (let j = 0; j < objText.length; j++) {
    const c = objText[j];
    if (c === '"') j = skipQuotedIdent(objText, j) - 1;
    else if (c === "(") depth++;
    else if (c === ")") depth--;
    else if (depth === 0 && !isIdentChar(objText[j - 1])) {
      const t = toRe.exec(objText.slice(j, j + 5));
      if (t && t.index === 0) {
        toAt = j;
        break;
      }
    }
  }
  if (toAt === -1) return null;
  const objects: QualifiedName[] = [];
  if (targetType !== "other") {
    for (const { part } of splitTopLevel(objText.slice(0, toAt))) {
      const o = new RegExp(String.raw`^\s*${QUAL}`).exec(part);
      if (!o) continue;
      if (targetType === "schema" || targetType === "all-tables" || targetType === "all-functions")
        objects.push({ schema: undefined, name: normalizeSqlIdent(o[2]!) });
      else objects.push(qual(o[1], o[2]!));
    }
  }
  const granteeText = objText
    .slice(toAt)
    .replace(toRe, "")
    .split(/\b(?:with\s+grant\s+option|with\s+admin|granted\s+by|cascade|restrict)\b/i)[0]!;
  const grantees = granteeText
    .split(",")
    .map((g) => g.trim())
    .filter((g) => g !== "")
    .map((g) => normalizeSqlIdent(g.replace(/^group\s+/i, "")).toLowerCase());
  return { action, privileges, columnLevel, targetType, objects, grantees };
}

// ── Functions ───────────────────────────────────────────────────────────────

/** A parsed `create [or replace] function|procedure` statement. */
export interface ParsedFunction {
  fn: QualifiedName;
  kind: "function" | "procedure";
  securityDefiner: boolean;
  /** True when the definition pins `search_path` (`set search_path = ...`). */
  searchPath: boolean;
  /** `returns trigger` / `returns event_trigger`. */
  returnsTrigger: boolean;
  /** Raw body text (dollar-quoted, string or BEGIN ATOMIC), or "" when not found. */
  body: string;
  /** Offset of the body in the statement (-1 when not found). */
  bodyOffset: number;
  /** Offset of `security definer` in the statement (-1 when absent). */
  definerOffset: number;
}

const FUNCTION_HEAD_RE = new RegExp(
  String.raw`^create\s+(?:or\s+replace\s+)?(function|procedure)\s+${QUAL}\s*\(`,
  "i",
);

/** Parses a function / procedure definition, or returns null for any other statement. */
export function parseCreateFunction(stmt: SqlStatement): ParsedFunction | null {
  const { code, text } = stmt;
  const m = FUNCTION_HEAD_RE.exec(code);
  if (!m) return null;
  const close = matchParen(code, m[0].length - 1);
  if (close === -1) return null;
  const tail = code.slice(close + 1);
  const at = (re: RegExp): number => {
    const r = re.exec(tail);
    return r ? close + 1 + r.index : -1;
  };
  const definerOffset = at(/\bsecurity\s+definer\b/i);
  let body = "";
  let bodyOffset = -1;
  // Bodies are blanked in `code`, so find `as` there and read the quote from `text`.
  for (const as of tail.matchAll(/\bas\b/gi)) {
    let s = close + 1 + as.index + as[0].length;
    while (s < text.length && /\s/.test(text[s]!)) s++;
    const tag = dollarTagAt(text, s);
    if (tag) {
      const end = text.indexOf(tag, s + tag.length);
      if (end !== -1) {
        body = text.slice(s + tag.length, end);
        bodyOffset = s + tag.length;
      }
      break;
    }
    if (text[s] === "'") {
      const end = skipString(text, s);
      body = text.slice(s + 1, Math.max(s + 1, end - 1));
      bodyOffset = s + 1;
      break;
    }
  }
  if (bodyOffset === -1) {
    const atomic = /\bbegin\s+atomic\b/i.exec(tail);
    if (atomic) {
      bodyOffset = close + 1 + atomic.index;
      body = text.slice(bodyOffset);
    }
  }
  return {
    fn: qual(m[2], m[3]!),
    kind: m[1]!.toLowerCase() as "function" | "procedure",
    securityDefiner: definerOffset !== -1,
    searchPath: /\bset\s+"?search_path"?\s*(?:=|\bto\b|\bfrom\s+current\b)/i.test(tail),
    returnsTrigger: /\breturns\s+"?(?:event_)?trigger"?/i.test(tail),
    body,
    bodyOffset,
    definerOffset,
  };
}

/** A parsed `alter function|procedure|routine` statement (only the parts the detectors use). */
export interface ParsedAlterFunction {
  fn: QualifiedName;
  /** true for `set search_path`, false for `reset search_path` / `reset all`. */
  searchPath: boolean | undefined;
  security: "definer" | "invoker" | undefined;
  renameTo: string | undefined;
}

const ALTER_FUNCTION_RE = new RegExp(
  String.raw`^alter\s+(?:function|procedure|routine)\s+${QUAL}\s*(\()?`,
  "i",
);

/** Parses `alter function ...`, or returns null for any other statement. */
export function parseAlterFunction(stmt: SqlStatement): ParsedAlterFunction | null {
  const code = stmt.code;
  const m = ALTER_FUNCTION_RE.exec(code);
  if (!m) return null;
  let tailStart = m[0].length;
  if (m[3]) {
    const close = matchParen(code, m[0].length - 1);
    if (close === -1) return null;
    tailStart = close + 1;
  }
  const tail = code.slice(tailStart);
  const sec = /\bsecurity\s+(definer|invoker)\b/i.exec(tail)?.[1]?.toLowerCase();
  const rename = new RegExp(String.raw`\brename\s+to\s+(${SQL_IDENT})`, "i").exec(tail)?.[1];
  let searchPath: boolean | undefined;
  if (/\bset\s+"?search_path"?\s*(?:=|\bto\b|\bfrom\s+current\b)/i.test(tail)) searchPath = true;
  else if (/\breset\s+(?:"?search_path"?|all)\b/i.test(tail)) searchPath = false;
  return {
    fn: qual(m[1], m[2]!),
    searchPath,
    security: sec === "definer" || sec === "invoker" ? sec : undefined,
    renameTo: rename === undefined ? undefined : normalizeSqlIdent(rename),
  };
}

/** A migration file's statements, as passed to {@link functionSearchPathFixes}. */
export interface SqlFileStatements {
  file: string;
  statements: SqlStatement[];
}

/** Where a statement sits in migration order: files sorted by name, then statement index. */
export interface SqlPosition {
  file: string;
  /** Index of the file in name order. */
  fileIndex: number;
  /** Statement index within the file. */
  index: number;
}

/** True when `a` comes strictly after `b` in migration order. */
export function isAfter(a: SqlPosition, b: SqlPosition): boolean {
  return a.fileIndex !== b.fileIndex ? a.fileIndex > b.fileIndex : a.index > b.index;
}

/**
 * For each function key (`schema.name`), the position of the last
 * `alter function ... set search_path` that is still in effect (a later
 * `reset search_path` removes it). Files are processed in name order.
 */
export function functionSearchPathFixes(
  files: readonly SqlFileStatements[],
): Map<string, SqlPosition> {
  const fixes = new Map<string, SqlPosition>();
  const sorted = [...files].sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0));
  sorted.forEach(({ file, statements }, fileIndex) => {
    statements.forEach((stmt, index) => {
      const alter = parseAlterFunction(stmt);
      if (!alter || alter.searchPath === undefined) return;
      const key = qualifiedKey(alter.fn);
      if (alter.searchPath) fixes.set(key, { file, fileIndex, index });
      else fixes.delete(key);
    });
  });
  return fixes;
}

// ── Tables ──────────────────────────────────────────────────────────────────

/** A parsed `create table` statement. */
export interface ParsedTable {
  table: QualifiedName;
  ifNotExists: boolean;
  /** Normalized column names declared in the table body. */
  columns: string[];
  /** `partition of` tables are reached through their parent. */
  partition: boolean;
  temporary: boolean;
}

const CREATE_TABLE_RE = new RegExp(
  String.raw`^create\s+(?:(?:global\s+|local\s+)?(temp|temporary)\s+|unlogged\s+)?table\s+(if\s+not\s+exists\s+)?${QUAL}`,
  "i",
);
const TABLE_CONSTRAINT_WORDS = new Set([
  "constraint",
  "primary",
  "foreign",
  "unique",
  "check",
  "exclude",
  "like",
  "period",
]);

/** Parses a `create table`, or returns null for any other statement. */
export function parseCreateTable(stmt: SqlStatement): ParsedTable | null {
  const code = stmt.code;
  const m = CREATE_TABLE_RE.exec(code);
  if (!m) return null;
  const after = code.slice(m[0].length);
  const partition = /^\s*partition\s+of\b/i.test(after);
  const columns: string[] = [];
  const open = /^\s*\(/.exec(after);
  if (open) {
    const o = m[0].length + open[0].length - 1;
    const close = matchParen(code, o);
    if (close !== -1) {
      for (const { part } of splitTopLevel(code.slice(o + 1, close))) {
        const first = new RegExp(`^\\s*(${SQL_IDENT})`).exec(part)?.[1];
        if (!first) continue;
        if (!first.startsWith('"') && TABLE_CONSTRAINT_WORDS.has(first.toLowerCase())) continue;
        columns.push(normalizeSqlIdent(first));
      }
    }
  }
  return {
    table: qual(m[3], m[4]!),
    ifNotExists: m[2] !== undefined,
    columns,
    partition,
    temporary: m[1] !== undefined,
  };
}

/** A parsed `alter table`: the column, rename and row level security changes. */
export interface ParsedAlterTable {
  table: QualifiedName;
  addColumns: string[];
  dropColumns: string[];
  renameColumn: { from: string; to: string } | undefined;
  renameTo: string | undefined;
  rls: "enable" | "disable" | undefined;
}

const ALTER_TABLE_RE = new RegExp(
  String.raw`^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?${QUAL}`,
  "i",
);

/** Parses an `alter table`, or returns null for any other statement. */
export function parseAlterTable(stmt: SqlStatement): ParsedAlterTable | null {
  const code = stmt.code;
  const m = ALTER_TABLE_RE.exec(code);
  if (!m) return null;
  const out: ParsedAlterTable = {
    table: qual(m[1], m[2]!),
    addColumns: [],
    dropColumns: [],
    renameColumn: undefined,
    renameTo: undefined,
    rls: undefined,
  };
  const tail = code.slice(m[0].length);
  const renameTo = new RegExp(String.raw`^\s*rename\s+to\s+(${SQL_IDENT})`, "i").exec(tail);
  if (renameTo) {
    out.renameTo = normalizeSqlIdent(renameTo[1]!);
    return out;
  }
  const renameCol = new RegExp(
    String.raw`^\s*rename\s+(?:column\s+)?(${SQL_IDENT})\s+to\s+(${SQL_IDENT})`,
    "i",
  ).exec(tail);
  if (renameCol) {
    out.renameColumn = {
      from: normalizeSqlIdent(renameCol[1]!),
      to: normalizeSqlIdent(renameCol[2]!),
    };
    return out;
  }
  for (const { part } of splitTopLevel(tail)) {
    const p = part.trim();
    const rls = /^(enable|disable)\s+row\s+level\s+security\b/i.exec(p);
    if (rls) {
      out.rls = rls[1]!.toLowerCase() as "enable" | "disable";
      continue;
    }
    const add = new RegExp(
      String.raw`^add\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?(${SQL_IDENT})`,
      "i",
    ).exec(p);
    if (add && !TABLE_CONSTRAINT_WORDS.has(add[1]!.toLowerCase())) {
      out.addColumns.push(normalizeSqlIdent(add[1]!));
      continue;
    }
    const drop = new RegExp(
      String.raw`^drop\s+(?:column\s+)?(?:if\s+exists\s+)?(${SQL_IDENT})`,
      "i",
    ).exec(p);
    if (drop && !/^constraint$/i.test(drop[1]!)) out.dropColumns.push(normalizeSqlIdent(drop[1]!));
  }
  return out;
}

// ── Equalities in policy expressions ────────────────────────────────────────

/** One side of an equality: a column reference split into its dotted parts. */
export interface ColumnOperand {
  /** Normalized parts, e.g. ["org_members", "org_id"] or ["org_id"]. */
  parts: string[];
  /** Offset of the operand in the expression. */
  offset: number;
}

/** A `column = column` comparison found by {@link extractEqualities}. */
export interface Equality {
  /** Offset of the left operand in the expression. */
  offset: number;
  left: ColumnOperand;
  right: ColumnOperand;
  /** Both sides refer to the same column of the same table reference (always true). */
  sameColumn: boolean;
  /** False when a side was resolved without knowing the table's columns. */
  certain: boolean;
}

/** Column names of a table, or undefined when the table was never seen. */
export type ColumnLookup = (table: QualifiedName) => readonly string[] | undefined;

interface Token {
  kind: "ident" | "punct" | "op" | "literal";
  /** Normalized identifier or the raw punctuation / operator. */
  value: string;
  /** Lower-cased raw text (bare identifiers) for keyword checks; quoted idents are never keywords. */
  keyword: string;
  offset: number;
}

function tokenize(expr: string): Token[] {
  const out: Token[] = [];
  let i = 0;
  while (i < expr.length) {
    const c = expr[i]!;
    if (/\s/.test(c)) {
      i++;
    } else if (c === '"') {
      const j = skipQuotedIdent(expr, i);
      out.push({
        kind: "ident",
        value: normalizeSqlIdent(expr.slice(i, j)),
        keyword: "",
        offset: i,
      });
      i = j;
    } else if (isIdentStart(c)) {
      let j = i + 1;
      while (isIdentChar(expr[j])) j++;
      const w = expr.slice(i, j);
      out.push({ kind: "ident", value: w.toLowerCase(), keyword: w.toLowerCase(), offset: i });
      i = j;
    } else if (c === "'") {
      const j = skipString(expr, i);
      out.push({ kind: "literal", value: "'", keyword: "", offset: i });
      i = j;
    } else if (/[0-9]/.test(c)) {
      let j = i + 1;
      while (/[0-9.]/.test(expr[j] ?? "")) j++;
      out.push({ kind: "literal", value: expr.slice(i, j), keyword: "", offset: i });
      i = j;
    } else if ("(),.;[]".includes(c)) {
      out.push({ kind: "punct", value: c, keyword: "", offset: i });
      i++;
    } else {
      let j = i + 1;
      while (j < expr.length && /[+\-*/<>=~!@#%^&|`?:]/.test(expr[j]!)) j++;
      out.push({ kind: "op", value: expr.slice(i, j), keyword: "", offset: i });
      i = j;
    }
  }
  return out;
}

const CLAUSE_END = new Set([
  "where",
  "group",
  "order",
  "limit",
  "offset",
  "having",
  "union",
  "except",
  "intersect",
  "window",
  "fetch",
  "for",
  "returning",
]);
const JOIN_WORDS = new Set([
  "join",
  "inner",
  "left",
  "right",
  "full",
  "outer",
  "cross",
  "natural",
  "lateral",
]);
const NOT_ALIAS = new Set([...CLAUSE_END, ...JOIN_WORDS, "on", "using", "as", "tablesample"]);
const BEFORE_OPERAND = new Set([
  "and",
  "or",
  "not",
  "where",
  "on",
  "when",
  "then",
  "else",
  "having",
]);
const AFTER_OPERAND = new Set([
  "and",
  "or",
  "then",
  "when",
  "else",
  "end",
  "group",
  "order",
  "limit",
  "having",
  "union",
  "except",
  "intersect",
]);
const NON_COLUMN = new Set([
  "true",
  "false",
  "null",
  "current_user",
  "session_user",
  "current_role",
  "user",
  "current_date",
  "current_timestamp",
  "localtimestamp",
  "now",
  "select",
  "exists",
  "not",
  "and",
  "or",
]);

interface Binding {
  /** Name the binding is referenced by (alias, else table name). */
  ref: string;
  table: QualifiedName | undefined;
  /** Known columns, or undefined (derived table or unseen table). */
  columns: readonly string[] | undefined;
}

interface Scope {
  id: number;
  parent: number;
  bindings: Binding[];
  /** Paren depth of the scope's own `(`; -1 for the policy scope. */
  depth: number;
  /** FROM-list parsing state. */
  inFrom: boolean;
  expectTable: boolean;
  lastBinding: Binding | undefined;
}

/**
 * Finds `column = column` comparisons in a policy expression (stripped code) and
 * resolves each side the way Postgres does: a qualified reference binds to the
 * nearest FROM item with that name or alias, an unqualified one to the innermost
 * FROM that has the column (when its columns are unknown, a single FROM item is
 * assumed to have it). The policy's own table is the outermost scope.
 */
export function extractEqualities(
  expr: string,
  policyTable: QualifiedName,
  columnsOf: ColumnLookup,
): Equality[] {
  const tokens = tokenize(expr);
  const newScope = (id: number, parent: number, depth: number, bindings: Binding[]): Scope => ({
    id,
    parent,
    depth,
    bindings,
    inFrom: false,
    expectTable: false,
    lastBinding: undefined,
  });
  const scopes: Scope[] = [
    newScope(0, -1, -1, [
      { ref: policyTable.name, table: policyTable, columns: columnsOf(policyTable) },
    ]),
  ];
  const scopeOf: number[] = new Array<number>(tokens.length).fill(0);
  const stack: number[] = [0];
  let depth = 0;

  for (let t = 0; t < tokens.length; t++) {
    const tok = tokens[t]!;
    const cur = stack[stack.length - 1]!;
    const scope = scopes[cur]!;
    if (tok.value === "(" && tok.kind === "punct") {
      depth++;
      if (tokens[t + 1]?.keyword === "select") {
        if (scope.inFrom && scope.expectTable && depth === scope.depth + 1) {
          // Derived table: an anonymous binding whose alias follows its `)`.
          scope.lastBinding = { ref: "", table: undefined, columns: undefined };
          scope.bindings.push(scope.lastBinding);
          scope.expectTable = false;
        }
        const s = newScope(scopes.length, cur, depth, []);
        scopes.push(s);
        stack.push(s.id);
      }
      scopeOf[t] = stack[stack.length - 1]!;
      continue;
    }
    if (tok.value === ")" && tok.kind === "punct") {
      scopeOf[t] = cur;
      if (scope.depth === depth && stack.length > 1) stack.pop();
      depth--;
      continue;
    }
    scopeOf[t] = cur;
    if (cur === 0 || depth !== scope.depth) continue; // policy scope, or nested parens
    if (tok.kind === "ident" && tok.keyword === "from") {
      scope.inFrom = true;
      scope.expectTable = true;
      scope.lastBinding = undefined;
      continue;
    }
    if (!scope.inFrom) continue;
    if (tok.kind === "ident" && CLAUSE_END.has(tok.keyword)) {
      scope.inFrom = false;
      continue;
    }
    if (tok.kind === "ident" && (JOIN_WORDS.has(tok.keyword) || tok.keyword === "on")) {
      if (tok.keyword === "join") scope.expectTable = true;
      else if (tok.keyword === "on") scope.expectTable = false;
      scope.lastBinding = undefined;
      continue;
    }
    if (tok.value === "," && tok.kind === "punct") {
      scope.expectTable = true;
      continue;
    }
    if (tok.kind === "ident" && scope.expectTable) {
      // table reference: ident [. ident]
      const parts = [tok.value];
      let k = t;
      while (tokens[k + 1]?.value === "." && tokens[k + 2]?.kind === "ident") {
        parts.push(tokens[k + 2]!.value);
        k += 2;
      }
      for (let x = t + 1; x <= k; x++) scopeOf[x] = cur;
      let binding: Binding;
      if (tokens[k + 1]?.value === "(") {
        // set-returning function in FROM: unknown columns
        binding = { ref: parts[parts.length - 1]!, table: undefined, columns: undefined };
      } else {
        const table: QualifiedName =
          parts.length >= 2
            ? { schema: parts[parts.length - 2], name: parts[parts.length - 1]! }
            : { schema: undefined, name: parts[0]! };
        binding = { ref: table.name, table, columns: columnsOf(table) };
      }
      scope.bindings.push(binding);
      scope.lastBinding = binding;
      scope.expectTable = false;
      t = k;
      continue;
    }
    if (tok.kind === "ident" && scope.lastBinding) {
      if (tok.keyword === "as") continue;
      if (!NOT_ALIAS.has(tok.keyword)) scope.lastBinding.ref = tok.value;
      scope.lastBinding = undefined;
    }
  }

  const operandAt = (
    end: number,
    dir: -1 | 1,
  ): { parts: string[]; first: number; last: number } | null => {
    // Collects ident(.ident){0,2} starting next to the `=` in direction dir.
    const idx: number[] = [];
    let k = end;
    const tok = tokens[k];
    if (!tok || tok.kind !== "ident") return null;
    idx.push(k);
    while (idx.length < 5) {
      const dot = tokens[k + dir];
      const nxt = tokens[k + 2 * dir];
      if (dot?.value === "." && dot.kind === "punct" && nxt?.kind === "ident") {
        idx.push(k + dir, k + 2 * dir);
        k += 2 * dir;
      } else break;
    }
    const ordered = dir === 1 ? idx : [...idx].reverse();
    const parts = ordered.filter((x) => tokens[x]!.kind === "ident").map((x) => tokens[x]!.value);
    if (parts.length > 3) return null;
    return { parts, first: Math.min(...idx), last: Math.max(...idx) };
  };

  const resolve = (
    parts: string[],
    scopeId: number,
  ): { binding: Binding; column: string; certain: boolean } | null => {
    const column = parts[parts.length - 1]!;
    if (parts.length >= 2) {
      const ref = parts[parts.length - 2]!;
      const schema = parts.length === 3 ? parts[0] : undefined;
      for (let s: number = scopeId; s !== -1; s = scopes[s]!.parent) {
        const hit = scopes[s]!.bindings.find(
          (b) =>
            b.ref === ref &&
            (schema === undefined || (b.table && (b.table.schema ?? "public") === schema)),
        );
        if (hit) return { binding: hit, column, certain: true };
      }
      return null;
    }
    for (let s: number = scopeId; s !== -1; s = scopes[s]!.parent) {
      const bs = scopes[s]!.bindings;
      if (bs.length === 0) continue;
      const known = bs.filter((b) => b.columns?.includes(column));
      const unknown = bs.filter((b) => b.columns === undefined);
      if (known.length === 1) return { binding: known[0]!, column, certain: unknown.length === 0 };
      if (known.length > 1) return null;
      if (unknown.length === 1) return { binding: unknown[0]!, column, certain: false };
      if (unknown.length > 1) return null;
    }
    return null;
  };

  const out: Equality[] = [];
  for (let t = 1; t < tokens.length - 1; t++) {
    const eq = tokens[t]!;
    if (eq.kind !== "op" || eq.value !== "=") continue;
    const left = operandAt(t - 1, -1);
    const right = operandAt(t + 1, 1);
    if (!left || !right) continue;
    const before = tokens[left.first - 1];
    const after = tokens[right.last + 1];
    const okBefore =
      !before ||
      (before.kind === "punct" && (before.value === "(" || before.value === ",")) ||
      (before.kind === "ident" && BEFORE_OPERAND.has(before.keyword));
    const okAfter =
      !after ||
      (after.kind === "punct" &&
        (after.value === ")" || after.value === "," || after.value === ";")) ||
      (after.kind === "ident" && AFTER_OPERAND.has(after.keyword));
    if (!okBefore || !okAfter) continue;
    if (left.parts.length === 1 && NON_COLUMN.has(tokens[left.first]!.keyword)) continue;
    if (right.parts.length === 1 && NON_COLUMN.has(tokens[right.first]!.keyword)) continue;
    const leftOp: ColumnOperand = { parts: left.parts, offset: tokens[left.first]!.offset };
    const rightOp: ColumnOperand = { parts: right.parts, offset: tokens[right.first]!.offset };
    const scopeId = scopeOf[t]!;
    let sameColumn = false;
    let certain = true;
    if (left.parts.join(".") === right.parts.join(".")) {
      sameColumn = true;
    } else {
      const l = resolve(left.parts, scopeId);
      const r = resolve(right.parts, scopeId);
      if (l && r && l.binding === r.binding && l.column === r.column) {
        sameColumn = true;
        certain = l.certain && r.certain;
      }
    }
    out.push({ offset: leftOp.offset, left: leftOp, right: rightOp, sameColumn, certain });
  }
  return out;
}

/** Splits an expression at top-level `and` (outside parentheses). */
export function splitTopLevelAnd(expr: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let last = 0;
  for (let j = 0; j < expr.length; j++) {
    const c = expr[j];
    if (c === '"') j = skipQuotedIdent(expr, j) - 1;
    else if (c === "'") j = skipString(expr, j) - 1;
    else if (c === "(") depth++;
    else if (c === ")") depth--;
    else if (depth === 0 && /^and\b/i.test(expr.slice(j, j + 4)) && !isIdentChar(expr[j - 1])) {
      out.push(expr.slice(last, j));
      last = j + 3;
    }
  }
  out.push(expr.slice(last));
  return out.map((s) => s.trim()).filter((s) => s !== "");
}
