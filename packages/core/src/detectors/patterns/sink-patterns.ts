/**
 * Server-side injection sinks, matched against canonical callee names.
 *
 * A canonical callee is the call's callee text with its first segment resolved through
 * the file's imports of well-known modules (see `resolveCallAliases` in `utils/sinks.ts`):
 * `import { exec as sh } from "node:child_process"` makes `sh(...)` read
 * `child_process.exec`, `import fs from "fs/promises"` makes `fs.readFile(...)` read
 * `fs.readFile`, and named imports read `<module>.<name>` (`next/server.NextResponse.redirect`).
 * Imports of project modules (`@/lib/db`, `./shell`) are never resolved, so a local helper
 * called `exec` is not mistaken for `child_process.exec`. Unresolved callees keep their
 * text (`res.redirect`, `pool.query`).
 */

/** What a sink does with attacker-controlled data. */
export type SinkKind = "sql" | "postgrest" | "command" | "eval" | "ssrf" | "path" | "redirect";

export interface SinkPattern {
  /** Stable id, e.g. `child-process-exec`. */
  id: string;
  kind: SinkKind;
  /** Matched against the canonical callee. */
  callee: RegExp;
  /**
   * Indexes of the arguments that carry the dangerous value; `"last"` is the last argument
   * (`res.redirect(301, url)`), `"all"` every argument (`new Function(a, b, body)`).
   */
  args: readonly number[] | "last" | "all";
  /** Only `new X(...)` calls (`new vm.Script(code)`). */
  constructorOnly?: boolean | undefined;
  /** Only plain calls, never `new X(...)`. */
  callOnly?: boolean | undefined;
  /**
   * Generic method names (`.query`, `.execute`) need SQL keywords in the argument's
   * static text before they count as SQL sinks.
   */
  requiresSqlText?: boolean | undefined;
  /** PostgREST filter methods need filter syntax (`col.eq.`) in the argument's static text. */
  requiresFilterText?: boolean | undefined;
  /** The first argument must be the string literal `location` (header setters). */
  locationHeader?: boolean | undefined;
  /**
   * `spawn`/`execFile`-style calls: the argument list is only dangerous with `shell: true`
   * (otherwise only an attacker-chosen program is reported).
   */
  argvStyle?: boolean | undefined;
}

/**
 * Modules whose imports are resolved to canonical names. Everything else (project
 * modules, unknown packages) keeps the local name.
 */
const KNOWN_MODULE_RE =
  /^(?:child_process|fs|vm|http|https|axios|got|ky|superagent|undici|fetch|next\/navigation|next\/server|shelljs|execa|util|path|url|@remix-run\/[\w-]+)$/;

/** Normalised module names: `node:` prefix dropped, fs/fetch variants folded. */
export function normalizeModuleName(spec: string): string {
  const s = spec.trim().replace(/^node:/, "");
  if (/^(?:fs|fs\/promises|fs-extra|graceful-fs)$/.test(s)) return "fs";
  if (/^(?:node-fetch|cross-fetch|isomorphic-fetch|isomorphic-unfetch)$/.test(s)) return "fetch";
  if (s === "child_process/promises") return "child_process";
  return s;
}

/** True for modules whose imports `resolveCallAliases` resolves (after normalisation). */
export function isKnownSinkModule(normalized: string): boolean {
  return KNOWN_MODULE_RE.test(normalized);
}

const FS_METHODS =
  "readFile|readFileSync|createReadStream|writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync|readdir|readdirSync|open|openSync|copyFile|copyFileSync|cp|cpSync|rename|renameSync|stat|statSync|lstat|lstatSync|outputFile|outputFileSync|outputJson|outputJsonSync|remove|removeSync|readJson|readJsonSync|writeJson|writeJsonSync|move|moveSync|copy|copySync";

export const SINK_PATTERNS: readonly SinkPattern[] = [
  // ---- SQL ----
  {
    id: "prisma-raw-unsafe",
    kind: "sql",
    callee: /(?:^|\.)\$(?:queryRawUnsafe|executeRawUnsafe)$/,
    args: [0],
  },
  {
    id: "sequelize-query",
    kind: "sql",
    callee: /^(?:sequelize|db\.sequelize)\.query$/,
    args: [0],
  },
  {
    id: "knex-raw",
    kind: "sql",
    callee:
      /^(?:knex|db|trx|qb|database|pg)(?:\.[\w$]+)*\.raw$|\.(?:whereRaw|orWhereRaw|havingRaw|orHavingRaw|orderByRaw|groupByRaw|joinRaw|fromRaw)$/,
    args: [0],
  },
  {
    id: "postgres-unsafe",
    kind: "sql",
    callee: /^(?:sql|db|pg|postgres|client|tx|trx)\.unsafe$/,
    args: [0],
  },
  {
    id: "sql-method",
    kind: "sql",
    callee:
      /\.(?:query|execute|exec|run|all|get|each|prepare|raw|unsafe|queryRaw|executeRaw|none|one|oneOrNone|many|manyOrNone|any|result|multi)$/,
    args: [0],
    requiresSqlText: true,
    callOnly: true,
  },
  // ---- PostgREST (Supabase) filter strings ----
  {
    id: "postgrest-logic-filter",
    kind: "postgrest",
    callee: /\.(?:or|and)$/,
    args: [0],
    requiresFilterText: true,
    callOnly: true,
  },
  // ---- shell commands ----
  {
    id: "child-process-exec",
    kind: "command",
    callee: /^child_process\.(?:exec|execSync)$/,
    args: [0],
  },
  {
    id: "child-process-spawn",
    kind: "command",
    callee: /^child_process\.(?:spawn|spawnSync|execFile|execFileSync)$/,
    args: [0, 1],
    argvStyle: true,
  },
  {
    id: "execa",
    kind: "command",
    callee: /^execa(?:\.execa|\.execaSync|\.sync)?$/,
    args: [0, 1],
    argvStyle: true,
  },
  { id: "shelljs-exec", kind: "command", callee: /^shelljs\.exec$/, args: [0] },
  // ---- dynamic code ----
  {
    id: "eval",
    kind: "eval",
    callee: /^(?:eval|window\.eval|globalThis\.eval|global\.eval)$/,
    args: [0],
    callOnly: true,
  },
  {
    id: "function-constructor",
    kind: "eval",
    callee: /^(?:Function|globalThis\.Function)$/,
    args: "all",
  },
  {
    id: "vm-run",
    kind: "eval",
    callee: /^vm\.(?:runInNewContext|runInThisContext|runInContext|compileFunction)$/,
    args: [0],
    callOnly: true,
  },
  { id: "vm-script", kind: "eval", callee: /^vm\.Script$/, args: [0], constructorOnly: true },
  {
    id: "string-timer",
    kind: "eval",
    callee: /^(?:setTimeout|setInterval)$/,
    args: [0],
    callOnly: true,
  },
  // ---- outbound requests (SSRF) ----
  {
    id: "http-client",
    kind: "ssrf",
    callee:
      /^(?:fetch|undici\.(?:fetch|request|stream)|axios(?:\.(?:get|post|put|patch|delete|head|options|request))?|got(?:\.(?:get|post|put|patch|delete|head|stream))?|ky(?:\.(?:get|post|put|patch|delete|head))?|superagent\.(?:get|post|put|patch|delete|head)|https?\.(?:get|request))$/,
    args: [0],
    callOnly: true,
  },
  // ---- filesystem (path traversal) ----
  {
    id: "fs-two-paths",
    kind: "path",
    callee:
      /^fs\.(?:copyFile|copyFileSync|rename|renameSync|cp|cpSync|move|moveSync|copy|copySync)$/,
    args: [0, 1],
    callOnly: true,
  },
  {
    id: "fs-call",
    kind: "path",
    callee: new RegExp(String.raw`^fs\.(?:${FS_METHODS})$`),
    args: [0],
    callOnly: true,
  },
  {
    id: "send-file",
    kind: "path",
    callee: /^(?:res|response|reply)\.(?:sendFile|download)$/,
    args: [0],
    callOnly: true,
  },
  // ---- redirects ----
  {
    id: "next-redirect",
    kind: "redirect",
    callee: /^next\/navigation\.(?:redirect|permanentRedirect)$|^@remix-run\/[\w-]+\.redirect$/,
    args: [0],
    callOnly: true,
  },
  {
    id: "response-redirect",
    kind: "redirect",
    callee: /(?:^|\.)(?:NextResponse|Response)\.redirect$/,
    args: [0],
    callOnly: true,
  },
  {
    id: "framework-redirect",
    kind: "redirect",
    callee: /^(?:res|response|reply|ctx|c|context)\.redirect$/,
    args: "last",
    callOnly: true,
  },
  {
    id: "location-header",
    kind: "redirect",
    callee:
      /^(?:res|response|reply|ctx|c|headers|res\.headers|response\.headers)\.(?:setHeader|set|header|append)$/,
    args: [1],
    callOnly: true,
    locationHeader: true,
  },
];

/** The patterns of the given kinds, in declaration order. */
export function sinkPatternsOf(...kinds: SinkKind[]): SinkPattern[] {
  return SINK_PATTERNS.filter((p) => kinds.includes(p.kind));
}

/** Substrings worth looking for before parsing a file, per sink kind (cheap prefilter). */
export const SINK_NEEDLES: Readonly<Record<SinkKind, readonly string[]>> = {
  sql: [
    "query",
    "execute",
    "Raw",
    "raw(",
    "unsafe",
    ".exec(",
    ".run(",
    ".all(",
    ".get(",
    ".prepare(",
  ],
  postgrest: [".or(", ".and("],
  command: ["child_process", "shelljs", "execa"],
  eval: ["eval", "Function", "vm", "setTimeout", "setInterval"],
  ssrf: ["fetch", "axios", "got", "ky", "superagent", "http", "undici"],
  path: ["fs", "sendFile", "download"],
  redirect: ["redirect", "ocation"],
};

/** SQL statements and clauses in the static text of a query argument. */
export const SQL_TEXT_RE =
  /\b(?:select\b[^;]{0,400}?\bfrom|insert\s+into|update\s+[\w".`[\]]+\s+set|delete\s+from|merge\s+into|create\s+(?:table|index|view)|drop\s+table|alter\s+table|truncate\s+table)\b|\b(?:where|order\s+by|group\s+by|having)\s+[\w"`[(]/i;

/** PostgREST filter syntax (`name.ilike.%x%`, `id.in.(1,2)`) in a filter string. */
export const POSTGREST_FILTER_RE =
  /[\w"]\.(?:eq|neq|gt|gte|lt|lte|like|ilike|is|in|cs|cd|ov|sl|sr|nxr|nxl|adj|fts|plfts|phfts|wfts|match|imatch)\./;

/**
 * Calls that verify a webhook signature: data that went through them was signed by the
 * sender and is not attacker-controlled.
 */
export const WEBHOOK_VERIFY_RE =
  /\b(?:constructEvent(?:Async)?|verifyWebhook\w*|verifySignature\w*|validateWebhook\w*|verifyRequestSignature)\s*\(|\b(?:webhooks?|wh|svix|hook)\s*\.\s*verify\s*\(/;

/**
 * Calls whose result is safe for a sink kind (sanitizers named for that purpose), matched
 * against the callee text. Generic taint cleaners live in `taint-sources.ts`.
 */
export const SINK_SANITIZERS: Readonly<Record<SinkKind, RegExp | undefined>> = {
  sql: /^(?:[\w$]+\.)?(?:escape|escapeId|escapeIdentifier|escapeLiteral|quoteIdent\w*|quoteLiteral|ident|literal)$|^(?:pgFormat|format|sqlstring\.format|SqlString\.format|mysql\.format)$/,
  postgrest: /(?:^|\.)(?:escape\w*|sanitize\w*|quote\w*)$/,
  command: /^(?:quote|shellQuote\.quote|shescape\.\w+|shellescape|shellEscape|escapeShellArg|shq)$/,
  eval: undefined,
  ssrf: /(?:^|\.)(?:safe\w*Url|sanitize\w*Url|assertSafe\w*|assertAllowed\w*|validateExternalUrl|ssrfSafe\w*|allowlisted\w*|allowListed\w*)$/i,
  path: /(?:^|\.)(?:basename|sanitizeFilename|sanitizeFileName|sanitizePath|safeJoin|safePath|resolveSafe\w*|resolveWithin\w*)$/,
  redirect:
    /(?:^|\.)(?:safeRedirect\w*|getSafeRedirect\w*|sanitizeRedirect\w*|sanitize\w*Url|toSafePath|safeNext\w*|relativeOnly|getRedirectPath|safeCallbackUrl|validateRedirect\w*)$/i,
};
