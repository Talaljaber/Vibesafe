/**
 * Taint sources and cleaners shared by the injection, client and validation detectors.
 *
 * Source patterns run on masked code (`JsSource.code`), so comments and string contents
 * never match. Patterns must not carry the `g` or `y` flag; the analysis compiles global
 * copies itself.
 */

/** Where a file's code runs, as far as taint is concerned. */
export type TaintRuntime = "server" | "client" | "script";

/**
 * `remote`: any visitor controls the value (request data, URL). `local`: only whoever runs
 * the process controls it (`process.argv`, stdin); findings from local sources cap at `high`.
 */
export type TaintTrust = "remote" | "local";

export interface TaintSource {
  /** Stable id, e.g. `request-body`. */
  id: string;
  /** Human label for finding text, e.g. `request body`. */
  label: string;
  trust: TaintTrust;
  /** Matches the source expression in masked code. */
  pattern: RegExp;
}

/** A pattern that never matches: label-only sources used for seeded parameters. */
const NEVER = /(?!)/;

const REQ = String.raw`\b(?:req|request)\s*\.\s*`;

/** Request data in server code: Express/Next/Koa/Hono/Lambda request objects and next/headers. */
export const SERVER_SOURCES: readonly TaintSource[] = [
  {
    id: "request-body",
    label: "request body",
    trust: "remote",
    pattern: new RegExp(REQ + String.raw`(?:body|files?)\b`),
  },
  {
    id: "request-payload",
    label: "request body",
    trust: "remote",
    pattern: new RegExp(REQ + String.raw`(?:json|formData|text|arrayBuffer|blob)\s*\(`),
  },
  {
    id: "request-query",
    label: "query string",
    trust: "remote",
    pattern: new RegExp(REQ + String.raw`query\b`),
  },
  {
    id: "request-params",
    label: "route parameters",
    trust: "remote",
    pattern: new RegExp(REQ + String.raw`params\b`),
  },
  {
    id: "request-url",
    label: "request URL",
    trust: "remote",
    pattern: new RegExp(REQ + String.raw`(?:url|originalUrl|path|nextUrl)\b`),
  },
  {
    id: "request-headers",
    label: "request headers or cookies",
    trust: "remote",
    pattern: new RegExp(REQ + String.raw`(?:headers|cookies|get\s*\(|header\s*\()`),
  },
  {
    id: "next-headers",
    label: "request headers or cookies",
    trust: "remote",
    pattern: /(?<![.\w$])(?:headers|cookies)\s*\(\s*\)/,
  },
  {
    id: "koa-request",
    label: "request data",
    trust: "remote",
    pattern:
      /\bctx\s*\.\s*(?:query|querystring|params|request\s*\.\s*(?:body|query|files?|headers))\b/,
  },
  {
    id: "hono-request",
    label: "request data",
    trust: "remote",
    pattern:
      /\bc\s*\.\s*req\s*\.\s*(?:query|queries|param|json|parseBody|formData|text|header)\s*\(/,
  },
  {
    id: "lambda-event",
    label: "request data",
    trust: "remote",
    pattern: /\bevent\s*\.\s*(?:body|queryStringParameters|pathParameters|headers)\b/,
  },
];

/** Attacker-controllable data in browser code: the URL, router params, `postMessage` data. */
export const CLIENT_SOURCES: readonly TaintSource[] = [
  {
    id: "location",
    label: "page URL",
    trust: "remote",
    pattern:
      /(?<![\w$.])(?:(?:window|document|globalThis|self)\s*\.\s*)?location\s*\.\s*(?:search|hash|href|pathname)\b/,
  },
  {
    id: "document-url",
    label: "page URL",
    trust: "remote",
    pattern: /\bdocument\s*\.\s*(?:URL|documentURI|baseURI|referrer)\b|\bwindow\s*\.\s*name\b/,
  },
  {
    id: "router-params",
    label: "URL parameters",
    trust: "remote",
    pattern: /\buse(?:SearchParams|Params)\s*\(\s*\)|\brouter\s*\.\s*(?:query|asPath)\b/,
  },
  {
    id: "message-data",
    label: "postMessage data",
    trust: "remote",
    pattern: /\b(?:event|evt|ev|e|msg|message)\s*\.\s*data\b/,
  },
];

/** Inputs of CLI scripts: argv and stdin (trust `local`). */
export const SCRIPT_SOURCES: readonly TaintSource[] = [
  {
    id: "process-argv",
    label: "command-line arguments",
    trust: "local",
    pattern: /\bprocess\s*\.\s*(?:argv|stdin)\b/,
  },
];

/** Label-only source for App Router `params` / route context (seeded from the handler signature). */
export const ROUTE_PARAMS_SOURCE: TaintSource = {
  id: "route-params",
  label: "route parameters",
  trust: "remote",
  pattern: NEVER,
};

/** Label-only source for server action arguments (any client can call a server action). */
export const SERVER_ACTION_SOURCE: TaintSource = {
  id: "server-action-argument",
  label: "server action argument",
  trust: "remote",
  pattern: NEVER,
};

/** Label-only source for page `params` / `searchParams` props and `getServerSideProps` context. */
export const PAGE_PROPS_SOURCE: TaintSource = {
  id: "page-props",
  label: "page URL parameters",
  trust: "remote",
  pattern: NEVER,
};

/** Label-only default source for `seedParams`. */
export const PARAMETER_SOURCE: TaintSource = {
  id: "parameter",
  label: "function parameter",
  trust: "remote",
  pattern: NEVER,
};

/** Default sources for a runtime. */
export function sourcesForRuntime(runtime: TaintRuntime): readonly TaintSource[] {
  if (runtime === "client") return CLIENT_SOURCES;
  if (runtime === "script") return SCRIPT_SOURCES;
  return SERVER_SOURCES;
}

/**
 * Source for a request handler whose request parameter is not called `req`/`request`
 * (e.g. `(r, res) => r.body`): member reads of `name` that carry request data.
 */
export function requestMemberSource(name: string): TaintSource {
  const escaped = name.replace(/[$]/g, "\\$");
  return {
    id: "request-param",
    label: "request data",
    trust: "remote",
    pattern: new RegExp(
      String.raw`(?<![.\w$])${escaped}\s*\.\s*(?:body|files?|query|params|url|originalUrl|path|nextUrl|headers|cookies|(?:json|formData|text|arrayBuffer|blob|get|header)\s*\()`,
    ),
  };
}

// ---------------------------------------------------------------------------
// Cleaners and pass-through calls
// ---------------------------------------------------------------------------

/**
 * What a cleaner makes safe. `numeric` coercions remove taint entirely (a number cannot
 * inject); the others are recorded on the hit (`cleanedBy`) so each sink decides whether
 * that cleaning is enough for it (e.g. `path` for traversal, `html` for XSS).
 */
export type CleanerKind = "numeric" | "url-encode" | "html" | "path" | "schema" | "sql" | "shell";

export interface TaintCleaner {
  id: string;
  kind: CleanerKind;
  /** Matched against the callee text before `(`, e.g. `path.basename` or `schema.parse`. */
  callee: RegExp;
}

export const TAINT_CLEANERS: readonly TaintCleaner[] = [
  {
    id: "number",
    kind: "numeric",
    callee:
      /^(?:Number|parseInt|parseFloat|Boolean|BigInt|Number\.(?:parseInt|parseFloat|isInteger|isFinite|isNaN|isSafeInteger)|Math\.\w+|isNaN|isFinite)$/,
  },
  { id: "uri-component", kind: "url-encode", callee: /^encodeURIComponent$/ },
  {
    id: "html-sanitizer",
    kind: "html",
    callee:
      /^(?:DOMPurify\.sanitize|purify\.sanitize|sanitizeHtml|sanitizeHTML|escapeHtml|escapeHTML|xss|filterXSS|he\.(?:encode|escape)|validator\.escape|lodash\.escape|_\.escape)$/,
  },
  { id: "basename", kind: "path", callee: /^(?:path\.(?:posix\.|win32\.)?)?basename$/ },
  {
    id: "schema",
    kind: "schema",
    callee:
      /^(?!JSON\.)[\w$.]*\.(?:parse|safeParse|parseAsync|safeParseAsync|validate|validateSync|validateAsync|cast)$/,
  },
  {
    id: "sql-escape",
    kind: "sql",
    callee:
      /^(?:[\w$]+\.)?(?:escape|escapeId|escapeIdentifier|escapeLiteral)$|^(?:pgFormat|sqlstring\.format|SqlString\.format|mysql\.format)$/,
  },
  {
    id: "shell-quote",
    kind: "shell",
    callee: /^(?:shellescape|shellEscape|escapeShellArg|shellQuote\.quote|shq)$/,
  },
];

/**
 * Calls whose result carries the taint of their arguments unchanged (no call boundary):
 * conversions, URL/path builders and string helpers. Matched against the callee text.
 */
export const PASS_THROUGH_CALLS: readonly RegExp[] = [
  /^(?:String|JSON\.(?:parse|stringify)|decodeURIComponent|decodeURI|encodeURI|unescape|Buffer\.from|Object\.(?:assign|values|keys|entries|fromEntries|freeze)|Array\.(?:from|of)|structuredClone|Promise\.(?:resolve|all|allSettled))$/,
  /^(?:(?:path|posix|win32|path\.posix|path\.win32)\.)?(?:join|resolve|normalize|relative)$/,
  /^(?:url\.(?:parse|resolve|format)|util\.format|URL|URLSearchParams)$/,
  /\.(?:concat|replace|replaceAll|padStart|padEnd|join|assign|from)$/,
];

/**
 * Payload of a queue job (BullMQ/Bull `job.data`, Agenda `job.attrs.data`, pg-boss
 * `job.data`). Second-order: whoever enqueued the job controls it. Not part of
 * {@link SERVER_SOURCES}; the injection detectors add it only to files that import a
 * queue library.
 */
export const QUEUE_JOB_SOURCE: TaintSource = {
  id: "queue-job-data",
  label: "queue job payload",
  trust: "remote",
  pattern: /\bjob\s*\.\s*(?:data|attrs\s*\.\s*data|payload)\b/,
};
