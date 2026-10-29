import {
  RISKY_ROUTE_PATTERNS,
  RISKY_HTTP_METHODS,
  AUTH_CHECK_PATTERNS,
  MIDDLEWARE_AUTH_PATTERNS,
  EXPRESS_AUTH_PATTERNS,
  EXPRESS_HANDLER_AUTH_PATTERNS,
  HANDLER_AUTH_PATTERNS,
  AUTH_WRAPPER_RE,
  PUBLIC_ROUTE_PATH_RE,
  SIGNATURE_VERIFY_PATTERNS,
  PUBLIC_HANDLER_PATTERNS,
  SECRET_PARAM_ANCHORED_RE,
  UNAMBIGUOUS_SECRET_NAME_RE,
} from "../patterns/auth-patterns.js";
import { maskCode } from "./js-source.js";
import type { JsSource } from "./js-source.js";
import type { FunctionSpan } from "./js-functions.js";

const APP_ROUTE_RE = /(?:^|\/)(?:src\/)?app\/(?:.+\/)?route\.(?:ts|js|mjs)$/;
const PAGES_API_RE = /(?:^|\/)(?:src\/)?pages\/api\/.+\.(?:ts|js|mjs|tsx|jsx)$/;
const MIDDLEWARE_RE = /^(?:src\/)?middleware\.(?:ts|js)$/;
const ALL_METHODS = ["GET", "HEAD", "OPTIONS", ...RISKY_HTTP_METHODS];

/**
 * Determines if a given file path is a Next.js API route file:
 * `app/** /route.(ts|js|mjs)` or `pages/api/**`, with an optional `src/` prefix.
 * (Express and other frameworks are out of scope.)
 */
export function isApiRoute(filePath: string): boolean {
  const p = filePath.replace(/\\/g, "/");
  return APP_ROUTE_RE.test(p) || PAGES_API_RE.test(p);
}

/**
 * Checks if the route path matches known risky/sensitive patterns like /admin or /users.
 */
export function isRiskyRoutePattern(filePath: string): boolean {
  const normalizedPath = filePath.replace(/\\/g, "/");
  return RISKY_ROUTE_PATTERNS.some((pattern: string) => normalizedPath.includes(pattern));
}

/** 1-indexed line number of a character offset. */
export function lineOfIndex(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i++) if (content.charCodeAt(i) === 10) line++;
  return line;
}

/**
 * Finds the 1-indexed line where a handler for one of `methods` is exported.
 * Recognises `export (async) function X`, `export const X = ...`,
 * `export { X }` and `export { handler as X }`, plus the `pages/api`
 * `req.method === "X"` style. Returns undefined when none is found.
 */
export function findHandlerLine(
  fileContent: string,
  methods: readonly string[] = RISKY_HTTP_METHODS,
): number | undefined {
  let best: number | undefined;
  const consider = (index: number): void => {
    const line = lineOfIndex(fileContent, index);
    if (best === undefined || line < best) best = line;
  };
  const set = new Set(methods);
  const alt = methods.join("|");

  const decl = new RegExp(
    `\\bexport\\s+(?:async\\s+)?function\\s+(?:${alt})\\b|\\bexport\\s+(?:const|let|var)\\s+(?:${alt})\\b`,
    "g",
  );
  for (const m of fileContent.matchAll(decl)) consider(m.index ?? 0);

  for (const m of fileContent.matchAll(/\bexport\s*\{([^}]*)\}/g)) {
    for (const spec of m[1]!.split(",")) {
      const parts = spec.trim().split(/\s+as\s+/);
      const exported = (parts[1] ?? parts[0] ?? "").trim();
      if (set.has(exported)) consider(m.index ?? 0);
    }
  }

  // pages/api structure: `req.method === "POST"`, `case "POST":`, `["POST"].includes(req.method)`
  if (/\breq\.method\b/.test(fileContent)) {
    const quoted = new RegExp(`["'](?:${alt})["']`, "g");
    for (const m of fileContent.matchAll(quoted)) consider(m.index ?? 0);
  }
  return best;
}

/**
 * Checks if the file content defines risky HTTP methods like POST, PUT, PATCH, DELETE.
 */
export function hasRiskyHttpMethods(fileContent: string): boolean {
  return findHandlerLine(fileContent, RISKY_HTTP_METHODS) !== undefined;
}

/** Line of any exported HTTP handler, or undefined. */
export function findAnyHandlerLine(fileContent: string): number | undefined {
  return findHandlerLine(fileContent, ALL_METHODS);
}

/**
 * Checks if the file content contains a call/usage of a known auth helper.
 * A bare `import { auth }` does not count.
 */
export function hasAuthCheck(fileContent: string): boolean {
  return AUTH_CHECK_PATTERNS.some((re) => re.test(fileContent));
}

/**
 * Best effort: does a root (or src/) middleware.ts/js perform auth and run on `/api`?
 * Limits: the `matcher` is inspected textually (string/array literals only; no
 * evaluation of variables), and in-function `pathname` conditions are ignored,
 * so a middleware that authenticates but skips `/api` in code is treated as protecting.
 */
export async function middlewareProtectsApi(
  files: readonly string[],
  readFile: (file: string) => Promise<string>,
): Promise<boolean> {
  for (const file of files) {
    const p = file.replace(/\\/g, "/");
    if (!MIDDLEWARE_RE.test(p)) continue;
    const content = await readFile(file);
    if (!MIDDLEWARE_AUTH_PATTERNS.some((re) => re.test(content))) continue;
    if (matcherCoversApi(content)) return true;
  }
  return false;
}

export function matcherCoversApi(content: string): boolean {
  const m = /\bmatcher\s*:\s*(\[[^\]]*\]|"[^"]*"|'[^']*'|`[^`]*`)/.exec(content);
  if (!m) return true; // no matcher: middleware runs on every request
  const text = m[1]!;
  const lookaheads = [...text.matchAll(/\(\?!([^)]*)\)/g)].map((x) => x[1]!);
  const rest = text.replace(/\(\?!([^)]*)\)/g, "");
  if (/\/api\b/.test(rest)) return true;
  // catch-all like "/((?!_next|favicon.ico).*)": covers /api unless api is excluded
  if (lookaheads.length > 0) return !lookaheads.some((l) => /\bapi\b/.test(l));
  return /["'`]\/(?::path\*|\(\.\*\))["'`]/.test(text);
}

// ---------------------------------------------------------------------------
// Express route discovery
// ---------------------------------------------------------------------------

export interface ExpressRoute {
  /** Upper-cased HTTP method (`ALL` for `.all`). */
  method: string;
  /** Route path literal (first argument). */
  path: string;
  /** 1-indexed line of the `app.get(` / `router.post(` call. */
  line: number;
  /** Receiver identifier, e.g. `app` or `router`. */
  receiver: string;
  /** Source text of everything after the path argument (the handler chain). */
  handlerChain: string;
  /**
   * Same span as `handlerChain` (same length and line layout) with comments, string/regex
   * literals and template text blanked out. Analyse this so incidental words never count as code.
   */
  chainCode: string;
  /** 1-indexed line where the handler chain text starts. */
  chainStartLine: number;
  /** Character offset of the call in the file. */
  index: number;
}

const EXPRESS_SOURCE_RE = /\.(?:js|ts|mjs|cjs)$/;
const EXPRESS_TEST_RE = /\.(?:test|spec)\.[cm]?[jt]s$|(?:^|\/)__tests__\//;
const EXPRESS_IMPORT_RE = /(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(?\s*)["']express["']/;
const EXPRESS_ROUTE_CALL_RE =
  /\b([A-Za-z_$][\w$]*)\s*\.\s*(get|post|put|patch|delete|all)\s*\(\s*(["'`])((?:\\.|(?!\3)[^\\\n])*)\3\s*,/g;
const MUTATING_EXPRESS_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE", "ALL"]);

export function isExpressMutatingMethod(method: string): boolean {
  return MUTATING_EXPRESS_METHODS.has(method.toUpperCase());
}

/** `.js/.ts/.mjs/.cjs` source file that is not a test or a declaration file. */
export function isExpressCandidateFile(filePath: string): boolean {
  const p = filePath.replace(/\\/g, "/");
  return EXPRESS_SOURCE_RE.test(p) && !EXPRESS_TEST_RE.test(p) && !/\.d\.ts$/.test(p);
}

/** True when the project depends on express or the file imports/requires it. */
export function usesExpress(fileContent: string, dependencies?: Record<string, string>): boolean {
  return Boolean(dependencies?.["express"]) || EXPRESS_IMPORT_RE.test(fileContent);
}

/** Moved to `js-source.ts`; re-exported unchanged for existing callers. */
export { maskCode };

/** Index of the bracket closing a call whose `(` precedes `from`, in already-masked code; -1 when unbalanced. */
function findCallEnd(masked: string, from: number): number {
  let depth = 1;
  for (let i = from; i < masked.length; i++) {
    const c = masked[i]!;
    if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/** Splits masked code on commas that are not nested in brackets. */
export function splitTopLevel(code: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let last = 0;
  for (let i = 0; i < code.length; i++) {
    const c = code[i]!;
    if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") depth--;
    else if (c === "," && depth === 0) {
      parts.push(code.slice(last, i));
      last = i + 1;
    }
  }
  parts.push(code.slice(last));
  return parts;
}

/** Control-char-free, length-limited route path for use in messages and AI prompts. */
export function displayRoutePath(routePath: string): string {
  const clean = routePath.replace(/[\u0000-\u001f\u007f-\u009f`]/g, "");
  return clean.length > 80 ? `${clean.slice(0, 80)}...` : clean;
}

/**
 * Extracts Express routes: `app|router.<get|post|put|patch|delete|all>("/path", ...handlers)`.
 * Receivers are limited to identifiers assigned from `express()` / `express.Router()` /
 * `Router()` in the file, plus the conventional names `app`, `router` and `*Router`. Generic
 * names such as `api`, `server` or `*App` are NOT assumed (they are usually HTTP clients),
 * so `axios.get("/x", cfg)`, `api.post("/x", body)` and `map.get(...)` are not routes.
 * Calls inside comments or strings are ignored. Limits: `router.route("/x").post(...)`
 * chains and dynamic (non-literal) paths are not discovered. Template-literal paths are
 * accepted as text. When brackets cannot be balanced, the chain is truncated at the next
 * route-like call instead of swallowing the rest of the file.
 */
export function extractExpressRoutes(fileContent: string): ExpressRoute[] {
  const code = maskCode(fileContent);
  const receivers = new Set<string>();
  for (const m of code.matchAll(
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:express\s*\(\s*\)|(?:express\s*\.\s*)?Router\s*\()/g,
  ))
    receivers.add(m[1]!);
  const looksLikeApp = (name: string): boolean =>
    receivers.has(name) || /^(?:app|router)$/i.test(name) || /Router$/.test(name);

  const matches = [...fileContent.matchAll(EXPRESS_ROUTE_CALL_RE)].filter(
    (m) => code[m.index ?? 0] === fileContent[m.index ?? 0],
  );
  const routes: ExpressRoute[] = [];
  matches.forEach((m, idx) => {
    const receiver = m[1]!;
    if (!looksLikeApp(receiver)) return;
    const start = m.index ?? 0;
    const chainStart = start + m[0].length;
    const open = start + m[0].indexOf("(");
    let end = findCallEnd(code, open + 1);
    if (end === -1) {
      const next = matches[idx + 1];
      end = next?.index ?? fileContent.length;
    }
    routes.push({
      method: m[2]!.toUpperCase(),
      path: m[4]!,
      line: lineOfIndex(fileContent, start),
      receiver,
      handlerChain: fileContent.slice(chainStart, end),
      chainCode: code.slice(chainStart, end),
      chainStartLine: lineOfIndex(fileContent, chainStart),
      index: start,
    });
  });
  return routes;
}

/** True when a `use()` argument list contains an Express auth middleware (comments/strings ignored). */
export function hasExpressAuth(text: string): boolean {
  const code = maskCode(text);
  return EXPRESS_AUTH_PATTERNS.some((re) => re.test(code));
}

/**
 * Does a route's handler chain authenticate? Middleware arguments (everything before the
 * final handler) are checked against the middleware patterns; the final handler's body is
 * checked only against strict call-form patterns (e.g. `getSession(req)`), so variables,
 * comments and strings such as `authenticated` or `// TODO auth()` never count.
 */
export function chainHasExpressAuth(route: Pick<ExpressRoute, "chainCode">): boolean {
  const parts = splitTopLevel(route.chainCode);
  const handler = parts.pop() ?? "";
  const middleware = parts.join(",");
  return (
    EXPRESS_AUTH_PATTERNS.some((re) => re.test(middleware)) ||
    EXPRESS_HANDLER_AUTH_PATTERNS.some((re) => re.test(handler))
  );
}

/** True when `routePath` equals `prefix` or lies below it on a path-segment boundary. */
export function pathCovers(prefix: string, routePath: string): boolean {
  const p = prefix.replace(/\/+$/, "");
  return p === "" || routePath === p || routePath.startsWith(`${p}/`);
}

/**
 * Best effort: is there an auth `X.use(<auth>)` before `route` in the file that covers it?
 * A `use` scoped to a path covers the route only when the route path is that path or below
 * it (segment-aware, so `/api` does not cover `/apiary`); this applies to router-level and
 * app-level `use` alike. An unscoped `use` covers every route on its own receiver, and an
 * app-level one covers all. Limits: mounts in other files (`app.use("/api", authRouter)` in
 * index.ts) and conditional middleware are not tracked.
 */
export function isCoveredByExpressUse(fileContent: string, route: ExpressRoute): boolean {
  const code = maskCode(fileContent);
  for (const m of code.matchAll(/\b([A-Za-z_$][\w$]*)\s*\.\s*use\s*\(/g)) {
    const at = m.index ?? 0;
    if (at >= route.index) break;
    const argsStart = at + m[0].length;
    const endIdx = findCallEnd(code, argsStart);
    if (endIdx === -1) continue;
    const argsCode = code.slice(argsStart, endIdx);
    if (!EXPRESS_AUTH_PATTERNS.some((re) => re.test(argsCode))) continue;
    // mount path comes from the original text (strings are blanked in `code`)
    const scoped = /^\s*(["'`])([^"'`]*)\1\s*,/.exec(fileContent.slice(argsStart, endIdx));
    const covers = !scoped || pathCovers(scoped[2]!, route.path);
    // `app.use("/admin", requireAuth, adminRouter)` naming this router
    if (argsCode.split(/[^\w$]+/).includes(route.receiver)) return true;
    if (m[1] === route.receiver && covers) return true;
    if (m[1] !== route.receiver && /^(?:app|server)$/i.test(m[1]!) && covers) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Per-handler authentication (additive helpers)
// ---------------------------------------------------------------------------

/**
 * URL path of a Next.js App Router route or Pages API file: `app/api/orders/[id]/route.ts`
 * gives `/api/orders/[id]` (route groups `(x)` and parallel slots `@x` dropped),
 * `pages/api/health.ts` gives `/api/health`. Undefined for other files.
 */
export function nextRoutePath(filePath: string): string | undefined {
  const p = filePath.replace(/\\/g, "/");
  const app = /(?:^|\/)(?:src\/)?app\/(?:(.*)\/)?route\.(?:ts|js|mjs)$/.exec(p);
  if (app) {
    const segs = (app[1] ?? "")
      .split("/")
      .filter((x) => x !== "" && !/^\(.*\)$/.test(x) && !x.startsWith("@"));
    return `/${segs.join("/")}`;
  }
  const pages = /(?:^|\/)(?:src\/)?pages\/(api(?:\/.+)?)\.(?:ts|js|mjs|tsx|jsx)$/.exec(p);
  if (pages) return `/${pages[1]!.replace(/\/index$/, "")}`;
  return undefined;
}

/** Sign-in/sign-up, password reset, OAuth/auth callbacks, the Auth.js catch-all, health probes. */
export function isPublicRoutePath(routePath: string): boolean {
  return PUBLIC_ROUTE_PATH_RE.test(routePath);
}

/** True when a wrapper callee (`withAuth`, `auth`, `lib.withSession`) authenticates. */
export function isAuthWrapper(callee: string): boolean {
  return AUTH_WRAPPER_RE.test(callee.split(".").pop() ?? callee);
}

/** True when masked code verifies a webhook signature (`stripe.webhooks.constructEvent(...)`). */
export function verifiesSignature(code: string): boolean {
  return SIGNATURE_VERIFY_PATTERNS.some((re) => re.test(code));
}

/** True when masked code is public by design (Stripe Checkout session creation, OAuth code exchange). */
export function isPublicByDesignCode(code: string): boolean {
  return PUBLIC_HANDLER_PATTERNS.some((re) => re.test(code));
}

/**
 * Offset (relative to `code`) of the first authentication check in masked code: a known
 * auth call ({@link AUTH_CHECK_PATTERNS}, {@link HANDLER_AUTH_PATTERNS}) or a call to one of
 * `helpers` (same-file functions that authenticate).
 */
export function firstAuthCheck(code: string, helpers: ReadonlySet<string>): number | undefined {
  let best: number | undefined;
  for (const re of [...AUTH_CHECK_PATTERNS, ...HANDLER_AUTH_PATTERNS]) {
    const m = re.exec(code);
    if (m && (best === undefined || m.index < best)) best = m.index;
  }
  for (const name of helpers) {
    const re = new RegExp(String.raw`(?<![.\w$])${name.replace(/\$/g, "\\$")}\s*\(`);
    const m = re.exec(code);
    if (m && (best === undefined || m.index < best)) best = m.index;
  }
  return best;
}

/**
 * Names of same-file functions whose body authenticates (directly or through another such
 * helper, two levels deep), e.g. `async function requireStaff() { await getSession() ... }`.
 */
export function localAuthHelpers(src: JsSource, spans: readonly FunctionSpan[]): Set<string> {
  const helpers = new Set<string>();
  for (let round = 0; round < 2; round++) {
    for (const s of spans) {
      if (s.name === undefined || helpers.has(s.name) || !/^[A-Za-z_$][\w$]*$/.test(s.name))
        continue;
      if (firstAuthCheck(src.code.slice(s.bodyStart, s.bodyEnd), helpers) !== undefined)
        helpers.add(s.name);
    }
  }
  return helpers;
}

/**
 * True when the handler is wrapped by an auth wrapper, or its body performs an auth check,
 * calls a same-file auth helper or compares a request secret with a literal or env var.
 */
export function spanAuthenticates(
  src: JsSource,
  span: FunctionSpan,
  helpers: ReadonlySet<string>,
): boolean {
  if (span.wrappers.some(isAuthWrapper)) return true;
  const body = src.code.slice(span.bodyStart, span.bodyEnd);
  return (
    firstAuthCheck(body, helpers) !== undefined ||
    hasDenyingSecretComparison(src, span.bodyStart, span.bodyEnd)
  );
}

/** A comparison of a request query/header value with a shared secret. */
export interface SecretComparison {
  /** Offset of the comparison operator and its 1-indexed line. */
  offset: number;
  line: number;
  /** Query parameter or header name (`key`, `authorization`, `x-cron-secret`). */
  name: string;
  /** `literal`: compared with a string literal; `env`: with `process.env.*` (or a template of it). */
  against: "literal" | "env";
  /** The name looks like a secret, or the failing branch answers 401/403. */
  secretLike: boolean;
  /** The comparison is an `if (...)` whose branch rejects the request (return/throw 401/403). */
  denies: boolean;
  /** File range of the compared literal or env expression. */
  valueStart: number;
  valueEnd: number;
}

const SC_OPERAND = String.raw`(?:await\s+)?[A-Za-z_$][\w$]*(?:\s*(?:\?\.|\.)\s*[A-Za-z_$][\w$]*|\s*\((?:[^()]|\([^()]*\))*\)|\s*\[[^\]]*\])*`;
const SC_STRING = String.raw`"[^"\n]*"|'[^'\n]*'|` + "`[^`\\n]*`";
const SC_LEFT_RE = new RegExp(String.raw`(${SC_OPERAND}|${SC_STRING})\s*$`);
const SC_RIGHT_RE = new RegExp(String.raw`^\s*(${SC_OPERAND}|${SC_STRING})`);
const REQUEST_SECRET_RES: readonly RegExp[] = [
  /\b(?:searchParams|query|headers\s*\(\s*\)|headers)\s*\.\s*get\s*\(\s*["'`]([\w-]+)["'`]\s*\)/,
  /\b(?:req|request)\s*\.\s*(?:query|headers|cookies)\s*(?:\?\.|\.)\s*([\w$]+)/,
  /\b(?:req|request)\s*\.\s*(?:query|headers|cookies)\s*\[\s*["'`]([\w-]+)["'`]\s*\]/,
  /\b(?:req|request)\s*\.\s*(?:header|get)\s*\(\s*["'`]([\w-]+)["'`]\s*\)/,
];

function requestSecretName(text: string): string | undefined {
  for (const re of REQUEST_SECRET_RES) {
    const m = re.exec(text);
    if (m) return m[1];
  }
  return undefined;
}

/** Resolves `x` in `x === "..."` to the request query/header name it was bound from, if any. */
function boundRequestName(src: JsSource, name: string, before: number): string | undefined {
  const esc = name.replace(/\$/g, "\\$");
  const window = src.text.slice(Math.max(0, before - 4000), before);
  let found: string | undefined;
  const direct = new RegExp(
    String.raw`\b(?:const|let|var)\s+${esc}\s*(?::[^=;\n]+)?=\s*([^;\n]+)`,
    "g",
  );
  for (const m of window.matchAll(direct)) found = requestSecretName(m[1]!);
  if (found !== undefined) return found;
  const destructured = new RegExp(
    String.raw`\b(?:const|let|var)\s*\{[^}]*\b${esc}\b[^}]*\}\s*=\s*(?:await\s+)?(?:req|request)\s*\.\s*(?:query|headers)\b`,
  );
  return destructured.test(window) ? name : undefined;
}

function isEnvSide(src: JsSource, text: string, before: number): boolean {
  if (/\bprocess\s*\.\s*env\b|\bimport\s*\.\s*meta\s*\.\s*env\b|\bDeno\s*\.\s*env\b/.test(text))
    return true;
  const id = /^[A-Za-z_$][\w$]*$/.exec(text.trim());
  if (!id) return false;
  const esc = id[0].replace(/\$/g, "\\$");
  return new RegExp(
    String.raw`\b(?:const|let|var)\s+${esc}\s*(?::[^=;\n]+)?=[^;\n]*\bprocess\s*\.\s*env\b`,
  ).test(src.text.slice(0, before));
}

/**
 * When the compared operand is part of a `+` concatenation, the whole concatenation's range and
 * its parts; otherwise undefined.
 */
function concatenation(
  src: JsSource,
  code: string,
  operandIsRight: boolean,
  start: number,
  end: number,
  lineStart: number,
  lineEnd: number,
  op: number,
): { start: number; end: number; parts: string[] } | undefined {
  let s = start;
  let e = end;
  if (operandIsRight) {
    if (!/^\s*\+/.test(code.slice(end, lineEnd))) return undefined;
    let depth = 0;
    for (e = end; e < lineEnd; e++) {
      const ch = code[e];
      if (ch === "(" || ch === "[") depth++;
      else if (ch === ")" || ch === "]") {
        if (depth === 0) break;
        depth--;
      } else if (depth === 0 && "{;?&|".includes(ch ?? "")) break;
    }
  } else {
    if (!/\+\s*$/.test(code.slice(lineStart, start))) return undefined;
    s = Math.max(lineStart, code.lastIndexOf("(", op) + 1, code.lastIndexOf("&", start) + 1);
    if (s > start) s = lineStart;
  }
  const parts = src.text
    .slice(s, e)
    .split("+")
    .map((p) => p.trim());
  return { start: s, end: e, parts };
}

const TRIVIAL_LITERAL_RE = /^(?:|undefined|null|true|false|0|1)$/;
const DENY_RE = /\b(?:401|403|unauthori[sz]ed|forbidden|Unauthori[sz]ed|Forbidden)\b/;

/**
 * Comparisons (`===`, `!==`, `==`, `!=`) in `[from, to)` of a request query parameter or
 * header with a string literal or an environment variable: `searchParams.get("key") !==
 * "nightly-job"`, `req.headers["x-api-key"] === process.env.API_KEY`, or a local bound from
 * either. `secretLike` is false for enum-style comparisons (`get("dir") === "asc"`) unless the
 * failing branch answers 401/403.
 */
export function findSecretComparisons(src: JsSource, from: number, to: number): SecretComparison[] {
  const out: SecretComparison[] = [];
  const code = src.code;
  const re = /[!=]==?/g;
  re.lastIndex = from;
  for (let m = re.exec(code); m && m.index < to; m = re.exec(code)) {
    const op = m.index;
    if (m[0] === "!" || m[0] === "=") continue;
    const prev = code[op - 1];
    if (prev === "=" || prev === "!" || prev === "<" || prev === ">") continue;
    if (code[op + m[0].length] === "=" || code[op + m[0].length] === ">") continue;
    const lineStart = code.lastIndexOf("\n", op - 1) + 1;
    let lineEnd = code.indexOf("\n", op);
    if (lineEnd < 0) lineEnd = code.length;
    if (op - lineStart > 400 || lineEnd - op > 400) continue;
    const left = SC_LEFT_RE.exec(code.slice(lineStart, op));
    const right = SC_RIGHT_RE.exec(code.slice(op + m[0].length, lineEnd));
    if (!left || !right) continue;
    const lStart = lineStart + left.index;
    const lText = src.text.slice(lStart, lStart + left[1]!.length);
    const rStart = op + m[0].length + right[0].length - right[1]!.length;
    const rText = src.text.slice(rStart, rStart + right[1]!.length);
    for (const [reqText, otherText, otherStart] of [
      [lText, rText, rStart],
      [rText, lText, lStart],
    ] as const) {
      let name = requestSecretName(reqText);
      if (name === undefined && /^[A-Za-z_$][\w$]*$/.test(reqText.trim()))
        name = boundRequestName(src, reqText.trim(), op);
      if (name === undefined) continue;
      const lit = /^(["'`])([^"'`]*)\1$/.exec(otherText.trim());
      let against: "literal" | "env" | undefined;
      let vStart = otherStart;
      let vEnd = otherStart + otherText.length;
      const concat = concatenation(
        src,
        code,
        otherStart === rStart,
        otherStart,
        vEnd,
        lineStart,
        lineEnd,
        op,
      );
      if (concat) {
        // `"Bearer " + process.env.X`: a prefix literal is not the secret; only an env part counts
        if (!concat.parts.some((part) => isEnvSide(src, part, op))) continue;
        against = "env";
        vStart = concat.start;
        vEnd = concat.end;
      } else if (lit && !otherText.includes("${")) {
        if (TRIVIAL_LITERAL_RE.test(lit[2]!.trim())) continue;
        against = "literal";
      } else if (isEnvSide(src, otherText, op)) {
        against = "env";
      }
      if (against === undefined) continue;
      const denies = rejectsRequest(src, lineStart, op, m[0], name, against);
      out.push({
        offset: op,
        line: src.lineAt(op),
        name,
        against,
        secretLike: SECRET_PARAM_ANCHORED_RE.test(name) || denies,
        denies,
        valueStart: vStart,
        valueEnd: vEnd,
      });
      break;
    }
  }
  return out;
}

/** The statement or `{ ... }` block following the condition whose `(` is at `open`. */
function blockAfterCondition(
  code: string,
  open: number,
): { start: number; end: number } | undefined {
  let depth = 0;
  let i = open;
  for (; i < code.length && i < open + 600; i++) {
    if (code[i] === "(") depth++;
    else if (code[i] === ")" && --depth === 0) break;
  }
  if (depth !== 0) return undefined;
  let s = i + 1;
  while (s < code.length && /\s/.test(code[s] ?? "")) s++;
  if (code[s] === "{") {
    let d = 0;
    for (let j = s; j < code.length && j < s + 1500; j++) {
      if (code[j] === "{") d++;
      else if (code[j] === "}" && --d === 0) return { start: s, end: j + 1 };
    }
    return undefined;
  }
  const semi = code.indexOf(";", s);
  const e = semi < 0 || semi - s > 400 ? Math.min(code.length, s + 400) : semi + 1;
  return { start: s, end: e };
}

/**
 * True when the comparison at `op` sits in an `if` (directly, or through a boolean local) whose
 * consequent rejects the request: a return/throw that answers 401/403/unauthorized, or, for a
 * secret-named parameter, any return/throw taken when the values differ.
 */
function rejectsRequest(
  src: JsSource,
  lineStart: number,
  op: number,
  operator: string,
  name: string,
  against: "env" | "literal",
): boolean {
  const code = src.code;
  const prefix = code.slice(lineStart, op);
  const secretName =
    SECRET_PARAM_ANCHORED_RE.test(name) &&
    (against === "env" || UNAMBIGUOUS_SECRET_NAME_RE.test(name));
  const neq = operator.startsWith("!");
  const check = (open: number, mismatchRejects: boolean): boolean => {
    const blk = blockAfterCondition(code, open);
    if (!blk || !/\b(?:return|throw)\b/.test(code.slice(blk.start, blk.end))) return false;
    if (DENY_RE.test(src.text.slice(blk.start, blk.end))) return true;
    return secretName && mismatchRejects;
  };
  let ifMatch: RegExpExecArray | undefined;
  for (const m of prefix.matchAll(/\bif\s*\(/g)) ifMatch = m;
  if (ifMatch) {
    const open = lineStart + ifMatch.index + ifMatch[0].length - 1;
    return check(open, neq !== /!\s*\(/.test(code.slice(open, op)));
  }
  // `const ok = req.headers.get("x") === secret; if (!ok) return 401`
  const bound = /\b(?:const|let|var)\s+([\w$]+)\s*(?::[^=;\n]+)?=[^=]*$/.exec(prefix);
  if (!bound?.[1]) return false;
  const id = bound[1].replace(/\$/g, "\\$&");
  const use = new RegExp(String.raw`\bif\s*\(\s*(!?)\s*${id}\s*(===\s*false)?\s*\)`).exec(
    code.slice(op, op + 2500),
  );
  if (!use) return false;
  const negated = use[1] === "!" || use[2] !== undefined;
  return check(op + use.index + use[0].indexOf("("), neq !== negated);
}

/** True when `[from, to)` has a secret comparison that rejects the request when it fails. */
function hasDenyingSecretComparison(src: JsSource, from: number, to: number): boolean {
  if (!/[!=]==?/.test(src.code.slice(from, to))) return false;
  return findSecretComparisons(src, from, to).some((c) => c.secretLike && c.denies);
}

/** True when `[from, to)` compares a secret-like request value with a literal or env var. */
export function hasSecretComparison(src: JsSource, from: number, to: number): boolean {
  if (!/[!=]==?/.test(src.code.slice(from, to))) return false;
  return findSecretComparisons(src, from, to).some((c) => c.secretLike);
}
