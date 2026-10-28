import {
  RISKY_ROUTE_PATTERNS,
  RISKY_HTTP_METHODS,
  AUTH_CHECK_PATTERNS,
  MIDDLEWARE_AUTH_PATTERNS,
  EXPRESS_AUTH_PATTERNS,
} from "../patterns/auth-patterns.js";

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

/** Index of the `)` closing a call whose `(` precedes `from`; skips strings, templates and comments. */
function findCallEnd(content: string, from: number): number {
  let depth = 1;
  for (let i = from; i < content.length; i++) {
    const c = content[i]!;
    if (c === '"' || c === "'" || c === "`") {
      for (i++; i < content.length && content[i] !== c; i++) if (content[i] === "\\") i++;
    } else if (c === "/" && content[i + 1] === "/") {
      while (i < content.length && content[i] !== "\n") i++;
    } else if (c === "/" && content[i + 1] === "*") {
      const end = content.indexOf("*/", i + 2);
      i = end === -1 ? content.length : end + 1;
    } else if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return content.length;
}

/**
 * Extracts Express routes: `app|router.<get|post|put|patch|delete|all>("/path", ...handlers)`.
 * Receivers are limited to identifiers that look like an Express app/router
 * (`app`, `router`, `*Router`, `*Routes`, `server`, `api`) or that are assigned from
 * `express()` / `express.Router()` / `Router()`, so `axios.get("/x", cfg)` and
 * `map.get(...)` are not mistaken for routes. Limits: `router.route("/x").post(...)`
 * chains and dynamic (non-literal) paths are not discovered. Template-literal
 * paths are accepted as text.
 */
export function extractExpressRoutes(fileContent: string): ExpressRoute[] {
  const receivers = new Set<string>();
  for (const m of fileContent.matchAll(
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:express\s*\(\s*\)|(?:express\s*\.\s*)?Router\s*\()/g,
  ))
    receivers.add(m[1]!);
  const looksLikeApp = (name: string): boolean =>
    receivers.has(name) || /^(?:app|server|api|router|routes?)$/i.test(name) || /(?:Router|Routes|App)$/.test(name);

  const routes: ExpressRoute[] = [];
  for (const m of fileContent.matchAll(EXPRESS_ROUTE_CALL_RE)) {
    const receiver = m[1]!;
    if (!looksLikeApp(receiver)) continue;
    const start = m.index ?? 0;
    const chainStart = start + m[0].length;
    const open = start + m[0].indexOf("(");
    const end = findCallEnd(fileContent, open + 1);
    routes.push({
      method: m[2]!.toUpperCase(),
      path: m[4]!,
      line: lineOfIndex(fileContent, start),
      receiver,
      handlerChain: fileContent.slice(chainStart, end),
      chainStartLine: lineOfIndex(fileContent, chainStart),
      index: start,
    });
  }
  return routes;
}

/** True when a handler chain / `use()` argument text contains an Express auth middleware or check. */
export function hasExpressAuth(text: string): boolean {
  return EXPRESS_AUTH_PATTERNS.some((re) => re.test(text));
}

/**
 * Best effort: is there an auth `X.use(<auth>)` before `route` in the file that covers it?
 * A `use` covers the route when it is on the same receiver, or on the root `app`
 * and either unscoped or scoped to a prefix of the route path. Limits:
 * mounts in other files (`app.use("/api", authRouter)` in index.ts) and
 * conditional middleware are not tracked.
 */
export function isCoveredByExpressUse(fileContent: string, route: ExpressRoute): boolean {
  for (const m of fileContent.matchAll(/\b([A-Za-z_$][\w$]*)\s*\.\s*use\s*\(/g)) {
    const at = m.index ?? 0;
    if (at >= route.index) break;
    const argsStart = at + m[0].length;
    const args = fileContent.slice(argsStart, findCallEnd(fileContent, argsStart));
    if (!hasExpressAuth(args)) continue;
    // `x.use(auth)`, or `app.use("/admin", requireAuth, adminRouter)` naming this router
    const scoped = /^\s*(["'`])([^"'`]*)\1\s*,/.exec(args);
    const covers = !scoped || route.path.startsWith(scoped[2]!);
    if (args.split(/[^\w$]+/).includes(route.receiver)) return true;
    // a router-level `use` covers its own routes; an app-level `use` only the paths it is scoped to
    if (m[1] === route.receiver && (covers || !/^(?:app|server)$/i.test(m[1]!))) return true;
    if (m[1] !== route.receiver && /^(?:app|server)$/i.test(m[1]!) && covers) return true;
  }
  return false;
}
