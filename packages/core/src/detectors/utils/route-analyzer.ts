import {
  RISKY_ROUTE_PATTERNS,
  RISKY_HTTP_METHODS,
  AUTH_CHECK_PATTERNS,
  MIDDLEWARE_AUTH_PATTERNS,
  EXPRESS_AUTH_PATTERNS,
  EXPRESS_HANDLER_AUTH_PATTERNS,
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

const REGEX_PREV_KEYWORD_RE = /\b(?:return|typeof|case|in|of|delete|void|throw|else|do|yield|await)\s*$/;
const REGEX_PREV_CHARS = "(,=:[!&|?{};+-*%<>~^";

/**
 * Returns `src` with comments, string literals, regex literals and template text
 * replaced by spaces (newlines and `${}` expressions are kept, so offsets and line
 * numbers are unchanged). Heuristic: regex-vs-division is decided from the previous token.
 */
export function maskCode(src: string): string {
  const out = src.split("");
  const n = src.length;
  const mask = (from: number, to: number): void => {
    for (let k = from; k < to && k < n; k++) if (out[k] !== "\n") out[k] = " ";
  };
  const tmplDepths: number[] = [];
  let braces = 0;
  let prevSig = "";

  // scans template text starting at `start` (just after "`" or the closing "}"); returns where code resumes
  const scanTemplate = (start: number): number => {
    let i = start;
    while (i < n) {
      const c = src[i]!;
      if (c === "\\") {
        mask(i, i + 2);
        i += 2;
      } else if (c === "`") {
        prevSig = "`";
        return i + 1;
      } else if (c === "$" && src[i + 1] === "{") {
        tmplDepths.push(braces);
        braces++;
        prevSig = "{";
        return i + 2;
      } else {
        mask(i, i + 1);
        i++;
      }
    }
    return n;
  };

  let i = 0;
  while (i < n) {
    const c = src[i]!;
    if (c === "/" && src[i + 1] === "/") {
      let e = src.indexOf("\n", i);
      if (e === -1) e = n;
      mask(i, e);
      i = e;
    } else if (c === "/" && src[i + 1] === "*") {
      const e = src.indexOf("*/", i + 2);
      const end = e === -1 ? n : e + 2;
      mask(i, end);
      i = end;
    } else if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < n && src[j] !== c && src[j] !== "\n") j += src[j] === "\\" ? 2 : 1;
      mask(i + 1, j);
      i = Math.min(j + 1, n);
      prevSig = c;
    } else if (c === "`") {
      i = scanTemplate(i + 1);
    } else if (c === "/") {
      const regexOk =
        prevSig === "" ||
        REGEX_PREV_CHARS.includes(prevSig) ||
        (/[\w$]/.test(prevSig) && REGEX_PREV_KEYWORD_RE.test(src.slice(Math.max(0, i - 12), i)));
      let j = i + 1;
      let ok = false;
      if (regexOk) {
        let inClass = false;
        for (; j < n && src[j] !== "\n"; j++) {
          const d = src[j]!;
          if (d === "\\") j++;
          else if (d === "[") inClass = true;
          else if (d === "]") inClass = false;
          else if (d === "/" && !inClass) {
            ok = true;
            break;
          }
        }
      }
      if (ok) {
        mask(i + 1, j);
        i = j + 1;
        while (i < n && /[a-z]/i.test(src[i]!)) i++; // flags
        prevSig = ")";
      } else {
        prevSig = "/";
        i++;
      }
    } else {
      if (c === "{") braces++;
      else if (c === "}") {
        braces--;
        if (tmplDepths.length > 0 && tmplDepths[tmplDepths.length - 1] === braces) {
          tmplDepths.pop();
          i = scanTemplate(i + 1);
          continue;
        }
      }
      if (!/\s/.test(c)) prevSig = c;
      i++;
    }
  }
  return out.join("");
}

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
