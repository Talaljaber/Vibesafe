import {
  RISKY_ROUTE_PATTERNS,
  RISKY_HTTP_METHODS,
  AUTH_CHECK_PATTERNS,
  MIDDLEWARE_AUTH_PATTERNS,
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
