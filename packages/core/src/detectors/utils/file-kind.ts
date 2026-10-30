import {
  classifyInfraFile,
  isLockfileName,
  isPythonRequirementsFile,
  type ProjectContext,
} from "@talaljaber/vibesafe-shared";
import { hasUseClientDirective, hasUseServerDirective, isClientFile } from "./file-classifier.js";
import { stripComments } from "./strip-comments.js";

/**
 * What a scanned file is. Path-only kinds come from {@link classifyPath}; a few JS
 * kinds (`next-server-action`, `next-client-component`, `client-module`,
 * `express-server`) need the content and come from {@link classifyFile}.
 */
export type FileKind =
  // Next.js (JS-like)
  | "next-app-route"
  | "next-pages-api"
  | "next-server-action"
  | "next-server-component"
  | "next-client-component"
  | "next-pages-page"
  | "next-error-boundary"
  | "next-middleware"
  | "next-config"
  // Other JS-like
  | "build-config"
  | "express-server"
  | "server-module"
  | "client-module"
  | "script"
  | "js-module"
  // Non-JS
  | "python"
  | "sql"
  | "dockerfile"
  | "dockerignore"
  | "compose"
  | "firebase-rules"
  | "workflow"
  | "gh-action"
  | "shell"
  | "terraform"
  | "tfvars"
  | "supabase-config"
  | "k8s-manifest"
  | "env"
  | "env-example"
  | "env-vault"
  | "package-manifest"
  | "lockfile"
  | "python-manifest"
  | "gitignore"
  | "json"
  | "other";

/**
 * Where a file's code runs. `unknown` is the default for plain modules whose
 * runtime cannot be told from the path or content (e.g. `lib/db.ts`) and for
 * non-JS data files.
 */
export type FileRuntime = "server" | "client" | "edge" | "build" | "script" | "infra" | "unknown";

/** Result of {@link classifyFile}. */
export interface FileClassification {
  kind: FileKind;
  runtime: FileRuntime;
  /** JS/TS source (see {@link isJsLike}). */
  jsLike: boolean;
  /** Test or fixture path (see {@link isTestOrFixturePath}). */
  testOrFixture: boolean;
  /** Generated or minified file (see {@link isGenerated}). */
  generated: boolean;
}

const RUNTIME: Record<FileKind, FileRuntime> = {
  "next-app-route": "server",
  "next-pages-api": "server",
  "next-server-action": "server",
  "next-server-component": "server",
  "next-client-component": "client",
  "next-pages-page": "client",
  "next-error-boundary": "client",
  "next-middleware": "edge",
  "next-config": "build",
  "build-config": "build",
  "express-server": "server",
  "server-module": "server",
  "client-module": "client",
  script: "script",
  "js-module": "unknown",
  python: "unknown",
  sql: "unknown",
  dockerfile: "infra",
  dockerignore: "infra",
  compose: "infra",
  "firebase-rules": "infra",
  workflow: "infra",
  "gh-action": "infra",
  shell: "infra",
  terraform: "infra",
  tfvars: "infra",
  "supabase-config": "infra",
  "k8s-manifest": "infra",
  env: "infra",
  "env-example": "infra",
  "env-vault": "infra",
  "package-manifest": "unknown",
  lockfile: "unknown",
  "python-manifest": "unknown",
  gitignore: "unknown",
  json: "unknown",
  other: "unknown",
};

/** The runtime a file kind executes in. */
export function runtimeOfKind(kind: FileKind): FileRuntime {
  return RUNTIME[kind];
}

const JS_LIKE_RE = /\.(?:[cm]?[jt]s|[jt]sx)$/i;

/** True for JS/TS sources: `.js .jsx .ts .tsx .mjs .cjs .mts .cts` (including `.d.ts`). */
export function isJsLike(relativePath: string): boolean {
  return JS_LIKE_RE.test(relativePath);
}

function normalize(relativePath: string): string {
  return relativePath.replace(/\\/g, "/").replace(/^\.\//, "");
}

const TEST_SEGMENT_RE =
  /(?:^|\/)(?:tests?|__tests__|__mocks__|__fixtures__|fixtures|e2e|cypress)\//i;
const TEST_NAME_RE = /\.(?:test|spec)\.[^/]+$|(?:^|\/)(?:test_[^/]*|[^/]*_test|conftest)\.py$/i;

/**
 * True for test and fixture paths at any depth: `test/`, `tests/`, `__tests__/`,
 * `__mocks__/`, `fixtures/`, `__fixtures__/`, `e2e/`, `cypress/`, `*.test.*`, `*.spec.*`,
 * `test_*.py`, `*_test.py`, `conftest.py`. Broader than the discovery defaults on
 * purpose: detectors also see files passed explicitly via `targetFiles`.
 */
export function isTestOrFixturePath(relativePath: string): boolean {
  const p = normalize(relativePath);
  return TEST_SEGMENT_RE.test(p) || TEST_NAME_RE.test(p);
}

const GENERATED_PATH_RE =
  /\.d\.[cm]?ts$|\.min\.[cm]?js$|[.-]bundle\.[cm]?js$|\.generated\.[^/]+$|(?:^|\/)(?:__generated__|generated)\//i;
const GENERATED_HEADER_RE = /@generated\b|\bDO NOT EDIT\b|\bauto-?generated\b/i;

/**
 * True for generated or minified files: `.d.ts`, `*.min.js`, `*.bundle.js`,
 * `*.generated.*`, files under `generated/` or `__generated__/`, and, when `content`
 * is given, files whose first 512 characters carry an `@generated`, `DO NOT EDIT`
 * or `auto-generated` marker.
 */
export function isGenerated(relativePath: string, content?: string | undefined): boolean {
  if (GENERATED_PATH_RE.test(normalize(relativePath))) return true;
  return content !== undefined && GENERATED_HEADER_RE.test(content.slice(0, 512));
}

const JS_EXT = String.raw`\.(?:[cm]?[jt]s|[jt]sx)$`;
const APP_ROUTE_RE = new RegExp(String.raw`(?:^|/)app/(?:.+/)?route` + JS_EXT);
const APP_ERROR_RE = new RegExp(String.raw`(?:^|/)app/(?:.+/)?(?:global-)?error` + JS_EXT);
const APP_SERVER_COMPONENT_RE = new RegExp(
  String.raw`(?:^|/)app/(?:.+/)?(?:page|layout|template|loading|not-found|default)` + JS_EXT,
);
const PAGES_API_RE = /(?:^|\/)(?:src\/)?pages\/api\//;
const PAGES_RE = /(?:^|\/)(?:src\/)?pages\//;
/** Next middleware only at a project root, `src/`, or a workspace package root. */
const MIDDLEWARE_RE = new RegExp(
  String.raw`^(?:(?:apps|packages)/[^/]+/)?(?:src/)?(?:middleware|proxy)` + JS_EXT,
);
const NEXT_CONFIG_RE = new RegExp(String.raw`(?:^|/)next\.config` + JS_EXT);
const BUILD_CONFIG_RE = new RegExp(
  String.raw`(?:^|/)(?:vite|vitest|webpack|rollup|tailwind|postcss|eslint|babel|jest|playwright|tsup|astro|svelte|nuxt|remix|drizzle|prettier)\.config` +
    JS_EXT +
    String.raw`|(?:^|/)\.eslintrc\.[cm]?js$`,
  "i",
);
const SCRIPT_PATH_RE = /(?:^|\/)(?:scripts|bin|seeds?)\/|(?:^|\/)seed\.[^/]+$/;
const SERVER_PATH_RE = /(?:^|\/)(?:server|backend)\/|\.server\.[^/]+$/;

/**
 * Classifies a file from its path alone (`/` or `\` separators). JS files get their
 * Next.js / build / script / server kind when the path decides it, else `js-module`;
 * use {@link classifyFile} to refine JS kinds from content.
 */
export function classifyPath(relativePath: string): FileKind {
  const p = normalize(relativePath);
  const base = p.slice(p.lastIndexOf("/") + 1);

  if (isJsLike(p)) {
    if (NEXT_CONFIG_RE.test(p)) return "next-config";
    if (BUILD_CONFIG_RE.test(p)) return "build-config";
    if (PAGES_API_RE.test(p)) return "next-pages-api";
    if (APP_ROUTE_RE.test(p)) return "next-app-route";
    if (MIDDLEWARE_RE.test(p)) return "next-middleware";
    if (APP_ERROR_RE.test(p)) return "next-error-boundary";
    if (APP_SERVER_COMPONENT_RE.test(p)) return "next-server-component";
    if (PAGES_RE.test(p)) return "next-pages-page";
    if (SCRIPT_PATH_RE.test(p)) return "script";
    if (SERVER_PATH_RE.test(p)) return "server-module";
    return "js-module";
  }

  const infra = classifyInfraFile(p);
  // next.config.mts is JS-like and handled above; the other infra kinds map 1:1.
  if (infra !== null && infra !== "next-config-mts") return infra;
  if (/\.py$/i.test(base)) return "python";
  if (/\.sql$/i.test(base)) return "sql";
  if (base === "package.json") return "package-manifest";
  if (isLockfileName(base)) return "lockfile";
  if (
    base === "pyproject.toml" ||
    base === "Pipfile" ||
    base === "Pipfile.lock" ||
    isPythonRequirementsFile(p)
  ) {
    return "python-manifest";
  }
  if (base === ".gitignore") return "gitignore";
  if (/\.json$/i.test(base)) return "json";
  return "other";
}

/** Kinds decided by the path that content never overrides. */
const PATH_FINAL: ReadonlySet<FileKind> = new Set<FileKind>([
  "next-app-route",
  "next-pages-api",
  "next-middleware",
  "next-config",
  "build-config",
  "script",
  "next-error-boundary",
  "next-pages-page",
]);

const SERVER_ONLY_RE = /(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*)["']server-only["']/;
const EXPRESS_LIKE_RE =
  /(?:\bfrom\s*|\brequire\s*\(\s*)["'](?:express|fastify|koa|hono|@hapi\/hapi|restify)["']|\bhttp\.createServer\s*\(/;
const BROWSER_RE =
  /\b(?:window|document|navigator)\s*\.|\b(?:localStorage|sessionStorage)\b|\buse(?:State|Effect|LayoutEffect|Router|SearchParams|Pathname)\s*\(/;

/**
 * Classifies a file from its path and content. Refinements for JS files whose path
 * does not decide the kind:
 * - a leading `"use server"` directive gives `next-server-action`;
 * - a leading `"use client"` directive gives `next-client-component`;
 * - otherwise a plain module is a `script` (shebang), `server-module`
 *   (`import "server-only"`), `express-server` (imports express/fastify/koa/hono/hapi/
 *   restify or calls `http.createServer`), or a `client-module` when
 *   `isClientFile(...)` holds (e.g. Vite `src/`) or its code (comments and strings
 *   blanked) uses `window.`, `document.`, `navigator.`, web storage or the
 *   `useState/useEffect/useLayoutEffect/useRouter/useSearchParams/usePathname` hooks.
 *
 * Partition: every JS-like file has exactly one runtime, so server-side rules
 * (`runtime !== "client"`) and client-side rules (`runtime === "client"`) never
 * overlap and never both skip a file (see {@link isServerScope}/{@link isClientScope}).
 */
export function classifyFile(
  relativePath: string,
  content: string,
  projectContext?: Pick<ProjectContext, "framework"> | undefined,
): FileClassification {
  const jsLike = isJsLike(relativePath);
  let kind = classifyPath(relativePath);
  if (jsLike && !PATH_FINAL.has(kind))
    kind = refineJsKind(relativePath, kind, content, projectContext);
  return {
    kind,
    runtime: RUNTIME[kind],
    jsLike,
    testOrFixture: isTestOrFixturePath(relativePath),
    generated: isGenerated(relativePath, content),
  };
}

function refineJsKind(
  relativePath: string,
  kind: FileKind,
  content: string,
  projectContext: Pick<ProjectContext, "framework"> | undefined,
): FileKind {
  if (hasUseServerDirective(content)) return "next-server-action";
  if (hasUseClientDirective(content)) return "next-client-component";
  if (kind !== "js-module") return kind;
  if (/^﻿?#!/.test(content)) return "script";
  const code = stripComments(content);
  if (SERVER_ONLY_RE.test(code)) return "server-module";
  if (EXPRESS_LIKE_RE.test(code)) return "express-server";
  if (isClientFile(relativePath, content, projectContext)) return "client-module";
  if (BROWSER_RE.test(stripComments(content, { blankStrings: true }))) return "client-module";
  return "js-module";
}

/** JS file that server-side rules (injection and friends) analyse: runtime is not client. */
export function isServerScope(c: Pick<FileClassification, "jsLike" | "runtime">): boolean {
  return c.jsLike && c.runtime !== "client";
}

/** JS file that client-side rules analyse: runtime is client. */
export function isClientScope(c: Pick<FileClassification, "jsLike" | "runtime">): boolean {
  return c.jsLike && c.runtime === "client";
}
