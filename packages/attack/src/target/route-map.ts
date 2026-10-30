import { isPublicRoutePath, nextRoutePath } from "@talaljaber/vibesafe-core";
import type { Finding } from "@talaljaber/vibesafe-shared";
import type { RouteEntry, SessionSpec, StaticRef } from "../types.js";
import { handlerLines } from "./enclosing-handler.js";

const APP_ROUTE_FILE_RE = /(?:^|\/)app\/(?:.*\/)?route\.(?:ts|js|mjs)$/;

const norm = (p: string): string => p.replace(/\\/g, "/");

/** `[id]` and `[...slug]` segments of a route pattern, as written. */
export function dynamicSegmentsOf(pattern: string): string[] {
  return pattern.split("/").filter((s) => /^\[.+\]$/.test(s));
}

function toRef(f: Finding): StaticRef {
  return {
    findingId: f.id,
    ruleId: f.ruleId,
    title: f.title,
    file: f.file ?? "",
    line: f.line,
    severity: f.severity,
  };
}

/**
 * Builds the route map from the scan's file list: every App Router `app/**\/route.{ts,js,mjs}`
 * that is not a public route (sign-in, callbacks, health). Findings located in a route file
 * become that route's findingRefs.
 */
export function buildRouteMap(
  files: readonly string[],
  readSource: (relativeFile: string) => string | undefined,
  findings: readonly Finding[] = [],
): RouteEntry[] {
  const routes: RouteEntry[] = [];
  for (const file of files) {
    const rel = norm(file);
    if (!APP_ROUTE_FILE_RE.test(rel)) continue;
    const pattern = nextRoutePath(rel);
    if (pattern === undefined || isPublicRoutePath(pattern)) continue;
    const content = readSource(file) ?? "";
    const methods = handlerLines(content).map((h) => h.method);
    routes.push({
      pattern,
      sourceFile: rel,
      methods: [...methods],
      dynamicSegments: dynamicSegmentsOf(pattern),
      findingRefs: findings.filter((f) => f.file !== undefined && norm(f.file) === rel).map(toRef),
    });
  }
  return routes.sort((a, b) => (a.pattern < b.pattern ? -1 : a.pattern > b.pattern ? 1 : 0));
}

export type ConcretePath = { path: string } | { skip: { outcome: "INCONCLUSIVE"; reason: string } };

/**
 * Fills a route pattern with the concrete id from `session.resources[pattern]`. Ids are never
 * invented: a dynamic route with no id is INCONCLUSIVE "no test id for this route".
 */
export function concretePath(pattern: string, session: SessionSpec | undefined): ConcretePath {
  if (dynamicSegmentsOf(pattern).length === 0) return { path: pattern };
  const id = session?.resources[pattern];
  if (id === undefined || id === "") {
    return { skip: { outcome: "INCONCLUSIVE", reason: "no test id for this route" } };
  }
  // SessionSpec.resources holds one id per pattern, so several dynamic segments cannot be filled.
  if (dynamicSegmentsOf(pattern).length > 1) {
    return { skip: { outcome: "INCONCLUSIVE", reason: "no test id for this route" } };
  }
  const filled = pattern.split("/").map((s) => {
    if (!/^\[.+\]$/.test(s)) return s;
    return s.startsWith("[...") || s.startsWith("[[...")
      ? id.split("/").map(encodeURIComponent).join("/")
      : encodeURIComponent(id);
  });
  return { path: filled.join("/") };
}
