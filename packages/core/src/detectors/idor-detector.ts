// ─────────────────────────────────────────────────────────────────────────────
// IDOR Detector
//
// Authenticated request handlers that load, update or delete a row by an id the
// caller supplies (route params, query string, body), with no user/org/tenant
// filter on the query and no ownership check on the row.
// ─────────────────────────────────────────────────────────────────────────────

import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { makeFinding } from "./utils/finding.js";
import { classifyFile, isJsLike, isServerScope } from "./utils/file-kind.js";
import { getJsSource } from "./utils/js-source.js";
import { extractFunctions, handlerSpans, type FunctionSpan } from "./utils/js-functions.js";
import { analyzeTaint } from "./utils/taint.js";
import {
  columnName,
  extractQueryChains,
  isIdColumn,
  isOwnerColumn,
  requestValue,
  type QueryFilter,
  type RequestValue,
} from "./utils/query-chains.js";
import {
  chainHasExpressAuth,
  extractExpressRoutes,
  isCoveredByExpressUse,
  localAuthHelpers,
  middlewareProtectsApi,
  spanAuthenticates,
  verifiesSignature,
  type ExpressRoute,
} from "./utils/route-analyzer.js";
import { ADMIN_CHECK_RE, IDENTITY_VALUE_RE, OWNERSHIP_CHECK_RE } from "./patterns/auth-patterns.js";

const HANDLER_ROLES = new Set([
  "app-route-handler",
  "pages-api-handler",
  "express-handler",
  "server-action",
]);
/** Catalog-style tables whose rows are usually readable by any signed-in user. */
const PUBLIC_TABLE_RE =
  /^(?:products?|categor(?:y|ies)|posts?|articles?|pages?|plans?|prices?|pricing|countries|tags?|faqs?|stores?|shops?|public_\w+)$/i;
/** `is_published = true`-style filters: the row is public by design. */
const PUBLIC_FLAG_RE =
  /^(?:is_?published|published|is_?public|public|visibility|is_?listed|slug)$/i;
const ADMIN_PATH_RE = /(?:^|\/)(?:admin|internal|staff|superuser|backoffice)(?:\/|$)/i;
const REQ_IDENTITY_RE = /\b(?:req|request)\s*\.\s*(?:user|auth)\b/;
const PREFILTER_RE = /\.\s*(?:from|find\w*|update\w*|delete\w*|upsert|select)\s*\(/;
const MAX_PER_FILE = 25;

function safeName(name: string | undefined): string {
  return name !== undefined && /^[\w.-]{1,64}$/.test(name) ? `"${name}"` : "a table";
}

/** The Express route whose final handler is `span`, if any. */
function routeOf(routes: readonly ExpressRoute[], span: FunctionSpan): ExpressRoute | undefined {
  let best: ExpressRoute | undefined;
  for (const r of routes) if (r.index < span.start && (!best || r.index > best.index)) best = r;
  return best;
}

export class IdorDetector implements Detector {
  id = "idor-detector";
  name = "IDOR Detection";
  category = "authorization" as const;
  description =
    "Detects authenticated handlers that read or change a record by a caller-supplied id without scoping the query to the caller's user or organization.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    let middleware: boolean | undefined;
    for (const file of context.files) {
      try {
        if (!isJsLike(file)) continue;
        const text = await context.readFile(file);
        if (!text || !PREFILTER_RE.test(text)) continue;
        const cls = classifyFile(file, text, context.projectContext);
        if (!isServerScope(cls) || cls.testOrFixture || cls.generated) continue;
        const src = await getJsSource(context, file);
        const spans = handlerSpans(src, cls).filter((s) => HANDLER_ROLES.has(s.role));
        if (spans.length === 0) continue;
        const helpers = localAuthHelpers(src, extractFunctions(src, cls));
        const routes =
          cls.kind === "express-server" || spans.some((s) => s.role === "express-handler")
            ? extractExpressRoutes(text)
            : [];
        const adminFile = ADMIN_PATH_RE.test(file.replace(/\\/g, "/"));
        let count = 0;
        for (const span of spans) {
          if (count >= MAX_PER_FILE || adminFile) break;
          const body = src.code.slice(span.bodyStart, span.bodyEnd);
          const bodyText = src.text.slice(span.bodyStart, span.bodyEnd);
          if (verifiesSignature(body)) continue;
          if (ADMIN_CHECK_RE.test(bodyText) || OWNERSHIP_CHECK_RE.test(body)) continue;
          const chains = extractQueryChains(src, span.bodyStart, span.bodyEnd);
          if (chains.length === 0) continue;
          let authed = spanAuthenticates(src, span, helpers) || REQ_IDENTITY_RE.test(body);
          if (!authed && span.role === "express-handler") {
            const route = routeOf(routes, span);
            authed =
              route !== undefined &&
              (chainHasExpressAuth(route) || isCoveredByExpressUse(text, route));
          }
          if (!authed && (span.role === "app-route-handler" || span.role === "pages-api-handler")) {
            middleware ??= await middlewareProtectsApi(context.files, (f) => context.readFile(f));
            authed = middleware;
          }
          if (!authed) continue;
          const state = analyzeTaint(src, span, { runtime: "server" });
          for (const chain of chains) {
            if (chain.verb === "insert" || chain.client === "rls" || chain.opaqueFilter) continue;
            if (
              chain.verb === "select" &&
              chain.table !== undefined &&
              PUBLIC_TABLE_RE.test(chain.table)
            )
              continue;
            if (chain.filters.some((f) => PUBLIC_FLAG_RE.test(columnName(f.column)))) continue;
            let scoped = false;
            let target: { filter: QueryFilter; origin: RequestValue } | undefined;
            for (const f of chain.filters) {
              const owner = isOwnerColumn(f.column);
              if (!owner && !isIdColumn(f.column)) continue;
              const origin = requestValue(state, src, f.value);
              if (origin === undefined) {
                if (owner || IDENTITY_VALUE_RE.test(f.value.text)) scoped = true;
              } else {
                target ??= { filter: f, origin };
              }
            }
            if (scoped || target === undefined) continue;
            // Ownership can still be enforced where a per-handler scan cannot see it (a helper in
            // another file, a database trigger), so this rule stays at medium confidence.
            const action =
              chain.verb === "select" ? "reads" : chain.verb === "delete" ? "deletes" : "changes";
            findings.push(
              makeFinding({
                category: "authorization",
                ruleId: "authorization/idor-unscoped-lookup",
                title: "Record accessed by a caller-supplied id without an ownership check",
                severity: "high",
                confidence: "medium",
                file,
                line: target.filter.line,
                endLine: span.endLine,
                evidence: src.lineText(target.filter.line),
                discriminator: `${chain.start}:${columnName(target.filter.column)}`,
                plainEnglishProblem: `This handler ${action} a row of ${safeName(chain.table)} by an id taken from the ${target.origin.label}, but the query is not limited to records the signed-in user or their organization owns, and nothing checks the row's owner afterwards.`,
                whyItMatters:
                  "Any logged-in user can change the id in the URL or request and read or modify another user's or another tenant's records (an insecure direct object reference). Ids are often sequential or leak in URLs, so they are not a secret.",
                fixSteps: [
                  'Add the owner or tenant filter to the query itself, e.g. `.eq("org_id", session.orgId)` (Supabase) or `where: { id, userId: session.user.id }` (Prisma).',
                  "Alternatively load the row and return 404 when its owner/org differs from the signed-in user before using or returning it.",
                  "Prefer the user's RLS-scoped client over the service-role client for user-facing queries so the database enforces ownership too.",
                ],
                aiFixPrompt:
                  'This API handler reads, updates or deletes a database record using an id that comes from the request (route params, query string or body) without restricting the query to records the signed-in user owns. Add an ownership or tenant filter to the same query (for example `.eq("org_id", session.orgId)` in Supabase or `where: { id, userId: session.user.id }` in Prisma) so another user\'s id behaves like a missing record (404). Keep the existing authentication check and do not rely on ids being hard to guess.',
              }),
            );
            count++;
          }
        }
      } catch {
        // detectors never throw
      }
    }
    return findings;
  }
}
