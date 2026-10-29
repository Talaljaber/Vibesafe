// ─────────────────────────────────────────────────────────────────────────────
// Mass Assignment Detector
//
// The whole request body (or a spread of it) written into an insert/update/upsert/
// create, so the caller chooses every column: role, org_id, is_admin, price...
// ─────────────────────────────────────────────────────────────────────────────

import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { makeFinding } from "./utils/finding.js";
import { classifyFile, isJsLike, isServerScope } from "./utils/file-kind.js";
import { getJsSource } from "./utils/js-source.js";
import { handlerSpans } from "./utils/js-functions.js";
import { analyzeTaint, type TaintHit, type TaintState } from "./utils/taint.js";
import {
  SEEDED_SOURCES,
  extractQueryChains,
  objectProps,
  type QueryRange,
} from "./utils/query-chains.js";
import { IDENTITY_VALUE_RE } from "./patterns/auth-patterns.js";

const HANDLER_ROLES = new Set([
  "app-route-handler",
  "pages-api-handler",
  "express-handler",
  "server-action",
]);
/** Taint sources that carry a caller-built object. */
const BODY_SOURCES = new Set([
  "request-body",
  "request-payload",
  "request-query",
  "request-param",
  "server-action-argument",
  "koa-request",
  "hono-request",
  "lambda-event",
]);
/** A whole object: identifier/member chain, `await req.json()`, `req.body`, `Object.fromEntries(...)`. */
const WHOLE_OBJECT_RE =
  /^(?:await\s+)?(?:[A-Za-z_$][\w$]*(?:\s*\??\.\s*[A-Za-z_$][\w$]*)*|(?:req|request)\s*\.\s*json\s*\(\s*\)|Object\s*\.\s*fromEntries\s*\([^()]*(?:\([^()]*\))?[^()]*\))$/;
/** Models where an extra column means privilege escalation or a tenant switch. */
const SENSITIVE_MODEL_RE =
  /(?:^|[_.]|(?<=[a-z]))(?:users?|members?|memberships?|profiles?|roles?|accounts?|orgs?|organi[sz]ations?|teams?|admins?|permissions?|tenants?|staff|employees?)(?:$|[_.A-Z])/i;
/** Fields that, set explicitly after the spread, show the author restricted the dangerous ones. */
const SENSITIVE_FIELD_RE =
  /^(?:role|roles|is_?admin|isAdmin|admin|org_?id|orgId|tenant_?id|tenantId|user_?id|userId|owner_?id|ownerId|permissions?|plan|status|verified|email_verified)$/;
const PREFILTER_RE = /\.\s*(?:insert|update|upsert|create\w*|set|values)\s*\(/;
const MAX_PER_FILE = 25;

function safeName(name: string | undefined): string {
  return name !== undefined && /^[\w.-]{1,64}$/.test(name) ? `"${name}"` : "the table";
}

/** Uncleaned caller-built object reaching `r` as a whole, or undefined. */
function wholeBody(state: TaintState, r: QueryRange): TaintHit | undefined {
  const text = r.text.trim();
  if (!WHOLE_OBJECT_RE.test(text) || IDENTITY_VALUE_RE.test(text)) return undefined;
  const hit = state.exprTaint(r.start, r.end);
  if (hit === undefined || hit.trust !== "remote" || hit.cleanedBy.length > 0) return undefined;
  if (!BODY_SOURCES.has(hit.source.id)) return undefined;
  if (hit.path === "indirect" && !SEEDED_SOURCES.has(hit.source.id)) return undefined;
  if (hit.via !== undefined && /^(?:session|user|claims|auth)$/.test(hit.via)) return undefined;
  return hit;
}

export class MassAssignmentDetector implements Detector {
  id = "mass-assignment-detector";
  name = "Mass Assignment Detection";
  category = "authorization" as const;
  description =
    "Detects request bodies written whole (or spread) into database inserts and updates, letting callers set columns such as role or org_id.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of context.files) {
      try {
        if (!isJsLike(file)) continue;
        const text = await context.readFile(file);
        if (!text || !PREFILTER_RE.test(text)) continue;
        const cls = classifyFile(file, text, context.projectContext);
        if (!isServerScope(cls) || cls.testOrFixture || cls.generated) continue;
        const src = await getJsSource(context, file);
        let count = 0;
        let overflow = 0;
        let overflowLine = 0;
        for (const span of handlerSpans(src, cls)) {
          if (!HANDLER_ROLES.has(span.role)) continue;
          const chains = extractQueryChains(src, span.bodyStart, span.bodyEnd).filter(
            (c) => c.payload !== undefined && c.verb !== "select" && c.verb !== "delete",
          );
          if (chains.length === 0) continue;
          const state = analyzeTaint(src, span, { runtime: "server" });
          for (const chain of chains) {
            const payload = chain.payload!;
            if (/\b(?:pick|omit)\s*\(/.test(src.code.slice(payload.start, payload.end))) continue;
            let hit: TaintHit | undefined;
            let anchor = payload.start;
            let overridden = false;
            if (src.code[payload.start] === "{") {
              const props = objectProps(src, payload.start);
              for (const p of props) {
                if (!p.spread) continue;
                hit = wholeBody(state, p.value);
                if (hit !== undefined) {
                  anchor = p.start;
                  overridden = props.some(
                    (q) => !q.spread && q.start > p.start && SENSITIVE_FIELD_RE.test(q.key ?? ""),
                  );
                  break;
                }
              }
            } else {
              hit = wholeBody(state, payload);
            }
            if (hit === undefined) continue;
            if (count >= MAX_PER_FILE) {
              overflow++;
              if (overflowLine === 0) overflowLine = src.lineAt(anchor);
              continue;
            }
            const sensitive = chain.table !== undefined && SENSITIVE_MODEL_RE.test(chain.table);
            const confident =
              sensitive && hit.path !== "indirect" && !span.truncated && !overridden;
            const line = src.lineAt(anchor);
            findings.push(
              makeFinding({
                category: "authorization",
                ruleId: "authorization/mass-assignment",
                title: "Request body written straight into the database (mass assignment)",
                severity: "high",
                confidence: confident ? "high" : "medium",
                file,
                line,
                endLine: span.endLine,
                evidence: src.lineText(line),
                discriminator: `${chain.start}`,
                plainEnglishProblem: `The ${hit.source.label} is passed whole into a database ${chain.verb === "insert" ? "insert" : chain.verb} on ${safeName(chain.table)} instead of copying only the fields users may change, so a caller can set any column (for example role, org_id, user_id or is_admin).`,
                whyItMatters:
                  "An attacker adds extra JSON fields to a normal request to promote themselves to admin/owner, move a record into another tenant, or change prices and statuses that only the server should set.",
                fixSteps: [
                  "Copy only the allowed fields into the write, e.g. `{ display_name: body.display_name }`, or parse the body with a strict schema that does not contain role or ownership fields.",
                  "Set ownership and privilege columns (org_id, user_id, role) from the session on the server, never from the request.",
                  "If role changes are a feature, handle them in a separate code path that checks the caller may grant that role.",
                ],
                aiFixPrompt:
                  "This API handler writes the request body (or a spread of it) directly into a database insert/update, so callers can set any column such as role, org_id, user_id or is_admin. Replace the spread with an explicit allowlist of user-editable fields (or a strict schema without privilege/ownership fields), set ownership columns from the authenticated session, and move any role change into a separate, permission-checked path.",
              }),
            );
            count++;
          }
        }
        if (overflow > 0) {
          findings.push(
            makeFinding({
              category: "authorization",
              ruleId: "authorization/mass-assignment",
              title: `${overflow} more request bodies written straight into the database`,
              severity: "high",
              confidence: "medium",
              file,
              line: overflowLine,
              evidence: src.lineText(overflowLine),
              discriminator: "summary",
              plainEnglishProblem: `This file has ${overflow} more places that write a request body whole into the database. Only the first ${MAX_PER_FILE} are listed individually.`,
              whyItMatters:
                "Callers can set any column (role, org_id, user_id, is_admin) by adding extra JSON fields.",
              fixSteps: [
                "Copy only the allowed fields into each write, or parse the body with a strict schema without privilege or ownership fields.",
              ],
              aiFixPrompt:
                "Many handlers in this file write the request body whole into database inserts/updates. Replace each with an explicit allowlist of user-editable fields and set ownership columns from the session.",
            }),
          );
        }
      } catch {
        // detectors never throw
      }
    }
    return findings;
  }
}
