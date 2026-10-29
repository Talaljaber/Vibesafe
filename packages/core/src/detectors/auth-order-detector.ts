// ─────────────────────────────────────────────────────────────────────────────
// Auth Order Detector
//
// A handler that writes to the database first and only afterwards checks the
// session, role or ownership: the write already happened when the check rejects.
// ─────────────────────────────────────────────────────────────────────────────

import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { makeFinding } from "./utils/finding.js";
import { classifyFile, isJsLike, isServerScope } from "./utils/file-kind.js";
import { getJsSource, type JsSource } from "./utils/js-source.js";
import { extractFunctions, handlerSpans } from "./utils/js-functions.js";
import { extractQueryChains, isWriteVerb } from "./utils/query-chains.js";
import { firstAuthCheck, isAuthWrapper, localAuthHelpers } from "./utils/route-analyzer.js";
import { OWNERSHIP_CHECK_RE } from "./patterns/auth-patterns.js";

const HANDLER_ROLES = new Set([
  "app-route-handler",
  "pages-api-handler",
  "express-handler",
  "server-action",
]);
/** Role/permission checks that gate a handler (matched on masked code). */
const ROLE_GATE_RE =
  /\.\s*role\s*(?:===|!==|==|!=)|\b(?:isAdmin|isStaff|hasRole|hasPermission|requireRole|requireAdmin|can)\s*\(|!\s*(?:isAdmin|isStaff|isOwner|isManager)\b/g;
/** Bookkeeping tables that are fine to write before authenticating. */
const LOG_TABLE_RE =
  /log|audit|event|attempt|metric|analytic|rate|limit|webhook|visit|view|request/i;
/** An early exit that rejects the caller, shortly after a check. */
const DENY_RE =
  /\b(?:return|throw)\b[^;]{0,160}?(?:\b40[13]\b|unauthori[sz]ed|Unauthori[sz]ed|forbidden|Forbidden|redirect\s*\(|notFound\s*\(|UNAUTHORIZED|FORBIDDEN)/;
const PREFILTER_RE = /\.\s*(?:insert|update|upsert|delete|create\w*|set|values)\s*\(/;

/**
 * Gates in `[from, to)`: `first` is the offset of the earliest auth/role/ownership check of
 * any kind, `denying` the earliest one followed by a rejecting early exit.
 */
function findGates(
  src: JsSource,
  from: number,
  to: number,
  helpers: ReadonlySet<string>,
): { first: number; denying: number } | undefined {
  const body = src.code.slice(from, to);
  const candidates: number[] = [];
  const auth = firstAuthCheck(body, helpers);
  if (auth !== undefined) candidates.push(auth);
  ROLE_GATE_RE.lastIndex = 0;
  for (let m = ROLE_GATE_RE.exec(body); m; m = ROLE_GATE_RE.exec(body)) candidates.push(m.index);
  const own = OWNERSHIP_CHECK_RE.exec(body);
  if (own) candidates.push(own.index);
  candidates.sort((a, b) => a - b);
  for (const c of candidates) {
    const after = src.text.slice(from + c, Math.min(to, from + c + 400));
    if (DENY_RE.test(after)) return { first: from + candidates[0]!, denying: from + c };
  }
  return undefined;
}

export class AuthOrderDetector implements Detector {
  id = "auth-order-detector";
  name = "Auth Order Detection";
  category = "authorization" as const;
  description =
    "Detects handlers that write to the database before checking the caller's session, role or ownership.";

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
        const spans = handlerSpans(src, cls).filter((s) => HANDLER_ROLES.has(s.role));
        if (spans.length === 0) continue;
        const helpers = localAuthHelpers(src, extractFunctions(src, cls));
        for (const span of spans) {
          if (span.wrappers.some(isAuthWrapper)) continue;
          const write = extractQueryChains(src, span.bodyStart, span.bodyEnd).find(
            (c) =>
              isWriteVerb(c.verb) &&
              c.client !== "rls" &&
              !(c.table !== undefined && LOG_TABLE_RE.test(c.table)),
          );
          if (write === undefined) continue;
          const gates = findGates(src, span.bodyStart, span.bodyEnd, helpers);
          // any check before the write (even one without a visible early exit) means no finding
          if (gates === undefined || gates.first <= write.start) continue;
          const gate = gates.denying;
          const confident =
            (write.client === "service-role" || write.client === "direct") && !span.truncated;
          findings.push(
            makeFinding({
              category: "authorization",
              ruleId: "authorization/auth-check-after-write",
              title: "Database write runs before the auth check",
              severity: "high",
              confidence: confident ? "high" : "medium",
              file,
              line: write.verbLine,
              endLine: span.endLine,
              evidence: src.lineText(write.verbLine),
              plainEnglishProblem: `This handler performs a database ${write.verb} on line ${write.verbLine} and only checks the session, role or ownership on line ${src.lineAt(gate)}, after the change is already made.`,
              whyItMatters:
                "Anyone, including signed-out users or members of another organization, can trigger the write; the later check only changes the response they get, not what happened in the database.",
              fixSteps: [
                "Move the session check (and any role or ownership check) to the top of the handler, before any database write.",
                'Scope the write itself to the caller (e.g. `.eq("org_id", session.orgId)`) so it cannot touch other tenants\' rows.',
                "Return 401/403 before doing any work when the checks fail.",
              ],
              aiFixPrompt:
                "This API handler writes to the database before it checks who the caller is and whether they may do it, so the write happens even when the request is later rejected. Reorder the handler so authentication and the role/ownership checks run first and return 401/403 early, then perform the write scoped to the caller's user or organization.",
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
