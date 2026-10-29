// ─────────────────────────────────────────────────────────────────────────────
// Error Leak Detector
//
// Server responses that send an error's stack trace or the raw database error
// details/hint back to the client.
// ─────────────────────────────────────────────────────────────────────────────

import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { makeFinding } from "./utils/finding.js";
import { classifyFile, isJsLike, isServerScope } from "./utils/file-kind.js";
import { getJsSource } from "./utils/js-source.js";

/** Response constructors whose argument is sent to the client. Matched on masked code. */
const RESPONSE_CALL_RE =
  /\b(?:(?:NextResponse|Response)\s*\.\s*json|new\s+(?:NextResponse|Response)|(?:res|response|reply|ctx|c)\s*(?:\.\s*status\s*\([^()]*\))?\s*\.\s*(?:json|send|end))\s*\(/g;
/** `err.stack` read in the response payload. */
const STACK_READ_RE = /[\w$)\]]\s*\??\.\s*stack\b/;
/** Raw PostgREST/Postgres error internals: `details: e.details`, `hint: error.hint`. */
const DB_DETAIL_RE = /[\w$)\]]\s*\??\.\s*(?:details|hint)\b/;
/** Development-only guards around the leak. */
const DEV_GUARD_RE = /\bNODE_ENV\b|\bisDev\w*\b|\bisProd\w*\b|\b(?:dev|debug)Mode\b|\bIS_DEV\b/;
const PREFILTER_RE = /\.\s*(?:stack|details|hint)\b/;
const MAX_PER_FILE = 25;

export class ErrorLeakDetector implements Detector {
  id = "error-leak-detector";
  name = "Error Leak Detection";
  category = "security_config" as const;
  description =
    "Detects API responses that return error stack traces or raw database error details to the client.";

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
        const code = src.code;
        RESPONSE_CALL_RE.lastIndex = 0;
        let count = 0;
        for (
          let m = RESPONSE_CALL_RE.exec(code);
          m && count < MAX_PER_FILE;
          m = RESPONSE_CALL_RE.exec(code)
        ) {
          const open = m.index + m[0].length - 1;
          const close = src.matchOf(open);
          if (close <= open || close - open > 4000) continue;
          const args = code.slice(open + 1, close);
          const stack = STACK_READ_RE.exec(args);
          const detail = stack ? null : DB_DETAIL_RE.exec(args);
          const hit = stack ?? detail;
          if (!hit) continue;
          const lineStart = src.lines.lineStart(Math.max(1, src.lineAt(m.index) - 3));
          if (DEV_GUARD_RE.test(code.slice(lineStart, close))) continue;
          const line = src.lineAt(open + 1 + hit.index + hit[0].length - 1);
          findings.push(
            makeFinding({
              category: "security_config",
              ruleId: "security_config/error-stack-leak",
              title: stack
                ? "Error stack trace returned to the client"
                : "Raw database error details returned to the client",
              severity: "medium",
              confidence: stack ? "high" : "medium",
              file,
              line,
              evidence: src.lineText(line),
              plainEnglishProblem: stack
                ? "This response includes the error's stack trace, which shows server file paths, library versions and the code path that failed."
                : "This response passes the database error's internal `details`/`hint` fields to the client, which can reveal table, column and constraint names and fragments of the query.",
              whyItMatters:
                "Attackers use these details to map your schema and code and to tune injection or enumeration attacks. Users get nothing useful from them.",
              fixSteps: [
                'Log the full error on the server (`console.error(err)` or your logger) and return a generic message such as `{ error: "Internal Server Error" }` with an opaque request id.',
                "Map known, safe error cases (validation, not found, conflict) to explicit messages instead of forwarding the raw error.",
                'If you need details while developing, include them only when `process.env.NODE_ENV !== "production"`.',
              ],
              aiFixPrompt:
                "This API error response sends internal error information (stack trace or raw database error details/hint/code) to the client. Change it to log the full error on the server and return only a generic message (plus an optional request id) to the client, mapping known safe cases such as validation or not-found errors to explicit messages. Only include details in development builds.",
            }),
          );
          count++;
        }
      } catch {
        // detectors never throw
      }
    }
    return findings;
  }
}
