// ─────────────────────────────────────────────────────────────────────────────
// Route Secret Detector
//
// Routes (cron jobs, internal hooks, admin endpoints) "protected" by comparing a
// query parameter or header with a literal committed in source, and secret
// comparisons with `===` instead of a constant-time compare.
// ─────────────────────────────────────────────────────────────────────────────

import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { makeFinding } from "./utils/finding.js";
import { classifyFile, isJsLike, isServerScope } from "./utils/file-kind.js";
import { getJsSource, type JsSource } from "./utils/js-source.js";
import { findSecretComparisons, type SecretComparison } from "./utils/route-analyzer.js";
import { SECRET_PARAM_NAME_RE } from "./patterns/auth-patterns.js";

const PREFILTER_RE = /[!=]==?/;
const REQUEST_HINT_RE = /\b(?:searchParams|query|headers?|cookies)\b/;
const CONSTANT_TIME_RE =
  /\b(?:timingSafeEqual|safeCompare|safeEqual|constantTimeEqual|constantTimeCompare|timingSafeCompare|secureCompare|tsscmp)\b/;
const MAX_PER_FILE = 25;

/** The comparison line with the compared literal blanked out (never echo the secret). */
function redactedLine(src: JsSource, c: SecretComparison): string {
  const line = src.lineAt(c.offset);
  const lineStart = src.lines.lineStart(line);
  const text = src.lineText(line);
  const a = c.valueStart - lineStart;
  const b = c.valueEnd - lineStart;
  if (a < 0 || b > text.length || b <= a + 1) return text;
  return `${text.slice(0, a + 1)}[REDACTED]${text.slice(b - 1)}`;
}

export class RouteSecretDetector implements Detector {
  id = "route-secret-detector";
  name = "Route Secret Detection";
  category = "auth" as const;
  description =
    "Detects routes guarded by a query parameter or header compared with a hardcoded value, and secret comparisons that are not constant-time.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of context.files) {
      try {
        if (!isJsLike(file)) continue;
        const text = await context.readFile(file);
        if (!text || !PREFILTER_RE.test(text) || !REQUEST_HINT_RE.test(text)) continue;
        const cls = classifyFile(file, text, context.projectContext);
        if (!isServerScope(cls) || cls.testOrFixture || cls.generated) continue;
        const src = await getJsSource(context, file);
        const constantTime = CONSTANT_TIME_RE.test(src.code);
        const seen = new Set<number>();
        let count = 0;
        for (const c of findSecretComparisons(src, 0, src.text.length)) {
          if (!c.secretLike || seen.has(c.line) || count >= MAX_PER_FILE) continue;
          seen.add(c.line);
          const evidence = c.against === "literal" ? redactedLine(src, c) : src.lineText(c.line);
          if (c.against === "literal") {
            findings.push(
              makeFinding({
                category: "auth",
                ruleId: "auth/hardcoded-route-secret",
                title: "Route protected by a hardcoded secret in source",
                severity: "high",
                confidence: SECRET_PARAM_NAME_RE.test(c.name) ? "high" : "medium",
                file,
                line: c.line,
                evidence,
                discriminator: c.name,
                plainEnglishProblem:
                  "This code lets a request through when a query parameter or header equals a fixed string written in the source code. That string is the only thing protecting the endpoint.",
                whyItMatters:
                  "Anyone who sees the code (a leaked repo, a former contributor, a bundled file) or guesses the value can call the endpoint. Values sent in query strings also end up in server logs, browser history and Referer headers.",
                fixSteps: [
                  "Generate a long random secret and store it in an environment variable (for example `CRON_SECRET`), never in code.",
                  "Send it in an `Authorization: Bearer ...` header instead of the query string.",
                  "Compare with a constant-time function such as `crypto.timingSafeEqual` on equal-length buffers, and rotate the old value.",
                ],
                aiFixPrompt:
                  "This route is protected only by comparing a query parameter or header with a hardcoded string in the source code. Replace the literal with a long random secret read from an environment variable (e.g. process.env.CRON_SECRET), require it in the Authorization header rather than the query string, compare it with crypto.timingSafeEqual on equal-length buffers, and return 401 when it is missing or wrong.",
              }),
            );
          } else if (!constantTime) {
            findings.push(
              makeFinding({
                category: "auth",
                ruleId: "auth/non-constant-time-compare",
                title: "Secret compared with === instead of a constant-time check",
                severity: "low",
                confidence: "medium",
                file,
                line: c.line,
                evidence,
                discriminator: c.name,
                plainEnglishProblem:
                  "A secret from a request header or query parameter is compared with the expected value using `===`/`!==`, which stops at the first differing character.",
                whyItMatters:
                  "Timing differences can, in principle, let an attacker recover a secret byte by byte. It is hard to exploit over the network, but a constant-time compare costs nothing.",
                fixSteps: [
                  "Compare secrets with `crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))` after checking that both have the same length.",
                  "Keep the secret in an environment variable and send it in a header, not the query string.",
                ],
                aiFixPrompt:
                  "This code compares a request-supplied secret with the expected value using === or !==. Replace the comparison with a constant-time check: convert both values to Buffers, return false when their lengths differ, then use crypto.timingSafeEqual.",
              }),
            );
          }
          count++;
        }
      } catch {
        // detectors never throw
      }
    }
    return findings;
  }
}
