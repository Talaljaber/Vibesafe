import { handlerSpan } from "../target/enclosing-handler.js";

export const MAY_WRITE_REASON = "handler may write";

const WRITE_PATTERNS: readonly RegExp[] = [
  /\.(insert|update|upsert|delete|deleteMany|updateMany|create|createMany)\s*\(/,
  /fetch\([\s\S]{0,200}?method\s*:\s*["'](POST|PUT|PATCH|DELETE)/,
  /\b(stripe|resend|sendgrid|nodemailer|twilio|ses)\b[\s\S]{0,80}\.(create|send|sendMail)\(/,
  /\bexec(Sync)?\(|\bspawn\(/,
  /\bfs\.(write|rm|unlink|rename|append)/,
  /revalidate(Path|Tag)\(/,
  /cookies\(\)\.(set|delete)/,
];

const RISKY_SEGMENT_RE =
  /\/(seed|reset|delete|remove|logout|signout|cron|migrate|webhook|send|charge|sync|import|purge|clear|wipe|drop)(\/|$)/i;

export interface PreflightResult {
  skip: boolean;
  reason?: string | undefined;
}

/**
 * GET side-effect pre-flight. A GET handler is skipped (INCONCLUSIVE "handler may write") when
 * its own body, not the whole file, matches a write pattern, or its route path has a risky
 * segment. A false "may write" is the safe direction. When the file has no GET handler export
 * (e.g. an unrecognised shape) the whole file is checked.
 */
export function preflightGet(routePattern: string, content: string): PreflightResult {
  const body = handlerSpan(content, "GET")?.body ?? content;
  const hit = WRITE_PATTERNS.some((re) => re.test(body)) || RISKY_SEGMENT_RE.test(routePattern);
  return hit ? { skip: true, reason: MAY_WRITE_REASON } : { skip: false };
}
