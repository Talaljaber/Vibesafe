import { handlerLines } from "../target/enclosing-handler.js";

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
 * The text a GET may execute: the whole file minus the spans of the other handlers (each runs
 * from its export line to the next handler export). Prelude, helpers, aliased and wrapped
 * handler definitions stay in, so a false "may write" is the only error direction.
 */
function getReachableText(content: string): string {
  const handlers = handlerLines(content);
  const getLines = new Set(handlers.filter((h) => h.method === "GET").map((h) => h.line));
  if (getLines.size === 0) return content;
  const lines = content.split(/\r?\n/);
  const drop = new Set<number>();
  handlers.forEach((h, i) => {
    if (h.method === "GET" || getLines.has(h.line)) return;
    const next = handlers.slice(i + 1).find((n) => n.line > h.line);
    const end = next ? next.line - 1 : lines.length;
    for (let l = h.line; l <= end; l++) drop.add(l);
  });
  return lines.filter((_, i) => !drop.has(i + 1)).join("\n");
}

/**
 * GET side-effect pre-flight. A GET handler is skipped (INCONCLUSIVE "handler may write") when
 * code it can reach (see getReachableText) matches a write pattern, or its route path has a
 * risky segment. A false "may write" is the safe direction.
 */
export function preflightGet(routePattern: string, content: string): PreflightResult {
  const body = getReachableText(content);
  const hit = WRITE_PATTERNS.some((re) => re.test(body)) || RISKY_SEGMENT_RE.test(routePattern);
  return hit ? { skip: true, reason: MAY_WRITE_REASON } : { skip: false };
}
