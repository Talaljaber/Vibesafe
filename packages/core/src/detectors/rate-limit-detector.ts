import type { Detector, Finding, ScanContext } from "@vibesafe/shared";
import { CATEGORY_PREFIX, createFindingId } from "@vibesafe/shared";
import { sanitizeEvidence } from "./utils/sanitize-evidence.js";
import { findAnyHandlerLine, isApiRoute, lineOfIndex, matcherCoversApi } from "./utils/route-analyzer.js";

const RULE_ID = "security_config/missing-rate-limit";
const SOURCE_RE = /\.(?:ts|js|mjs|cjs|tsx|jsx)$/;
const TEST_RE = /(?:\.(?:test|spec)\.[a-z]+$|(?:^|\/)(?:__tests__|tests?)\/)/;
const MIDDLEWARE_RE = /^(?:src\/)?middleware\.(?:ts|js)$/;

type Kind = "auth" | "ai" | "messaging";
interface Source {
  file: string;
  path: string;
}

/** Source that signals a rate limiter is in play. Applied to comment-stripped code. */
const RATE_LIMIT_SIGNALS: RegExp[] = [
  /@upstash\/ratelimit/,
  /rate-limiter-flexible/,
  /express-rate-limit/,
  /express-slow-down/,
  /["'][^"'\n]*rate-?limit[^"'\n]*["']/i, // any import specifier naming a rate limit module
  /\brateLimit\s*\(/,
  /\bslowDown\s*\(/,
  /\blimiter\./,
  /\bRatelimit\b/,
  /\bRateLimiter\b/,
];

/** `use(...)` calls that apply a limiter globally in an Express app/router. */
const GLOBAL_LIMITER_USE_RE =
  /\b(?:app|router|server)\.use\s*\([^)]*\b(?:rate-?limit\w*|\w*limiter\w*|slowDown|throttle\w*)\b/i;
const ARG_LIMITER_RE = /\b(?:rate-?limit\w*|\w*limiter\w*|slowDown|throttle\w*|\w*Limit)\b/i;

const AUTH_PATH_RE =
  /(?:^|[/\\._-])(?:log-?in|sign-?in|sign-?up|register|passwords?|forgot|reset|otp|verify|verification|2fa|mfa|magic-?link)(?:[/\\._-]|$)/i;

const AI_IMPORT_RE =
  /(?:from\s*|require\s*\(\s*|import\s*\(\s*)["'](?:openai|@anthropic-ai\/sdk|ai|@ai-sdk\/[\w-]+)["']/;
const MESSAGING_IMPORT_RE = /(?:from\s*|require\s*\(\s*|import\s*\(\s*)["'](?:resend|nodemailer|twilio)["']/;

const AI_CALL_RE =
  /\b(?:openai|anthropic|OpenAI|Anthropic)\b|\b(?:generateText|streamText|generateObject|streamObject)\s*\(|chat\.completions|messages\.create/;
const MESSAGING_CALL_RE = /\.sendMail\s*\(|\b[rR]esend\b|\btwilio\b|\.emails\.send\s*\(|messages\.create/;

const KIND_RANK: Record<Kind, number> = { auth: 0, ai: 1, messaging: 2 };

const KIND_INFO: Record<Kind, { label: string; why: string }> = {
  auth: {
    label: "authentication endpoint",
    why: "Without a limit, attackers can brute-force passwords and one-time codes, stuff stolen credentials, or flood password-reset emails.",
  },
  ai: {
    label: "AI/LLM endpoint",
    why: "Every request spends your paid AI credits. Without a limit, one script can drain your API budget in minutes.",
  },
  messaging: {
    label: "email/SMS sending endpoint",
    why: "Without a limit, someone can use your endpoint to spam people, hurting your sender reputation and running up provider bills.",
  },
};

interface Candidate {
  file: string;
  line: number;
  evidence: string;
  kinds: Set<Kind>;
}

function stripComments(code: string): string {
  return code.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " ")).replace(/(^|[^:\\])\/\/.*$/gm, "$1");
}

function hasSignal(code: string): boolean {
  return RATE_LIMIT_SIGNALS.some((re) => re.test(code));
}

function evidenceAt(code: string, line: number): string {
  return sanitizeEvidence(code.split("\n")[line - 1] ?? "");
}

/**
 * Flags sensitive endpoints (auth, AI/LLM, email/SMS sending) in Next.js route
 * handlers and Express routes that have no rate limiting signal.
 *
 * A signal counts when found in: the route file itself; a local module the file
 * imports (one level); a root `middleware.ts` that uses a limiter and runs on
 * `/api`; or, for Express, a global `app.use(limiter)` anywhere in the project
 * or a limiter passed as route middleware. Limits enforced outside the code
 * (CDN/WAF/gateway) are invisible to a static scan.
 */
export class RateLimitDetector implements Detector {
  id = "rate-limit-detector";
  name = "Missing Rate Limiting";
  category = "security_config" as const;
  description =
    "Detects sensitive endpoints (auth, AI/LLM, email/SMS) in Next.js and Express with no rate limiting.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const sources: Source[] = context.files
      .map((f) => ({ file: f, path: f.replace(/\\/g, "/") }))
      .filter(({ path }) => SOURCE_RE.test(path) && !TEST_RE.test(path));

    const cache = new Map<string, string>();
    const read = async (file: string): Promise<string> => {
      let c = cache.get(file);
      if (c === undefined) {
        c = stripComments(await context.readFile(file));
        cache.set(file, c);
      }
      return c;
    };

    // Project-wide signals.
    let middlewareLimits = false;
    let globalExpressLimiter = false;
    for (const { file, path } of sources) {
      const code = await read(file);
      if (MIDDLEWARE_RE.test(path) && hasSignal(code) && matcherCoversApi(code)) middlewareLimits = true;
      if (GLOBAL_LIMITER_USE_RE.test(code)) globalExpressLimiter = true;
    }

    const candidates: Candidate[] = [];
    for (const { file, path } of sources) {
      const code = await read(file);
      if (isApiRoute(path)) {
        if (middlewareLimits || (await this.importsSignal(code, path, sources, read))) continue;
        const line = findAnyHandlerLine(code);
        if (line === undefined) continue;
        const kinds = new Set<Kind>();
        if (AUTH_PATH_RE.test(path)) kinds.add("auth");
        if (AI_IMPORT_RE.test(code)) kinds.add("ai");
        if (MESSAGING_IMPORT_RE.test(code)) kinds.add("messaging");
        if (kinds.size === 0) continue;
        candidates.push({ file, line, evidence: evidenceAt(code, line), kinds });
      } else {
        candidates.push(...(await this.expressCandidates(file, path, code, globalExpressLimiter, sources, read)));
      }
    }

    return candidates.map((c) => this.createFinding(c));
  }

  /** True when the file, or a local module it imports (one level), carries a rate limit signal. */
  private async importsSignal(
    code: string,
    path: string,
    sources: Source[],
    read: (file: string) => Promise<string>,
  ): Promise<boolean> {
    if (hasSignal(code)) return true;
    for (const m of code.matchAll(/(?:from\s*|require\s*\(\s*|import\s*\(\s*)["']((?:\.{1,2}\/|@\/|~\/)[^"']+)["']/g)) {
      const spec = m[1]!.replace(/^(?:\.{1,2}\/)+|^[@~]\//, "").replace(/\.(?:js|ts|mjs|cjs)$/, "");
      for (const s of sources) {
        if (s.path === path) continue;
        const bare = s.path.replace(/\.[a-z]+$/, "").replace(/\/index$/, "");
        if ((bare === spec || bare.endsWith(`/${spec}`)) && hasSignal(await read(s.file))) return true;
      }
    }
    return false;
  }

  private async expressCandidates(
    file: string,
    path: string,
    code: string,
    globalLimiter: boolean,
    sources: Source[],
    read: (file: string) => Promise<string>,
  ): Promise<Candidate[]> {
    if (!/\.(?:ts|js|mjs|cjs)$/.test(path)) return [];
    // `express` must be present so `api.get("/login")` on an HTTP client is not mistaken for a route.
    if (!/\bexpress\b/.test(code) && !/\b(?:app|router)\s*=\s*(?:Router|express)\s*\(/.test(code)) return [];
    const routeRe = /\b(?:app|router|server)\.(?:get|post|put|patch|delete|all)\s*\(\s*(["'`])([^"'`]*)\1/g;
    const routes = [...code.matchAll(routeRe)];
    if (routes.length === 0 || globalLimiter) return [];
    // A limiter imported from a shared module only counts when the file actually applies it.
    if (/\.use\s*\(/.test(code) && (await this.importsSignal(code, path, sources, read))) return [];

    const out: Candidate[] = [];
    for (let i = 0; i < routes.length; i++) {
      const m = routes[i]!;
      const start = m.index ?? 0;
      const segment = code.slice(start, routes[i + 1]?.index ?? code.length);
      const handlerAt = segment.search(/=>|\bfunction\b|\basync\b/);
      const args = segment.slice(m[0].length, handlerAt === -1 ? undefined : handlerAt);
      if (ARG_LIMITER_RE.test(args) || hasSignal(args)) continue;

      const kinds = new Set<Kind>();
      if (AUTH_PATH_RE.test(m[2]!)) kinds.add("auth");
      if (AI_IMPORT_RE.test(code) && AI_CALL_RE.test(segment)) kinds.add("ai");
      if (MESSAGING_IMPORT_RE.test(code) && MESSAGING_CALL_RE.test(segment)) kinds.add("messaging");
      if (kinds.size === 0) continue;
      const line = lineOfIndex(code, start);
      out.push({ file, line, evidence: evidenceAt(code, line), kinds });
    }
    return out;
  }

  private createFinding(c: Candidate): Finding {
    const kinds = [...c.kinds].sort((a, b) => KIND_RANK[a] - KIND_RANK[b]);
    const primary = kinds[0]!;
    // High for auth (credential brute force) and AI (direct per-request cost);
    // medium for email/SMS (abuse is real but typically bounded by provider quotas).
    const severity = primary === "messaging" ? "medium" : "high";
    const info = KIND_INFO[primary];
    return {
      id: createFindingId(CATEGORY_PREFIX.security_config, RULE_ID, c.file, c.line, c.evidence),
      ruleId: RULE_ID,
      title: `No rate limiting on ${info.label}`,
      severity,
      category: "security_config",
      deployBlocking: false,
      confidence: "medium",
      file: c.file,
      line: c.line,
      evidence: c.evidence,
      plainEnglishProblem: `This ${info.label} has no rate limiting, so a single client can call it as often as it likes.`,
      whyItMatters: info.why,
      fixSteps: [
        "Add a rate limiter such as `@upstash/ratelimit` (serverless) or `express-rate-limit` (Express).",
        "Key the limit on the user ID when signed in, otherwise on the client IP.",
        "Return HTTP 429 with a `Retry-After` header when the limit is exceeded.",
        "Use a tighter limit for login, OTP and password-reset than for general endpoints.",
      ],
      autoFixAvailable: false,
      aiFixPrompt: `This endpoint (${c.file}:${c.line}) is a ${info.label} with no rate limiting. Add rate limiting (e.g. @upstash/ratelimit for Next.js or express-rate-limit for Express), keyed by user ID or IP, returning 429 when exceeded.`,
    };
  }
}
