import { posix } from "node:path";
import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { CATEGORY_PREFIX, createFindingId } from "@talaljaber/vibesafe-shared";
import { sanitizeEvidence } from "./utils/sanitize-evidence.js";
import {
  findAnyHandlerLine,
  isApiRoute,
  lineOfIndex,
  matcherCoversApi,
} from "./utils/route-analyzer.js";

const RULE_ID = "security_config/missing-rate-limit";
const SOURCE_RE = /\.(?:ts|js|mjs|cjs|tsx|jsx)$/;
const TEST_RE = /(?:\.(?:test|spec)\.[a-z]+$|(?:^|\/)(?:__tests__|tests?)\/)/;
// Not shared with route-analyzer: that regex is root-only and widening it would change other detectors.
const MIDDLEWARE_RE = /^(.*?\/)?(?:src\/)?middleware\.(?:ts|js)$/;

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
  // an import/require specifier naming a rate limit module (not any quoted string)
  /(?:from\s*|require\s*\(\s*|import\s*\(\s*)["'][^"'\n]*rate-?limit[^"'\n]*["']/i,
  /\brateLimit\s*\(/,
  /\bslowDown\s*\(/,
  /\blimiter\.(?:limit|check|consume|take|attempt|isAllowed)\s*\(/,
  /\bnew\s+Ratelimit\s*\(/,
  /\bnew\s+RateLimiter\w*\s*\(/,
];

// Limiter-shaped names only: a bare `limit` is the body-parser size option, not a rate limiter.
const ARG_LIMITER_RE = /\b(?:rate-?limit\w*|\w*ratelimit\w*|\w*limiter\w*|slowDown|throttle\w*)\b/i;

/** Drops object-literal contents so an option like `{ limiter: x }` is not mistaken for middleware. */
function withoutObjects(text: string): string {
  let prev: string;
  let cur = text;
  do {
    prev = cur;
    cur = cur.replace(/\{[^{}]*\}/g, "");
  } while (cur !== prev);
  return cur;
}

function argHasLimiter(text: string): boolean {
  return ARG_LIMITER_RE.test(withoutObjects(text));
}

const AUTH_PATH_RE =
  /(?:^|[/\\._-])(?:log-?in|sign-?in|sign-?up|register|passwords?|forgot|reset|otp|verify|verification|2fa|mfa|magic-?link)(?:[/\\._-]|$)/i;

const AI_IMPORT_RE =
  /(?:from\s*|require\s*\(\s*|import\s*\(\s*)["'](?:openai|@anthropic-ai\/sdk|ai|@ai-sdk\/[\w-]+)["']/;
const MESSAGING_IMPORT_RE =
  /(?:from\s*|require\s*\(\s*|import\s*\(\s*)["'](?:resend|nodemailer|twilio)["']/;

const AI_CALL_RE =
  /\b(?:openai|anthropic|OpenAI|Anthropic)\b|\b(?:generateText|streamText|generateObject|streamObject)\s*\(|chat\.completions|messages\.create/;
const MESSAGING_CALL_RE = /\.sendMail\s*\(|\b[rR]esend\b|\btwilio\b|\.emails\.send\s*\(/;

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
  return code
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "))
    .replace(/(^|[^:\\"'`])\/\/.*$/gm, "$1");
}

function hasSignal(code: string): boolean {
  return RATE_LIMIT_SIGNALS.some((re) => re.test(code));
}

function evidenceAt(code: string, line: number): string {
  return sanitizeEvidence(code.split("\n")[line - 1] ?? "");
}

interface UseCall {
  pathArgs: string[] | undefined;
  limiter: boolean;
}

type ReadFn = (file: string) => Promise<string>;

/** Inner text of the balanced parentheses opening at `open` (index of "("). */
function balanced(code: string, open: number): string {
  let depth = 0;
  for (let i = open; i < code.length; i++) {
    const ch = code[i];
    if (ch === "(") depth++;
    else if (ch === ")" && --depth === 0) return code.slice(open + 1, i);
  }
  return code.slice(open + 1);
}

/** Splits `use()` arguments into optional path literal(s) and the remaining middleware text. */
function splitUseArgs(args: string): { pathArgs: string[] | undefined; rest: string } {
  const m = /^\s*(?:(["'`])([^"'`]*)\1|\[([^\]]*)\])\s*(?:,|$)/.exec(args);
  if (!m) return { pathArgs: undefined, rest: args };
  const pathArgs =
    m[2] !== undefined
      ? [m[2]]
      : [...(m[3] ?? "").matchAll(/["'`]([^"'`]*)["'`]/g)].map((x) => x[1]!);
  return { pathArgs, rest: args.slice(m[0].length) };
}

function pathPrefixes(prefix: string, routePath: string): boolean {
  if (prefix === "" || prefix === "/") return true;
  const p = prefix.endsWith("/") ? prefix : `${prefix}/`;
  return routePath === prefix || routePath.startsWith(p);
}

/** `import x from "m"` / `const x = require("m")` bindings: the bound names text and the specifier. */
function importBindings(code: string): { names: string; spec: string }[] {
  const out: { names: string; spec: string }[] = [];
  const re =
    /(?:\bimport\s+([^"';]*?)\s*from\s*|\b(?:const|let|var)\s+([^=;]*?)=\s*require\s*\(\s*)["']([^"']+)["']/g;
  for (const m of code.matchAll(re)) out.push({ names: m[1] ?? m[2] ?? "", spec: m[3]! });
  return out;
}

/** Project sources that a local specifier (relative, `@/` or `~/`) may refer to. */
function resolveSpec(spec: string, path: string, sources: Source[]): Source[] {
  if (!/^(?:\.{1,2}\/|@\/|~\/)/.test(spec)) return [];
  const strip = (p: string) => p.replace(/\.(?:js|ts|mjs|cjs|tsx|jsx)$/, "");
  if (spec.startsWith(".")) {
    const target = strip(posix.join(posix.dirname(path), spec));
    return sources.filter((s) => {
      if (s.path === path) return false;
      const bare = s.path.replace(/\.[a-z]+$/, "");
      return bare === target || bare.replace(/\/index$/, "") === target;
    });
  }
  const bareSpec = strip(spec.replace(/^[@~]\//, ""));
  return sources.filter((s) => {
    if (s.path === path) return false;
    const bare = s.path.replace(/\.[a-z]+$/, "").replace(/\/index$/, "");
    return bare === bareSpec || bare.endsWith(`/${bareSpec}`);
  });
}

/** Local modules a file imports. */
function resolveSpecs(code: string, path: string, sources: Source[]): Source[] {
  const out: Source[] = [];
  for (const m of code.matchAll(/(?:from\s*|require\s*\(\s*|import\s*\(\s*)["']([^"'\n]+)["']/g))
    out.push(...resolveSpec(m[1]!, path, sources));
  return out;
}

function stripImports(code: string): string {
  return code
    .replace(/\bimport\s+[^"';]*?from\s*["'][^"']*["']/g, "")
    .replace(/^.*\brequire\s*\(.*$/gm, "");
}

/**
 * Flags sensitive endpoints (auth, AI/LLM, email/SMS sending) in Next.js route
 * handlers and Express routes that have no rate limiting signal.
 *
 * A signal counts when found in: the route file itself; a local module the file
 * imports (one level); a `middleware.ts` that uses a limiter and runs on `/api`
 * (scoped to the app directory it lives in); or, for Express, a limiter passed as
 * route middleware, or `use(limiter)` with no path (or a covering path) in the
 * same file or in a file that imports the route file.
 *
 * Limits: a path-scoped limiter (`app.use("/api", limiter)`) only covers routes in the
 * file that declares it, not routers mounted from it; limits enforced outside the code (CDN/WAF/gateway) are invisible to a
 * static scan; Next.js server actions, NextAuth handlers, Hono/Fastify/Koa and
 * chained `router.route(p).post().get()` after the first method are not scanned;
 * a local module that mentions a limiter counts even if it never applies it.
 */
export class RateLimitDetector implements Detector {
  id = "rate-limit-detector";
  name = "Missing Rate Limiting";
  category = "security_config" as const;
  description =
    "Detects sensitive endpoints (auth, AI/LLM, email/SMS) in Next.js route handlers and Express with no rate limiting. Does not see CDN/WAF limits, Next.js server actions, NextAuth, or Hono/Fastify/Koa.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const sources: Source[] = context.files
      .map((f) => ({ file: f, path: f.replace(/\\/g, "/") }))
      .filter(({ path }) => SOURCE_RE.test(path) && !TEST_RE.test(path));

    const cache = new Map<string, string>();
    const read: ReadFn = async (file) => {
      let c = cache.get(file);
      if (c === undefined) {
        c = stripComments(await context.readFile(file));
        cache.set(file, c);
      }
      return c;
    };

    // Project-wide signals.
    const middlewareRoots: string[] = [];
    const globallyLimited = new Set<string>(); // files covered by a path-less limiter `use()`
    const uses = new Map<string, UseCall[]>();
    for (const { file, path } of sources) {
      const code = await read(file);
      const mw = MIDDLEWARE_RE.exec(path);
      if (mw && hasSignal(code) && matcherCoversApi(code)) middlewareRoots.push(mw[1] ?? "");
      if (isApiRoute(path)) continue;
      const calls = await this.useCalls(code, path, sources, read);
      uses.set(file, calls);
      if (
        calls.some(
          (u) => u.limiter && (!u.pathArgs || u.pathArgs.some((p) => p === "/" || p === "")),
        )
      ) {
        globallyLimited.add(file);
        for (const m of resolveSpecs(code, path, sources)) globallyLimited.add(m.file);
      }
    }

    const candidates: Candidate[] = [];
    for (const { file, path } of sources) {
      const code = await read(file);
      if (isApiRoute(path)) {
        if (middlewareRoots.some((r) => path.startsWith(r))) continue;
        if (/webhook/i.test(path)) continue;
        if (await this.importsSignal(code, path, sources, read)) continue;
        const line = findAnyHandlerLine(code);
        if (line === undefined) continue;
        const body = stripImports(code);
        const kinds = new Set<Kind>();
        if (AUTH_PATH_RE.test(path)) kinds.add("auth");
        if (AI_IMPORT_RE.test(code) && AI_CALL_RE.test(body)) kinds.add("ai");
        if (MESSAGING_IMPORT_RE.test(code) && MESSAGING_CALL_RE.test(body)) kinds.add("messaging");
        if (kinds.size === 0) continue;
        candidates.push({ file, line, evidence: evidenceAt(code, line), kinds });
      } else {
        candidates.push(
          ...this.expressCandidates(
            file,
            path,
            code,
            globallyLimited.has(file),
            uses.get(file) ?? [],
          ),
        );
      }
    }

    return candidates.map((c) => this.createFinding(c));
  }

  /** True when the file, or a local module it imports (one level), carries a rate limit signal. */
  private async importsSignal(
    code: string,
    path: string,
    sources: Source[],
    read: ReadFn,
  ): Promise<boolean> {
    if (hasSignal(code)) return true;
    for (const s of resolveSpecs(code, path, sources))
      if (hasSignal(await read(s.file))) return true;
    return false;
  }

  /** The `app|router|server.use(...)` calls in a file, with whether each applies a limiter. */
  private async useCalls(
    code: string,
    path: string,
    sources: Source[],
    read: ReadFn,
  ): Promise<UseCall[]> {
    const out: UseCall[] = [];
    const bindings = importBindings(code);
    for (const m of code.matchAll(/\b(?:app|router|server)\.use\s*\(/g)) {
      const { pathArgs, rest } = splitUseArgs(balanced(code, (m.index ?? 0) + m[0].length - 1));
      let limiter = argHasLimiter(rest) || hasSignal(rest);
      // A limiter with an arbitrary name imported from a module that builds it.
      for (const id of limiter ? [] : (rest.match(/[A-Za-z_$][\w$]*/g) ?? [])) {
        const idRe = new RegExp(`\\b${id.replace(/\$/g, "\\$")}\\b`);
        for (const b of bindings) {
          if (!idRe.test(b.names)) continue;
          for (const s of resolveSpec(b.spec, path, sources))
            if (hasSignal(await read(s.file))) limiter = true;
        }
      }
      out.push({ pathArgs, limiter });
    }
    return out;
  }

  private expressCandidates(
    file: string,
    path: string,
    code: string,
    globalLimiter: boolean,
    uses: UseCall[],
  ): Candidate[] {
    if (!/\.(?:ts|js|mjs|cjs)$/.test(path)) return [];
    // `express` must be present so `api.get("/login")` on an HTTP client is not mistaken for a route.
    if (!/\bexpress\b/.test(code) && !/\b(?:app|router)\s*=\s*(?:Router|express)\s*\(/.test(code))
      return [];
    const routes: { index: number; len: number; path: string; method: string }[] = [];
    const methods = "get|post|put|patch|delete|all";
    const direct = new RegExp(
      `\\b(?:app|router|server)\\.(${methods})\\s*\\(\\s*(["'\`])([^"'\`]*)\\2`,
      "g",
    );
    for (const m of code.matchAll(direct))
      routes.push({ index: m.index ?? 0, len: m[0].length, path: m[3]!, method: m[1]! });
    const chained = new RegExp(
      `\\b(?:app|router|server)\\.route\\s*\\(\\s*(["'\`])([^"'\`]*)\\1\\s*\\)\\s*\\.(${methods})\\s*\\(`,
      "g",
    );
    for (const m of code.matchAll(chained))
      routes.push({ index: m.index ?? 0, len: m[0].length, path: m[2]!, method: m[3]! });
    routes.sort((a, b) => a.index - b.index);
    if (routes.length === 0 || globalLimiter) return [];

    const out: Candidate[] = [];
    for (let i = 0; i < routes.length; i++) {
      const r = routes[i]!;
      if (uses.some((u) => u.limiter && u.pathArgs?.some((p) => pathPrefixes(p, r.path)))) continue;
      const segment = code.slice(r.index, routes[i + 1]?.index ?? code.length);
      const handlerAt = segment.search(/=>|\bfunction\b|\basync\b/);
      const args = segment.slice(r.len, handlerAt === -1 ? undefined : handlerAt);
      if (argHasLimiter(args) || hasSignal(args)) continue;

      const kinds = new Set<Kind>();
      // A GET on /login just renders a page; brute force needs a state-changing method.
      if (r.method !== "get" && AUTH_PATH_RE.test(r.path)) kinds.add("auth");
      if (AI_IMPORT_RE.test(code) && AI_CALL_RE.test(segment)) kinds.add("ai");
      if (MESSAGING_IMPORT_RE.test(code) && MESSAGING_CALL_RE.test(segment)) kinds.add("messaging");
      if (kinds.size === 0) continue;
      const line = lineOfIndex(code, r.index);
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
        "If you already limit requests at a CDN, WAF or API gateway, this scan cannot see it; confirm it covers this route.",
        "Use a tighter limit for login, OTP and password-reset than for general endpoints.",
      ],
      autoFixAvailable: false,
      aiFixPrompt: `This endpoint (${c.file}:${c.line}) is a ${info.label} with no rate limiting. Add rate limiting (e.g. @upstash/ratelimit for Next.js or express-rate-limit for Express), keyed by user ID or IP, returning 429 when exceeded.`,
    };
  }
}
