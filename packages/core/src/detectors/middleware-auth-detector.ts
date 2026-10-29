// ─────────────────────────────────────────────────────────────────────────────
// Middleware Auth Detector
//
// Next.js middleware that (a) treats the mere presence of a session cookie as
// "logged in" without verifying it, or (b) has a matcher that skips protected
// route groups that exist in the app (e.g. app/admin).
// ─────────────────────────────────────────────────────────────────────────────

import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { makeFinding } from "./utils/finding.js";
import { classifyPath, isJsLike } from "./utils/file-kind.js";
import { getJsSource, type JsSource } from "./utils/js-source.js";
import { hasUseClientDirective } from "./utils/file-classifier.js";
import { AUTH_CHECK_PATTERNS, MIDDLEWARE_AUTH_PATTERNS } from "./patterns/auth-patterns.js";

/** Cookie reads in masked code: `req.cookies.get(`, `.has(`, `.getAll()`, `cookies().get(`. */
const COOKIE_ACCESS_RE = /\bcookies\s*(?:\(\s*\))?\s*\.\s*(?:get|has|getAll)\s*\(/g;
/** Cookie names that carry a login session. Matched on raw text near the access. */
const AUTH_COOKIE_NAME_RE =
  /["'`](?:sb-[^"'`]*|[^"'`]*(?:session|auth|token|jwt|sid|logged)[^"'`]*)["'`]/gi;
/** Calls that actually verify a session or token. Matched on masked code. */
const VERIFY_RE =
  /\b(?:jwtVerify|verify\w*|getToken|getUser|getClaims|getSession|getServerSession|updateSession|unsealData|getIronSession|decrypt\w*|unseal\w*|clerkMiddleware|authMiddleware|withAuth|NextAuth|auth|createServerClient|createMiddlewareClient|fetch)\s*\(|\bjwt\s*\.\s*verify\s*\(/;
/** The middleware gates access: redirects to a login page or answers 401. */
const GATE_RE = /\b(?:redirect|rewrite)\s*\(|\b401\b|NextResponse\s*\.\s*json\s*\(/;
const MATCHER_RE = /\bmatcher\s*:\s*(\[[^\]]*\]|"[^"\n]*"|'[^'\n]*'|`[^`\n]*`)/;
/** Top-level route segments that usually need a signed-in (and for some, privileged) user. */
const PROTECTED_SEGMENTS = [
  "admin",
  "internal",
  "staff",
  "backoffice",
  "console",
  "dashboard",
  "settings",
  "account",
  "billing",
] as const;
const PRIVILEGED_SEGMENT_RE = /^(?:admin|internal|staff|backoffice|console)$/;
const PAGE_FILE_RE =
  /^(?:src\/)?app\/(?:\([^/]+\)\/)*([^/()@[\]]+)\/(?:.+\/)?(?:page|layout|route)\.[cm]?[jt]sx?$/;
const PAGE_EXTS = ["tsx", "jsx", "ts", "js"];

/** Matcher prefixes, or undefined when the matcher cannot be read without guessing. */
function matcherPrefixes(raw: string): string[] | undefined {
  const entries = [...raw.matchAll(/["'`]([^"'`]*)["'`]/g)].map((m) => m[1]!);
  if (entries.length === 0) return undefined;
  const out: string[] = [];
  for (const e of entries) {
    if (e.includes("(") || e.includes("$") || !e.startsWith("/")) return undefined;
    const cut = e.search(/[:*]/);
    const prefix = (cut === -1 ? e : e.slice(0, cut)).replace(/\/+$/, "");
    out.push(prefix);
  }
  return out;
}

function covers(prefix: string, segment: string): boolean {
  return prefix === "" || prefix === `/${segment}` || `/${segment}`.startsWith(`${prefix}/`);
}

export class MiddlewareAuthDetector implements Detector {
  id = "middleware-auth-detector";
  name = "Middleware Auth Detection";
  category = "auth" as const;
  description =
    "Detects Next.js middleware that trusts the presence of a session cookie without verifying it, or whose matcher skips protected route groups.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of context.files) {
      try {
        if (!isJsLike(file) || classifyPath(file) !== "next-middleware") continue;
        const text = await context.readFile(file);
        if (!text) continue;
        const src = await getJsSource(context, file);
        const cookie = this.cookiePresence(src, file);
        if (cookie) findings.push(cookie);
        findings.push(...(await this.matcherGap(src, file, context, cookie !== undefined)));
      } catch {
        // detectors never throw
      }
    }
    return findings;
  }

  private cookiePresence(src: JsSource, file: string): Finding | undefined {
    if (!src.code.includes("cookies") || VERIFY_RE.test(src.code)) return undefined;
    if (!GATE_RE.test(src.code)) return undefined;
    COOKIE_ACCESS_RE.lastIndex = 0;
    for (let m = COOKIE_ACCESS_RE.exec(src.code); m; m = COOKIE_ACCESS_RE.exec(src.code)) {
      const near = src.text.slice(m.index, Math.min(src.text.length, m.index + 240));
      // the cookie name must be a string literal in code, not text in a comment
      const named = [...near.matchAll(AUTH_COOKIE_NAME_RE)].some(
        (n) => src.code[m!.index + (n.index ?? 0)] === n[0][0],
      );
      if (!named) continue;
      const line = src.lineAt(m.index);
      return makeFinding({
        category: "auth",
        ruleId: "auth/middleware-cookie-presence-only",
        title: "Middleware trusts a session cookie without verifying it",
        severity: "medium",
        confidence: "medium",
        file,
        line,
        evidence: src.lineText(line),
        plainEnglishProblem:
          "The middleware decides a visitor is logged in because a cookie with a session-like name exists. It never verifies the token's signature, expiry or session.",
        whyItMatters:
          "Anyone can set a cookie with that name to any value in their browser (for example `sb-x-auth-token=1`) and walk past the gate. Every page that relies only on this middleware is then reachable without logging in.",
        fixSteps: [
          "Verify the session in middleware: for Supabase create a server client with `@supabase/ssr` and call `supabase.auth.getUser()`; for JWTs use `jwtVerify` from `jose` with your secret.",
          "Redirect to the login page when verification fails, not just when the cookie is missing.",
          "Keep server-side session checks in pages and API routes; middleware is only a first gate.",
        ],
        aiFixPrompt:
          "This Next.js middleware treats the presence of a session cookie as proof of login without verifying it. Replace the cookie-presence check with real verification: create a Supabase server client in middleware and call supabase.auth.getUser() (or verify the JWT with jose's jwtVerify), and redirect to /login when verification fails. Keep server-side session checks in protected pages and API routes as well.",
      });
    }
    return undefined;
  }

  private async matcherGap(
    src: JsSource,
    file: string,
    context: ScanContext,
    cookieGate: boolean,
  ): Promise<Finding[]> {
    const m = MATCHER_RE.exec(src.text);
    if (!m || m.index === undefined) return [];
    // the matcher must sit in code (not a comment)
    if (src.code[m.index] !== src.text[m.index]) return [];
    const isGate =
      cookieGate ||
      MIDDLEWARE_AUTH_PATTERNS.some((re) => re.test(src.code)) ||
      (/\bredirect\s*\(/.test(src.code) && /login|sign-?in|auth/i.test(src.text));
    if (!isGate) return [];
    const prefixes = matcherPrefixes(m[1]!);
    if (prefixes === undefined) return [];
    const root = file.replace(/\\/g, "/").startsWith("src/") ? "src/" : "";
    const segments = await this.existingSegments(context, root);
    const out: Finding[] = [];
    const line = src.lineAt(m.index);
    for (const segment of PROTECTED_SEGMENTS) {
      if (!segments.has(segment)) continue;
      if (prefixes.some((p) => covers(p, segment))) continue;
      if (await this.segmentGuardsItself(context, root, segment)) continue;
      const privileged = PRIVILEGED_SEGMENT_RE.test(segment);
      out.push(
        makeFinding({
          category: "auth",
          ruleId: "auth/middleware-matcher-gap",
          title: "Middleware matcher skips a protected section",
          severity: privileged ? "high" : "medium",
          confidence: "medium",
          file,
          line,
          evidence: src.lineText(line),
          discriminator: segment,
          plainEnglishProblem: `The auth middleware only runs on the paths in its \`matcher\`, and none of them covers /${segment}, which exists in this app. Requests to /${segment} never pass through the login check.`,
          whyItMatters:
            "Signed-out visitors can open those pages directly. If the pages are client components that only hide content in the browser, their data and actions are exposed.",
          fixSteps: [
            `Add "/${segment}/:path*" (and "/${segment}") to the middleware matcher.`,
            "Also check the session on the server in that section's layout or page (and in its API routes), so a matcher mistake cannot expose it again.",
          ],
          aiFixPrompt:
            "The Next.js middleware matcher does not include a protected section of the app, so the login check never runs there. Add that section's path pattern (for example \"/admin/:path*\") to config.matcher, and add a server-side session check (and role check for admin areas) in that section's layout or page so it stays protected even if the matcher changes.",
        }),
      );
    }
    return out;
  }

  /** Top-level app route segments seen in `context.files`, plus probed protected ones. */
  private async existingSegments(context: ScanContext, root: string): Promise<Set<string>> {
    const segments = new Set<string>();
    for (const f of context.files) {
      const m = PAGE_FILE_RE.exec(f.replace(/\\/g, "/"));
      if (m) segments.add(m[1]!);
    }
    for (const segment of PROTECTED_SEGMENTS) {
      if (segments.has(segment)) continue;
      for (const ext of PAGE_EXTS) {
        if ((await context.readFile(`${root}app/${segment}/page.${ext}`)) !== "") {
          segments.add(segment);
          break;
        }
      }
    }
    return segments;
  }

  /** The section's own layout/page is a server component that checks the session. */
  private async segmentGuardsItself(
    context: ScanContext,
    root: string,
    segment: string,
  ): Promise<boolean> {
    for (const name of ["layout", "page"]) {
      for (const ext of PAGE_EXTS) {
        const text = await context.readFile(`${root}app/${segment}/${name}.${ext}`);
        if (!text || hasUseClientDirective(text)) continue;
        if (AUTH_CHECK_PATTERNS.some((re) => re.test(text))) return true;
      }
    }
    return false;
  }
}
