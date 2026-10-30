import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { makeFinding } from "./utils/finding.js";
import {
  classifyFile,
  isGenerated,
  isJsLike,
  isServerScope,
  isTestOrFixturePath,
} from "./utils/file-kind.js";
import { getJsSource, type JsSource } from "./utils/js-source.js";
import {
  extractExpressRoutes,
  isPublicRoutePath,
  usesExpress,
  verifiesSignature,
  type ExpressRoute,
} from "./utils/route-analyzer.js";
import { boundModuleNames, findCookieSites, isSessionCookieName } from "./utils/cookie-options.js";

const MAX_FILES = 2000;
const MAX_FINDINGS = 5;
const LEARN_MORE = "https://owasp.org/www-community/attacks/csrf";

const SESSION_END_PATH_RE = /(?:^|\/)(?:log-?out|sign-?out|session\/(?:destroy|end))\/?$/i;
const WEBHOOK_PATH_RE =
  /(?:^|\/)(?:web)?hooks?(?:\/|$)|webhook|callback|\/ipn\b|stripe|paypal|twilio|slack|github|sendgrid|mailgun|postmark|svix/i;
const HEADER_AUTH_RE =
  /\bauthorization\b|\bBearer\b|passport\s*\.\s*authenticate\s*\(\s*["'](?:jwt|bearer|headerapikey|basic|localapikey|oauth2-client-password)["']|\bsession\s*:\s*false\b|x-api-key/gi;

const PROTECTION_PACKAGES: readonly string[] = [
  "csurf",
  "@dr.pogodin/csurf",
  "csrf-csrf",
  "csrf-sync",
  "lusca",
  "tiny-csrf",
  "csrf",
  "@fastify/csrf-protection",
  "next-csrf",
  "@edge-csrf/core",
  "@edge-csrf/express",
  "@edge-csrf/nextjs",
];
const PROTECTION_IMPORT_RE = new RegExp(
  String.raw`(?:from\s*|require\s*\(\s*|import\s*\(\s*)["'](?:${PROTECTION_PACKAGES.map((p) =>
    p.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&"),
  ).join("|")})["']`,
  "g",
);
const PROTECTION_CODE_RE =
  /\b(?:csurf|doubleCsrf|csrfSync|csrfProtection|csrfToken|verifyCsrf\w*|validateCsrf\w*|checkCsrf\w*)\b|\blusca\s*\.\s*csrf\b/;
const ORIGIN_CHECK_RES = [
  /\b(?:req|request)\s*\.\s*(?:get|header)\s*\(\s*["'](?:origin|referer|referrer|sec-fetch-site|x-requested-with|x-csrf-token|x-xsrf-token|csrf-token)["']/gi,
  /\bheaders\s*(?:\.\s*(?:origin|referer)\b|\[\s*["'](?:origin|referer|referrer|sec-fetch-site|x-requested-with|x-csrf-token|x-xsrf-token|csrf-token)["']\s*\])/gi,
];
const URLENCODED_RE = /\b(?:express|bodyParser)\s*\.\s*urlencoded\s*\(/;
const FORM_MODULES: readonly string[] = [
  "multer",
  "express-fileupload",
  "busboy",
  "formidable",
  "body-parser",
];
const COOKIE_READ_RE =
  /\breq\s*\.\s*(?:signedCookies|cookies)\s*(?:\.\s*([A-Za-z_$][\w$]*)|\[\s*["'`]([^"'`\n]{1,64})["'`]\s*\])/g;
const PASSPORT_SESSION_RE = /\bpassport\s*\.\s*session\s*\(\s*\)/g;
const BODY_READ_RE = /\b(?:req|request)\s*\.\s*body\b|\bbody\s*[,}]/;
const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE", "ALL"]);

interface Site {
  file: string;
  src: JsSource;
  offset: number;
  kind: "session-middleware" | "passport-session" | "cookie-token";
}

interface KeptRoute {
  route: ExpressRoute;
  file: string;
}

/** True when a match of `re` over `raw` starts at code (not inside a comment or string) of `code`. */
function matchesInCode(re: RegExp, raw: string, code: string): boolean {
  re.lastIndex = 0;
  for (const m of raw.matchAll(re)) {
    const i = m.index ?? 0;
    if (code[i] === raw[i] && code[i] !== " ") return true;
  }
  return false;
}

/**
 * Express apps that authenticate with a cookie session (express-session, cookie-session,
 * passport sessions or a session-marked `res.cookie`) and accept state-changing requests
 * without any CSRF protection (a CSRF library, an Origin/Referer/custom-header check, or an
 * explicit `SameSite=Lax|Strict` session cookie). Express only: Next.js server actions and
 * route handlers are never inspected.
 */
export class CsrfDetector implements Detector {
  id = "csrf-detector";
  name = "CSRF Protection";
  category = "security_config" as const;
  description =
    "Detects Express apps that authenticate with cookies and accept state-changing requests without CSRF protection.";

  async detect(context: ScanContext): Promise<Finding[]> {
    try {
      return await this.analyze(context);
    } catch {
      return [];
    }
  }

  private async analyze(context: ScanContext): Promise<Finding[]> {
    const pc = context.projectContext;
    const deps: Record<string, string> = { ...pc.dependencies, ...pc.devDependencies };
    const dependsOnExpress = deps["express"] !== undefined;

    const files: Array<{ file: string; src: JsSource }> = [];
    for (const file of context.files) {
      if (files.length >= MAX_FILES) break;
      if (!isJsLike(file)) continue;
      if (context.config.includeTests !== true && isTestOrFixturePath(file)) continue;
      if (isGenerated(file)) continue;
      try {
        const src = await getJsSource(context, file);
        if (isGenerated(file, src.text)) continue;
        if (!isServerScope(classifyFile(file, src.text, pc))) continue;
        files.push({ file, src });
      } catch {
        // skip the file
      }
    }

    // Express files and their routes.
    const expressFiles = new Set<string>();
    const routesOf = new Map<string, ExpressRoute[]>();
    for (const { file, src } of files) {
      try {
        const routes =
          src.text.includes("(") && /\.\s*(?:get|post|put|patch|delete|all)\s*\(/.test(src.code)
            ? extractExpressRoutes(src.text)
            : [];
        routesOf.set(file, routes);
        if (usesExpress(src.text) || (dependsOnExpress && routes.length > 0)) {
          expressFiles.add(file);
        }
      } catch {
        // skip the file
      }
    }
    if (expressFiles.size === 0) return [];

    let protectedByLibrary = PROTECTION_PACKAGES.some((p) => deps[p] !== undefined);
    let sameSiteStrictOrLax = false;
    let sameSiteNone = false;
    let acceptsForms = false;
    const middleware: Site[] = [];
    let firstCookieToken: Site | undefined;

    for (const { file, src } of files) {
      try {
        const { text, code } = src;
        if (!protectedByLibrary) {
          protectedByLibrary =
            matchesInCode(PROTECTION_IMPORT_RE, text, code) ||
            PROTECTION_CODE_RE.test(code) ||
            ORIGIN_CHECK_RES.some((re) => matchesInCode(re, text, code));
        }
        if (!expressFiles.has(file)) continue;

        if (URLENCODED_RE.test(code)) acceptsForms = true;
        else if (/multer|fileupload|busboy|formidable|body-parser/.test(text)) {
          for (const n of boundModuleNames(src, FORM_MODULES)) {
            const esc = n.replace(/[$]/g, "\\$");
            if (new RegExp(String.raw`(?<![\w$.])${esc}\s*(?:\.\s*urlencoded\s*)?\(`).test(code)) {
              acceptsForms = true;
              break;
            }
          }
        }

        const sites = findCookieSites(src);
        for (const s of sites) {
          if (s.kind === "express-session" || s.kind === "cookie-session") {
            middleware.push({ file, src, offset: s.start, kind: "session-middleware" });
          } else if (
            firstCookieToken === undefined &&
            s.kind === "express" &&
            s.session &&
            !s.deletes
          ) {
            firstCookieToken = { file, src, offset: s.start, kind: "cookie-token" };
          }
          const sessionCfg =
            s.kind === "express-session" ||
            s.kind === "cookie-session" ||
            s.kind === "iron-session";
          const cookieCall = s.kind === "express" && s.session && !s.deletes;
          if (!sessionCfg && !cookieCall) continue;
          if (s.flags.sameSite === "lax" || s.flags.sameSite === "strict")
            sameSiteStrictOrLax = true;
          if (s.flags.sameSite === "none") sameSiteNone = true;
        }

        PASSPORT_SESSION_RE.lastIndex = 0;
        for (const m of code.matchAll(PASSPORT_SESSION_RE)) {
          middleware.push({ file, src, offset: m.index ?? 0, kind: "passport-session" });
        }
        if (firstCookieToken === undefined && code.includes("cookies")) {
          COOKIE_READ_RE.lastIndex = 0;
          for (const m of src.text.matchAll(COOKIE_READ_RE)) {
            const i = m.index ?? 0;
            if (code[i] !== text[i]) continue;
            const name = m[1] ?? m[2] ?? "";
            if (isSessionCookieName(name)) {
              firstCookieToken = { file, src, offset: i, kind: "cookie-token" };
              break;
            }
          }
        }
      } catch {
        // skip the file
      }
    }

    const evidence =
      middleware.length > 0 ? middleware : firstCookieToken ? [firstCookieToken] : [];
    if (evidence.length === 0 || protectedByLibrary || sameSiteStrictOrLax) return [];

    // Mutating routes.
    const kept: KeptRoute[] = [];
    for (const { file } of files) {
      if (!expressFiles.has(file)) continue;
      for (const route of routesOf.get(file) ?? []) {
        if (!MUTATING.has(route.method)) continue;
        if (isPublicRoutePath(route.path) || SESSION_END_PATH_RE.test(route.path)) continue;
        if (WEBHOOK_PATH_RE.test(route.path)) continue;
        if (verifiesSignature(route.chainCode)) continue;
        if (matchesInCode(HEADER_AUTH_RE, route.handlerChain, route.chainCode)) continue;
        kept.push({ route, file });
      }
    }
    if (kept.length === 0) return [];

    if (!acceptsForms) {
      acceptsForms = kept.some(({ route }) => {
        if (route.method === "DELETE") return true;
        const inline = /=>|\bfunction\b/.test(route.chainCode);
        return inline && !BODY_READ_RE.test(route.chainCode);
      });
    }

    const mediumConfidence = sameSiteNone || acceptsForms;
    const out: Finding[] = [];
    for (const site of evidence.slice(0, MAX_FINDINGS)) {
      const line = site.src.lineAt(site.offset);
      out.push(this.build(site, line, kept, mediumConfidence));
    }
    return out;
  }

  private build(site: Site, line: number, kept: KeptRoute[], medium: boolean): Finding {
    const named = kept
      .slice(0, 3)
      .map(({ route, file }) => `${route.method} ${route.path} (${file}:${route.line})`)
      .join(", ");
    const jsonOnly = medium
      ? ""
      : " Routes that only accept JSON are harder to hit, but bodiless POST/DELETE routes and any urlencoded form route are exposed.";
    return makeFinding({
      category: "security_config",
      ruleId: "security_config/csrf-cookie-session-unprotected",
      title: "Cookie-session app has no CSRF protection",
      severity: "medium",
      confidence: medium ? "medium" : "low",
      file: site.file,
      line,
      evidence: site.src.lineText(line).trim(),
      discriminator: "csrf",
      plainEnglishProblem: `This Express app signs users in with a cookie session, and ${kept.length} state-changing route${kept.length === 1 ? "" : "s"} (e.g. ${named}) accept requests without a CSRF token or an Origin check. Browsers attach the cookie when another site submits a form to these routes.${jsonOnly}`,
      whyItMatters:
        "An attacker's page can make a logged-in visitor change their email, transfer funds or delete data without noticing. Browsers' Lax-by-default cookies reduce this but are not applied everywhere (older browsers, Safari/Firefox defaults, top-level POST within two minutes in Chrome).",
      fixSteps: [
        'Set the session cookie `sameSite: "lax"` (or `"strict"`) explicitly.',
        "Add `csrf-csrf` (double-submit token) or `csrf-sync` to every state-changing route except signed webhooks, or reject requests whose `Origin` header is not your site.",
        "Send the token from the frontend in a header. Do not add `csurf` (deprecated).",
      ],
      aiFixPrompt:
        "My Express app uses cookie sessions and has POST/PUT/PATCH/DELETE routes without CSRF protection. Set the session cookie to `sameSite: 'lax'`, `httpOnly`, `secure` in production, add `csrf-csrf` double-submit protection (or an Origin/Referer allowlist middleware) to every state-changing route except signed webhooks, send the token from the frontend in a header, and show the tests that a cross-site POST without the token is rejected.",
      learnMoreUrl: LEARN_MORE,
    });
  }
}
