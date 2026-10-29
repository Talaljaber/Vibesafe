import { type Detector, type Finding, type ScanContext } from "@talaljaber/vibesafe-shared";
import { CATEGORY_PREFIX, createFindingId } from "@talaljaber/vibesafe-shared";
import {
  isApiRoute,
  findHandlerLine,
  findAnyHandlerLine,
  hasAuthCheck,
  isRiskyRoutePattern,
  middlewareProtectsApi,
  isExpressCandidateFile,
  isExpressMutatingMethod,
  usesExpress,
  extractExpressRoutes,
  chainHasExpressAuth,
  displayRoutePath,
  type ExpressRoute,
  isCoveredByExpressUse,
  nextRoutePath,
  isPublicRoutePath,
  isPublicByDesignCode,
  verifiesSignature,
  localAuthHelpers,
  spanAuthenticates,
  hasSecretComparison,
} from "./utils/route-analyzer.js";
import { RISKY_HTTP_METHODS, EXPRESS_PUBLIC_ROUTE_RE } from "./patterns/auth-patterns.js";
import { isStripeWebhookRoute, isStripeWebhookExpressRoute } from "./stripe-webhook-detector.js";
import { classifyFile } from "./utils/file-kind.js";
import { createJsSource, getJsSource, type JsSource } from "./utils/js-source.js";
import { extractFunctions, handlerSpans, type FunctionSpan } from "./utils/js-functions.js";
import { analyzeTaint } from "./utils/taint.js";
import {
  columnName,
  extractQueryChains,
  isOwnerColumn,
  requestValue,
} from "./utils/query-chains.js";

const MUTATING_METHODS = new Set(RISKY_HTTP_METHODS);
/**
 * Calls whose names suggest an auth helper this detector does not know (`getUserOrThrow()`,
 * `assertSession()`): in per-handler mode such a handler is assumed authenticated.
 */
const AUTH_LIKE_CALL_RE =
  /\b\w*(?:auth|Auth|session|Session|login|Login|token|Token|guard|Guard|protect|Protect|permission|Permission|currentUser|CurrentUser)\w*\s*\(/;
const PUBLIC_FLAG_COLUMN_RE = /^(?:is_?published|published|is_?public|public|visibility|slug)$/i;

/**
 * True when `span` selects rows through a service-role/direct client filtered on a
 * tenant/user column whose value comes from the request (`.eq("org_id", searchParams.get("orgId"))`).
 */
function tenantReadFromRequest(src: JsSource, span: FunctionSpan): boolean {
  const chains = extractQueryChains(src, span.bodyStart, span.bodyEnd).filter(
    (c) =>
      c.verb === "select" &&
      (c.client === "service-role" || c.client === "direct") &&
      !c.opaqueFilter &&
      !c.filters.some((f) => PUBLIC_FLAG_COLUMN_RE.test(columnName(f.column))),
  );
  if (chains.length === 0) return false;
  const state = analyzeTaint(src, span, { runtime: "server" });
  return chains.some((c) =>
    c.filters.some(
      (f) => isOwnerColumn(f.column) && requestValue(state, src, f.value) !== undefined,
    ),
  );
}

/**
 * `app.all("*", ...)` / `app.all("/*", ...)` catch-alls (CORS headers, 404 handlers,
 * logging) are not data-modifying endpoints: skip them when the path is a bare wildcard
 * or the handler only passes control on (`next()`) or answers 404.
 */
function isNonMutatingCatchAll(route: ExpressRoute): boolean {
  if (route.method !== "ALL") return false;
  if (/^\/?\*$/.test(route.path)) return true;
  return (
    /\bnext\s*\(/.test(route.chainCode) ||
    /\b(?:status|sendStatus)\s*\(\s*404\s*\)/.test(route.chainCode)
  );
}

export class MissingAuthDetector implements Detector {
  id = "missing-auth-detector";
  name = "Missing Auth Detection";
  category = "auth" as const;
  description = "Detects API routes that perform risky operations without checking authentication.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const protectedByMiddleware = await middlewareProtectsApi(context.files, (f) =>
      context.readFile(f),
    );

    for (const filePath of context.files) {
      if (isExpressCandidateFile(filePath) && !isApiRoute(filePath)) {
        findings.push(...(await this.detectExpress(filePath, context)));
        continue;
      }
      if (!isApiRoute(filePath)) {
        continue;
      }

      const content = await context.readFile(filePath);

      // Webhook routes authenticate via signature verification, handled by StripeWebhookDetector
      if (isStripeWebhookRoute(filePath, content)) {
        continue;
      }
      // Sign-in, sign-up, password reset, OAuth callbacks and health probes are public by design.
      const routePath = nextRoutePath(filePath);
      if (routePath !== undefined && isPublicRoutePath(routePath)) continue;
      if (protectedByMiddleware) continue;

      const handlers = await this.handlers(filePath, content, context);
      const riskyLine = findHandlerLine(content, RISKY_HTTP_METHODS);
      const isMutatingRoute = riskyLine !== undefined;
      const isSensitivePath = isRiskyRoutePattern(filePath);

      // Severity: sensitive path + mutating method -> critical (deploy blocking);
      // sensitive path with only read handlers, or a mutating non-sensitive route -> high.
      const critical = isSensitivePath && isMutatingRoute;

      let line: number | undefined;
      if ((isMutatingRoute || isSensitivePath) && !hasAuthCheck(content)) {
        line = riskyLine ?? findAnyHandlerLine(content) ?? 1;
        // Per handler: public-by-design handlers (signed webhooks, checkout session creation,
        // OAuth code exchange), auth wrappers and request-secret checks are not gaps.
        const relevant = handlers.spans.filter((s) =>
          isMutatingRoute
            ? MUTATING_METHODS.has(s.httpMethod ?? "") || s.role === "pages-api-handler"
            : true,
        );
        const gaps = relevant.filter((s) => !handlers.covered(s));
        if (relevant.length > 0 && gaps.length === 0) line = undefined;
        else if (gaps.length > 0 && gaps.length < relevant.length) line = gaps[0]!.startLine;
      } else if (isMutatingRoute && hasAuthCheck(content)) {
        // One handler's auth check must not hide another handler's gap.
        const gap = handlers.spans.find(
          (s) =>
            s.role === "app-route-handler" &&
            MUTATING_METHODS.has(s.httpMethod ?? "") &&
            !s.truncated &&
            !handlers.covered(s) &&
            !AUTH_LIKE_CALL_RE.test(handlers.src.code.slice(s.bodyStart, s.bodyEnd)),
        );
        if (gap !== undefined) line = gap.startLine;
      }

      if (line !== undefined) {
        findings.push({
          id: createFindingId(CATEGORY_PREFIX.auth, "auth/missing-route-auth", filePath, line),
          ruleId: "auth/missing-route-auth",
          title: "Missing authentication in API Route",
          severity: critical ? "critical" : "high",
          category: "auth",
          deployBlocking: critical,
          confidence: "medium",
          file: filePath,
          line,
          plainEnglishProblem:
            "This API route appears to modify data or access sensitive info, but we couldn't find any code verifying who the user is.",
          whyItMatters:
            "Without an auth check, anyone on the internet can call this API directly and modify your database or view private data.",
          fixSteps: [
            "Import your authentication library's server-side session checker.",
            "Call the session checker at the very beginning of the route handler.",
            "If the session is null, immediately `return new Response('Unauthorized', { status: 401 })`.",
          ],
          autoFixAvailable: false,
          aiFixPrompt: `I need to secure this Next.js API route. Please add an authentication check at the beginning of the handler so that unauthenticated users receive a 401 response.`,
        });
        continue;
      }

      // Unauthenticated GET handlers that read tenant/user rows chosen by the request
      // (`?orgId=...`) through a client that bypasses row-level security.
      const read = handlers.spans.find(
        (s) =>
          (s.httpMethod === "GET" || s.httpMethod === "HEAD") &&
          !handlers.covered(s) &&
          tenantReadFromRequest(handlers.src, s),
      );
      if (read !== undefined) {
        findings.push({
          id: createFindingId(
            CATEGORY_PREFIX.auth,
            "auth/missing-route-auth",
            filePath,
            read.startLine,
          ),
          ruleId: "auth/missing-route-auth",
          title: "Unauthenticated route returns another tenant's data",
          severity: "critical",
          category: "auth",
          deployBlocking: true,
          confidence: "high",
          file: filePath,
          line: read.startLine,
          plainEnglishProblem:
            "This GET route returns rows filtered by an organization or user id taken from the request, using a database client that bypasses row-level security, and never checks who is calling.",
          whyItMatters:
            "Anyone who knows or guesses an id can download that tenant's private data (customer emails, orders, invoices) without logging in.",
          fixSteps: [
            "Check the session at the start of the handler and return 401 when there is none.",
            "Take the organization/user id from the session, not from the query string, and filter the query by it.",
            "Prefer the user's RLS-scoped client over the service-role client for user-facing reads.",
          ],
          autoFixAvailable: false,
          aiFixPrompt:
            "This Next.js GET route reads tenant data selected by an id from the request using a service-role (RLS-bypassing) client and has no authentication. Add a session check at the start of the handler that returns 401 when unauthenticated, take the organization or user id from the session instead of the request, and scope the query to it.",
        });
      }
    }

    return findings;
  }

  /** Handler spans of a Next.js route file and a per-span "is covered" check. */
  private async handlers(
    filePath: string,
    content: string,
    context: ScanContext,
  ): Promise<{ src: JsSource; spans: FunctionSpan[]; covered: (s: FunctionSpan) => boolean }> {
    const src = await getJsSource(context, filePath);
    try {
      const cls = classifyFile(filePath, content, context.projectContext);
      const spans = handlerSpans(src, cls).filter(
        (s) => s.role === "app-route-handler" || s.role === "pages-api-handler",
      );
      const helpers = localAuthHelpers(src, extractFunctions(src, cls));
      const covered = (s: FunctionSpan): boolean => {
        const body = src.code.slice(s.bodyStart, s.bodyEnd);
        return (
          spanAuthenticates(src, s, helpers) ||
          verifiesSignature(body) ||
          isPublicByDesignCode(body)
        );
      };
      return { src, spans, covered };
    } catch {
      return { src, spans: [], covered: () => false };
    }
  }

  /**
   * Express: flags mutating routes (POST/PUT/PATCH/DELETE/all) with no auth
   * middleware in the handler chain and no preceding auth `use()` in the file.
   * Best effort: auth applied in another file, or hidden inside a named handler
   * defined elsewhere, is not seen. Public-by-nature paths (login, register,
   * forgot/reset password, oauth, callback, health) are skipped.
   */
  private async detectExpress(filePath: string, context: ScanContext): Promise<Finding[]> {
    const content = await context.readFile(filePath);
    if (!usesExpress(content, context.projectContext?.dependencies)) return [];

    const stripeWebhookFile = isStripeWebhookRoute(filePath, content);
    const findings: Finding[] = [];
    for (const route of extractExpressRoutes(content)) {
      if (!isExpressMutatingMethod(route.method)) continue;
      if (EXPRESS_PUBLIC_ROUTE_RE.test(route.path)) continue;
      // Stripe webhooks authenticate via signature verification; StripeWebhookDetector reports
      // unsigned ones. Other routes in the same file, including non-Stripe webhooks, stay covered.
      if (stripeWebhookFile && isStripeWebhookExpressRoute(route)) continue;
      if (isNonMutatingCatchAll(route)) continue;
      if (chainHasExpressAuth(route) || isCoveredByExpressUse(content, route)) continue;
      // Signed webhooks, checkout session creation and request-secret checks are not gaps.
      if (verifiesSignature(route.chainCode) || isPublicByDesignCode(route.chainCode)) continue;
      const chainSrc = createJsSource(route.handlerChain);
      if (hasSecretComparison(chainSrc, 0, chainSrc.text.length)) continue;

      const critical = isRiskyRoutePattern(route.path);
      const shownPath = displayRoutePath(route.path);
      findings.push({
        id: createFindingId(CATEGORY_PREFIX.auth, "auth/missing-route-auth", filePath, route.line),
        ruleId: "auth/missing-route-auth",
        title: "Missing authentication in Express route",
        severity: critical ? "critical" : "high",
        category: "auth",
        deployBlocking: critical,
        confidence: "medium",
        file: filePath,
        line: route.line,
        plainEnglishProblem: `The Express route ${route.method} ${shownPath} modifies data, but we couldn't find any middleware or code verifying who the user is.`,
        whyItMatters:
          "Without an auth check, anyone on the internet can call this endpoint directly and modify your data.",
        fixSteps: [
          "Add an authentication middleware (for example `passport.authenticate`, `requireAuth` or a JWT verifier) to this route or to its router with `router.use(...)`.",
          "Reject unauthenticated requests with a 401 response.",
        ],
        autoFixAvailable: false,
        aiFixPrompt: `I need to secure this Express route (${route.method} ${shownPath}). Please add an authentication middleware so unauthenticated users receive a 401 response.`,
      });
    }
    return findings;
  }
}
