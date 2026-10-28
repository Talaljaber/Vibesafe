import { type Detector, type Finding, type ScanContext } from "@vibesafe/shared";
import { CATEGORY_PREFIX, createFindingId } from "@vibesafe/shared";
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
  hasExpressAuth,
  isCoveredByExpressUse,
} from "./utils/route-analyzer.js";
import { RISKY_HTTP_METHODS, EXPRESS_PUBLIC_ROUTE_RE } from "./patterns/auth-patterns.js";

export class MissingAuthDetector implements Detector {
  id = "missing-auth-detector";
  name = "Missing Auth Detection";
  category = "auth" as const;
  description = "Detects API routes that perform risky operations without checking authentication.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const protectedByMiddleware = await middlewareProtectsApi(context.files, (f) => context.readFile(f));

    for (const filePath of context.files) {
      if (isExpressCandidateFile(filePath) && !isApiRoute(filePath)) {
        findings.push(...(await this.detectExpress(filePath, context)));
        continue;
      }
      if (!isApiRoute(filePath)) {
        continue;
      }

      const content = await context.readFile(filePath);

      const riskyLine = findHandlerLine(content, RISKY_HTTP_METHODS);
      const isMutatingRoute = riskyLine !== undefined;
      const isSensitivePath = isRiskyRoutePattern(filePath);

      // Severity: sensitive path + mutating method -> critical (deploy blocking);
      // sensitive path with only read handlers, or a mutating non-sensitive route -> high.
      const critical = isSensitivePath && isMutatingRoute;

      if (isMutatingRoute || isSensitivePath) {
        if (!hasAuthCheck(content) && !protectedByMiddleware) {
          const line = riskyLine ?? findAnyHandlerLine(content) ?? 1;
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
            plainEnglishProblem: "This API route appears to modify data or access sensitive info, but we couldn't find any code verifying who the user is.",
            whyItMatters: "Without an auth check, anyone on the internet can call this API directly and modify your database or view private data.",
            fixSteps: [
              "Import your authentication library's server-side session checker.",
              "Call the session checker at the very beginning of the route handler.",
              "If the session is null, immediately `return new Response('Unauthorized', { status: 401 })`."
            ],
            autoFixAvailable: false,
            aiFixPrompt: `I need to secure this Next.js API route. Please add an authentication check at the beginning of the handler so that unauthenticated users receive a 401 response.`
          });
        }
      }
    }

    return findings;
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

    const findings: Finding[] = [];
    for (const route of extractExpressRoutes(content)) {
      if (!isExpressMutatingMethod(route.method)) continue;
      if (EXPRESS_PUBLIC_ROUTE_RE.test(route.path)) continue;
      if (hasExpressAuth(route.handlerChain) || isCoveredByExpressUse(content, route)) continue;

      const critical = isRiskyRoutePattern(route.path);
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
        plainEnglishProblem: `The Express route ${route.method} ${route.path} modifies data, but we couldn't find any middleware or code verifying who the user is.`,
        whyItMatters:
          "Without an auth check, anyone on the internet can call this endpoint directly and modify your data.",
        fixSteps: [
          "Add an authentication middleware (for example `passport.authenticate`, `requireAuth` or a JWT verifier) to this route or to its router with `router.use(...)`.",
          "Reject unauthenticated requests with a 401 response.",
        ],
        autoFixAvailable: false,
        aiFixPrompt: `I need to secure this Express route (${route.method} ${route.path}). Please add an authentication middleware so unauthenticated users receive a 401 response.`,
      });
    }
    return findings;
  }
}
