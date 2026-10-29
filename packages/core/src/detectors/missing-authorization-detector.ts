// ─────────────────────────────────────────────────────────────────────────────
// Missing Authorization Detector
//
// Detects routes that have authentication but no role/ownership checks.
// i.e., "You're logged in, but are you *allowed* to do this?"
// ─────────────────────────────────────────────────────────────────────────────

import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { CATEGORY_PREFIX, createFindingId } from "@talaljaber/vibesafe-shared";
import {
  isApiRoute,
  hasAuthCheck,
  findAnyHandlerLine,
  middlewareProtectsApi,
} from "./utils/route-analyzer.js";
import { AUTHZ_CHECK_PATTERNS } from "./patterns/auth-patterns.js";

/** Admin-sounding routes that need a role check, not just a session check. */
const ADMIN_ROUTE_PATTERNS = ["/admin", "/superuser", "/manage", "/moderat"];

export class MissingAuthorizationDetector implements Detector {
  id = "missing-authorization-detector";
  name = "Missing Authorization Detection";
  category = "authorization" as const;
  description =
    "Detects API routes that check authentication but skip role or ownership verification.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const protectedByMiddleware = await middlewareProtectsApi(context.files, (f) =>
      context.readFile(f),
    );

    for (const filePath of context.files) {
      if (!isApiRoute(filePath)) continue;

      const content = await context.readFile(filePath);

      // Only flag routes that DO have an auth check — missing auth is caught by MissingAuthDetector
      if (!hasAuthCheck(content) && !protectedByMiddleware) continue;

      const normalizedPath = filePath.replace(/\\/g, "/");
      const isAdminRoute = ADMIN_ROUTE_PATTERNS.some((p) => normalizedPath.includes(p));

      if (isAdminRoute) {
        const hasAuthzCheck = AUTHZ_CHECK_PATTERNS.some((re) => re.test(content));

        if (!hasAuthzCheck) {
          const line = findAnyHandlerLine(content) ?? 1;
          findings.push({
            id: createFindingId(
              CATEGORY_PREFIX.authorization,
              "authorization/missing-role-check",
              filePath,
              line,
            ),
            ruleId: "authorization/missing-role-check",
            title: "Admin route missing role check",
            severity: "high",
            category: "authorization",
            deployBlocking: false,
            confidence: "medium",
            file: filePath,
            line,
            plainEnglishProblem:
              "This admin route checks if a user is logged in, but not whether they are actually an admin.",
            whyItMatters:
              "Any logged-in user can call this route and perform admin actions, even if they are a regular customer.",
            fixSteps: [
              "After the auth check, verify the user has the required role.",
              "Example: `if (session.user.role !== 'admin') return new Response('Forbidden', { status: 403 })`",
            ],
            autoFixAvailable: false,
            aiFixPrompt:
              "This admin API route checks that the user is logged in, but doesn't verify their role. Please add a role check so only admins can access it.",
          });
        }
      }
    }

    return findings;
  }
}
