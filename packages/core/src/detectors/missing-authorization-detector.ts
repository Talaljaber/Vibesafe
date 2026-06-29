// ─────────────────────────────────────────────────────────────────────────────
// Missing Authorization Detector
//
// Detects routes that have authentication but no role/ownership checks.
// i.e., "You're logged in, but are you *allowed* to do this?"
// ─────────────────────────────────────────────────────────────────────────────

import type { Detector, Finding, ScanContext } from "@vibeguard/shared";
import { isApiRoute, hasAuthCheck } from "./utils/route-analyzer.js";
import crypto from "crypto";

/** Patterns that indicate a proper authorization check (role, ownership, admin). */
const AUTHZ_PATTERNS = [
  "isAdmin",
  "role",
  "hasPermission",
  "permissions",
  "ownerId",
  "user.id ===",
  "userId ===",
  "req.user.id",
  "session.user.id",
  "canAccess",
  "authorize",
];

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

    for (const filePath of context.files) {
      if (!isApiRoute(filePath)) continue;

      const content = await context.readFile(filePath);

      // Only flag routes that DO have an auth check — missing auth is caught by MissingAuthDetector
      if (!hasAuthCheck(content)) continue;

      const normalizedPath = filePath.replace(/\\/g, "/");
      const isAdminRoute = ADMIN_ROUTE_PATTERNS.some((p) =>
        normalizedPath.includes(p)
      );

      if (isAdminRoute) {
        const hasAuthzCheck = AUTHZ_PATTERNS.some((p) => content.includes(p));

        if (!hasAuthzCheck) {
          findings.push({
            id: `AUTHZ-${crypto.randomBytes(3).toString("hex")}`,
            ruleId: "authorization/missing-role-check",
            title: "Admin route missing role check",
            severity: "high",
            category: "authorization",
            deployBlocking: false,
            confidence: "medium",
            file: filePath,
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
