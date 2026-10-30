// Detector group "authz": authentication and authorization detectors (IDOR, mass assignment, auth ordering, route secrets, middleware, error leaks).
//
// Owned by one stream. Export ONLY: the group's *Detector classes (re-exported from
// their detector files), authzDetectors, authzPrecedence and authzNonJsExempt. Never
// export utils or types from here (core's index.ts re-exports this file with
// `export *`). Import precedence types with `import type` only.
import type { Detector } from "@talaljaber/vibesafe-shared";
import type { PrecedenceRule } from "../../scanner/precedence.js";
import type { FileKind } from "../utils/file-kind.js";
import { IdorDetector } from "../idor-detector.js";
import { MassAssignmentDetector } from "../mass-assignment-detector.js";
import { AuthOrderDetector } from "../auth-order-detector.js";
import { RouteSecretDetector } from "../route-secret-detector.js";
import { MiddlewareAuthDetector } from "../middleware-auth-detector.js";
import { ErrorLeakDetector } from "../error-leak-detector.js";
import { AuthBypassDetector } from "../auth-bypass-detector.js";
import { AdminDashboardDetector } from "../admin-dashboard-detector.js";

export {
  IdorDetector,
  MassAssignmentDetector,
  AuthOrderDetector,
  RouteSecretDetector,
  MiddlewareAuthDetector,
  ErrorLeakDetector,
  AuthBypassDetector,
  AdminDashboardDetector,
};

/** Fresh instances of this group's detectors, registered after the built-in ones. */
export const authzDetectors = (): Detector[] => [
  new IdorDetector(),
  new MassAssignmentDetector(),
  new AuthOrderDetector(),
  new RouteSecretDetector(),
  new MiddlewareAuthDetector(),
  new ErrorLeakDetector(),
  new AuthBypassDetector(),
  new AdminDashboardDetector(),
];

/**
 * Cross-owner precedence rules declared by this group (see scanner/precedence.ts).
 * `missing-auth-detector` treats a request-secret comparison as an auth mechanism, so
 * `auth/hardcoded-route-secret` and `auth/missing-route-auth` never fire together, and
 * IDOR / mass assignment / auth-order findings coexist with `auth/missing-route-auth`.
 * The one rule below dedupes the crypto group's decode finding against ours.
 */
export const authzPrecedence: readonly PrecedenceRule[] = [
  {
    winner: "crypto/jwt-decode-for-auth",
    losers: ["auth/jwt-decode-without-verify"],
    scope: "line",
    reason:
      "Both report the same unverified jwt.decode on this line; the crypto finding already names the problem.",
  },
];

/** Detector id -> non-JS file kinds it legitimately reports on (used by non-js-files.test.ts). */
export const authzNonJsExempt: Readonly<Record<string, readonly FileKind[]>> = {};
