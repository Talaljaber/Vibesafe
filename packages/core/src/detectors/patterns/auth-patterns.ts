/**
 * Call/usage-based signatures that indicate an authentication check.
 * A bare `import { auth }` is NOT enough: the helper must actually be invoked.
 */
export const AUTH_CHECK_PATTERNS: RegExp[] = [
  /\bauth\s*\(/,
  /\bgetAuth\s*\(/,
  /\bgetServerSession\s*\(/,
  /\bgetSession\s*\(/,
  /\bcurrentUser\s*\(/,
  /\bauth\.protect\s*\(/,
  /\bgetToken\s*\(/,
  /\bsupabase\.auth\.(getUser|getSession)\s*\(/,
  /\bjwt\.verify\s*\(/,
  /\bverifyToken\s*\(/,
  /\bverifyJwt\s*\(/,
  /\brequireAuth\b/,
  /\bcheckAuth\s*\(/,
  /\bisAuthenticated\b/,
  /\bwithAuth\s*\(/,
  /\bwithApiAuth\s*\(/,
];

/** Signatures that mark a middleware file as performing authentication. */
export const MIDDLEWARE_AUTH_PATTERNS: RegExp[] = [
  ...AUTH_CHECK_PATTERNS,
  /\bclerkMiddleware\s*\(/,
  /\bauthMiddleware\s*\(/,
  /\bwithAuth\b/,
  /next-auth\/middleware/,
  /\bNextAuth\s*\(/,
  /\bupdateSession\s*\(/,
];

export const RISKY_HTTP_METHODS = ["POST", "PUT", "PATCH", "DELETE"];

export const RISKY_ROUTE_PATTERNS = [
  "/admin",
  "/users",
  "/payment",
  "/billing",
  "/settings",
  "/dashboard",
  "/api/users",
  "/api/admin",
];

/**
 * Express: signatures of an authentication middleware in a route's middleware
 * arguments (everything before the final handler) or in an `app.use(...)` /
 * `router.use(...)` call. Matched against code with comments and strings blanked out.
 * Identifier or call forms only: no `authenticate\w*` / `validateUser` style wildcards.
 */
export const EXPRESS_AUTH_PATTERNS: RegExp[] = [
  /\bpassport\.authenticate\s*\(/,
  /\b(?:require|ensure|check|verify)(?:Auth\w*|Login\w*|LoggedIn|Jwt|Token|Session|User)\b/,
  /\bisAuth(?:enticated|orized|orised)?\b/,
  /\bjwt\s*\(/,
  /\bexpressjwt\s*\(/i,
  /\bjwt\.verify\s*\(/,
  /\bauth\s*\(/,
  /\bauthenticate\b/,
  /\bauth(?:Middleware|Guard|Required|Handler)\b/,
  /\bprotect\b/,
  /\bgetSession\s*\(/,
  /\bgetServerSession\s*\(/,
  /\bclerkMiddleware\s*\(/,
  /\bClerkExpressRequireAuth\s*\(/,
  /\bsupabase\.auth\.getUser\s*\(/,
  /\breq\.isAuthenticated\s*\(/,
];

/** Strict call-form auth checks accepted inside a route's final handler body. */
export const EXPRESS_HANDLER_AUTH_PATTERNS: RegExp[] = [
  /\bpassport\.authenticate\s*\(/,
  /\bjwt\.verify\s*\(/,
  /\b(?:getSession|getServerSession|getAuth|verifyToken|verifyJwt|checkAuth|requireAuth)\s*\(/,
  /\bsupabase\.auth\.getUser\s*\(/,
  /\breq\.isAuthenticated\s*\(/,
];

/**
 * Express route paths that are public by nature: specific leaf endpoints only
 * (login, signup, password reset, health, oauth callback). A bare `/auth/` segment is
 * deliberately NOT whitelisted, so `/auth/change-password` or `/auth/delete-account` are checked.
 */
export const EXPRESS_PUBLIC_ROUTE_RE =
  /(?:^|\/)(?:(?:log-?in|sign-?in|sign-?up|register|forgot-?password|reset-?password|health|healthz)|(?:o?auth)\/(?:[^/]+\/)?callback)\/?$/i;

/** Patterns that indicate a role / ownership / permission check. */
export const AUTHZ_CHECK_PATTERNS: RegExp[] = [
  /\bisAdmin\b/,
  /\bis_admin\b/,
  /\brole\s*(===|==|!==|!=|\.)/,
  /\broles?\.(includes|some|has)\s*\(/,
  /\bhasPermission\s*\(/,
  /\bhasRole\s*\(/,
  /\bpermissions?\.(includes|has|some)\s*\(/,
  /\bcan(Access)?\s*\(/,
  /\bownerId\s*(===|==|!==|!=)/,
  /\buserId\s*(===|==|!==|!=)/,
  /\buser\.id\s*(===|==|!==|!=)/,
  /\bsession\.user\.id\s*(===|==|!==|!=)/,
  /\breq\.user\.id\b/,
  /\bauthorize\s*\(/,
  /\brequire(Role|Admin)\b/,
];
