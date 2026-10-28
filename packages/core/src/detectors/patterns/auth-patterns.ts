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
