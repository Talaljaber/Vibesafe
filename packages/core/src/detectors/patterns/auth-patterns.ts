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

// ---------------------------------------------------------------------------
// Per-handler authentication, public-by-design routes and authorization scoping
// ---------------------------------------------------------------------------

/**
 * Extra call-form auth checks accepted inside one handler body, in addition to
 * {@link AUTH_CHECK_PATTERNS}: project helpers named for what they do. Matched on masked code.
 */
export const HANDLER_AUTH_PATTERNS: RegExp[] = [
  /\b(?:require|ensure|assert)(?:Auth\w*|User|Session|Login|LoggedIn|Admin|Staff|Role|Owner|Member\w*|Permission\w*)\s*\(/,
  /\bget(?:Current|LoggedIn|Auth|Authenticated|Session)User\s*\(/,
  /\bgetUserFromRequest\s*\(/,
  /\bvalidate(?:Request|Session|Token|ApiKey)\s*\(/,
  /\bverify(?:Session|ApiKey|Auth\w*|IdToken|AccessToken)\s*\(/,
  /\bgetKindeServerSession\s*\(/,
  /\bgetIronSession\s*\(/,
  /\bpassport\.authenticate\s*\(/,
  /\breq\.isAuthenticated\s*\(/,
];

/**
 * Wrapper callees that authenticate the wrapped handler (`export const GET = withAuth(...)`,
 * Auth.js v5 `auth(...)`, `withApiAuthRequired(...)`). Matched against the last segment of
 * the callee name.
 */
export const AUTH_WRAPPER_RE =
  /^(?:with\w*(?:Auth|Session|User|Admin|Role|Permission|Guard|Protect)\w*|withApiAuthRequired|withPageAuthRequired|require(?:Auth\w*|User|Session|Admin|Role)|protect(?:ed)?\w*|authed\w*|authenticated\w*|authorized\w*|auth|withClerk\w*|clerkMiddleware)$/i;

/**
 * URL paths of Next.js routes that are public by design: sign-in and sign-up, password
 * reset, OAuth/auth callbacks, the Auth.js catch-all and health probes.
 */
export const PUBLIC_ROUTE_PATH_RE =
  /(?:^|\/)(?:(?:log-?in|sign-?in|sign-?up|register|forgot-?password|reset-?password|health|healthz|livez|readyz|ping)|(?:o?auth)\/(?:[^/]+\/)?callback|auth\/\[\.\.\.[\w-]+\])\/?$/i;

/** Signature verification of an incoming webhook: such a route authenticates by signature. */
export const SIGNATURE_VERIFY_PATTERNS: RegExp[] = [
  /\bconstructEvent(?:Async)?\s*\(/,
  /\b\w*(?:webhook|Webhook|svix)\w*\s*\.\s*(?:verify|unwrap)\s*\(/,
  /\bverify\w*(?:Signature|Webhook|Hmac)\w*\s*\(/i,
  /\bvalidate\w*(?:Signature|Webhook)\w*\s*\(/i,
  /\bisValid\w*Signature\s*\(/i,
  /\btimingSafeEqual\s*\(/,
];

/**
 * Handler bodies that are public by design: creating a Stripe Checkout session for a
 * storefront visitor, exchanging an OAuth/magic-link code for a session.
 */
export const PUBLIC_HANDLER_PATTERNS: RegExp[] = [
  /\bcheckout\s*\.\s*sessions\s*\.\s*create\s*\(/,
  /\bexchangeCodeForSession\s*\(/,
  /\bverifyOtp\s*\(/,
];

/**
 * Columns that scope a row to a tenant or a user (`org_id`, `userId`, `owner_id`, `created_by`).
 * Matched against the last segment of a column name (`orders.org_id` gives `org_id`).
 */
export const OWNER_COLUMN_RE =
  /^(?:org|organi[sz]ation|tenant|team|workspace|account|company|user|owner|author|creator|member|profile|shop|store|project|client)_?id$|^(?:created_?by|owned_?by|uid|owner|user|author)$/i;

/** Columns that identify one row (`id`, `_id`, `uuid`, `order_id`, `invoiceId`). */
export const ID_COLUMN_RE = /^(?:id|_id|uuid|[a-z][a-z0-9]*_id|[a-z][A-Za-z0-9]*Id)$/;

/**
 * Value expressions that come from the authenticated identity rather than the request:
 * `session.user.id`, `user.id`, `req.user.id`, `ctx.session.orgId`, `auth.uid`.
 */
export const IDENTITY_VALUE_RE =
  /^\s*(?:await\s+)?\(?\s*(?:session|user|currentUser|authUser|me|viewer|claims|auth|membership|identity|principal|actor|caller|(?:ctx|context)\s*\.\s*(?:session|user|auth)|(?:req|request|c|ctx)\s*\.\s*(?:user|auth|session|locals)|res\s*\.\s*locals)\b/;

/** Binding names that hold the authenticated identity (`session`, `user`, `claims`). */
export const IDENTITY_NAME_RE =
  /^(?:session|user|currentUser|authUser|me|viewer|claims|auth|membership|identity|principal|actor|caller)$/;

/**
 * A comparison of a stored row's owner/tenant column with something else
 * (`order.user_id !== session.user.id`), or an explicit ownership/permission helper call.
 * Matched on masked code.
 */
export const OWNERSHIP_CHECK_RE =
  /\.\s*(?:(?:org|organi[sz]ation|tenant|team|workspace|account|user|owner|author|creator|member)_?[iI]d|created_?[bB]y|owner)\s*(?:!==|===|!=|==)|(?:!==|===|!=|==)\s*[\w$.?]+\.\s*(?:org|organi[sz]ation|tenant|team|workspace|account|user|owner|author|creator|created_?by|member)_?[iI]d\b|\b(?:assert|check|verify|ensure|require)\w*(?:Owner|Ownership|Access|Permission|Member)\w*\s*\(|\bcan(?:Access|Edit|View|Read|Update|Delete|Manage)?\s*\(|\bauthorize\w*\s*\(|\bhasPermission\s*\(/;

/** Admin/staff checks: an admin-only handler reaching any row is by design. Matched on raw text. */
export const ADMIN_CHECK_RE =
  /\b(?:isAdmin|is_admin|isStaff|is_staff|isSuperAdmin|isSuperuser|is_superuser|requireAdmin|requireStaff|assertAdmin|ensureAdmin)\b|\brole\s*(?:===|!==|==|!=)\s*["'`](?:admin|superadmin|super_admin|staff|owner)["'`]/;

/** Request parameter or header names that carry a shared secret (`key`, `token`, `x-cron-secret`). */
export const SECRET_PARAM_NAME_RE =
  /^(?:key|secret|token|auth|authorization|password|passwd|pass|pwd|passcode|signature|sig|cron|apikey|api[-_]key|access[-_]?(?:key|token)|admin[-_]?(?:key|token|secret|password)|x-[\w-]*(?:key|secret|token|auth|signature|password)[\w-]*)$|secret|token|api[-_]?key|password/i;
