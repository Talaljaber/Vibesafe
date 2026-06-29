export const AUTH_FUNCTION_SIGNATURES = [
  "getServerSession",
  "await auth()",
  "import { auth }",
  "supabase.auth.getUser",
  "supabase.auth.getSession",
  "verifyToken",
  "jwt.verify",
  "requireAuth",
  "checkAuth",
  "isAuthenticated"
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
