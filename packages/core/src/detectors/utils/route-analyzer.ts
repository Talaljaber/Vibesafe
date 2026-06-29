import { RISKY_ROUTE_PATTERNS, RISKY_HTTP_METHODS, AUTH_FUNCTION_SIGNATURES } from "../patterns/auth-patterns.js";

/**
 * Determines if a given file path is an API route.
 */
export function isApiRoute(filePath: string): boolean {
  const normalizedPath = filePath.replace(/\\/g, "/");
  return normalizedPath.includes("/api/") || normalizedPath.startsWith("api/");
}

/**
 * Checks if the route path matches known risky/sensitive patterns like /admin or /users.
 */
export function isRiskyRoutePattern(filePath: string): boolean {
  const normalizedPath = filePath.replace(/\\/g, "/");
  return RISKY_ROUTE_PATTERNS.some((pattern: string) => normalizedPath.includes(pattern));
}

/**
 * Checks if the file content defines risky HTTP methods like POST, PUT, DELETE.
 */
export function hasRiskyHttpMethods(fileContent: string): boolean {
  return RISKY_HTTP_METHODS.some((method: string) => 
    fileContent.includes(`export async function ${method}`) || 
    fileContent.includes(`export function ${method}`) ||
    // pages/api structure
    (fileContent.includes("req.method") && fileContent.includes(`"${method}"`)) ||
    (fileContent.includes("req.method") && fileContent.includes(`'${method}'`))
  );
}

/**
 * Checks if the file content contains any known auth check patterns.
 */
export function hasAuthCheck(fileContent: string): boolean {
  return AUTH_FUNCTION_SIGNATURES.some((sig: string) => fileContent.includes(sig));
}
