import { describe, expect, it } from "vitest";
import {
  nextRoutePath,
  findHandlerLine,
  isPublicRoutePath,
  isApiRoute,
  isRiskyRoutePattern,
} from "../../src/index.js";

describe("route helpers exported from the package index", () => {
  it("nextRoutePath maps files to URL paths", () => {
    expect(nextRoutePath("app/api/orders/[id]/route.ts")).toBe("/api/orders/[id]");
    expect(nextRoutePath("src/components/Button.tsx")).toBeUndefined();
  });

  it("findHandlerLine finds an exported handler", () => {
    expect(findHandlerLine("const a = 1;\nexport async function GET() {}\n", ["GET"])).toBe(2);
    expect(findHandlerLine("export const x = 1;\n", ["GET"])).toBeUndefined();
  });

  it("isPublicRoutePath recognises public routes", () => {
    expect(isPublicRoutePath("/api/health")).toBe(true);
    expect(isPublicRoutePath("/api/orders/[id]")).toBe(false);
  });

  it("isApiRoute recognises API route files", () => {
    expect(isApiRoute("app/api/orders/route.ts")).toBe(true);
    expect(isApiRoute("app/page.tsx")).toBe(false);
  });

  it("isRiskyRoutePattern recognises sensitive paths", () => {
    expect(isRiskyRoutePattern("app/api/admin/route.ts")).toBe(true);
    expect(isRiskyRoutePattern("app/api/ping/route.ts")).toBe(false);
  });
});
