import { describe, it, expect } from "vitest";
import {
  isApiRoute,
  hasRiskyHttpMethods,
  findHandlerLine,
  hasAuthCheck,
  matcherCoversApi,
  middlewareProtectsApi,
} from "../../src/detectors/utils/route-analyzer";

describe("isApiRoute", () => {
  it.each([
    "app/api/users/route.ts",
    "src/app/api/x/route.js",
    "app/foo/route.mjs",
    "pages/api/users.ts",
    "src/pages/api/a/b.js",
  ])("accepts %s", (p) => expect(isApiRoute(p)).toBe(true));
  it.each(["lib/api/client.ts", "src/api/helpers.ts", "app/page.tsx", "components/api/Button.tsx", "api/server.ts"])(
    "rejects %s",
    (p) => expect(isApiRoute(p)).toBe(false),
  );
});

describe("hasRiskyHttpMethods", () => {
  it.each([
    "export async function POST(r) {}",
    "export function DELETE() {}",
    "export const PUT = async () => {};",
    "const h = async () => {};\nexport { h as PATCH };",
    "async function POST() {}\nexport { POST };",
  ])("detects %s", (c) => expect(hasRiskyHttpMethods(c)).toBe(true));
  it("ignores GET-only", () => {
    expect(hasRiskyHttpMethods("export async function GET() {}\nexport { GET as HEAD }")).toBe(false);
  });
  it("reports the export line", () => {
    expect(findHandlerLine("a\n\nexport const POST = 1;")).toBe(3);
  });
});

describe("hasAuthCheck", () => {
  it("does not count a bare import", () => {
    expect(hasAuthCheck('import { auth } from "@/auth";')).toBe(false);
  });
  it.each(["const s = await auth();", "await getServerSession(opts)", "auth.protect()", "await currentUser()"])(
    "counts %s",
    (c) => expect(hasAuthCheck(c)).toBe(true),
  );
});

describe("middleware matcher", () => {
  it("covers /api via explicit matcher", () => {
    expect(matcherCoversApi('export const config = { matcher: ["/api/:path*"] }')).toBe(true);
  });
  it("does not cover when matcher is only dashboard", () => {
    expect(matcherCoversApi('export const config = { matcher: ["/dashboard/:path*"] }')).toBe(false);
  });
  it("covers catch-all lookahead unless api excluded", () => {
    expect(matcherCoversApi('matcher: ["/((?!_next|favicon.ico).*)"]')).toBe(true);
    expect(matcherCoversApi('matcher: ["/((?!api|_next).*)"]')).toBe(false);
  });
  it("detects protecting middleware", async () => {
    const files: Record<string, string> = {
      "middleware.ts": 'export default clerkMiddleware(); export const config = { matcher: ["/api/(.*)"] };',
    };
    expect(await middlewareProtectsApi(Object.keys(files), async (f) => files[f] ?? "")).toBe(true);
  });
});
