import { describe, it, expect } from "vitest";
import { MissingAuthDetector } from "../../src/detectors/missing-auth-detector";
import { MissingAuthorizationDetector } from "../../src/detectors/missing-authorization-detector";
import type { ScanContext } from "@vibesafe/shared";

const ctx = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake",
  projectContext: {} as any,
  files: Object.keys(files),
  config: {} as any,
  readFile: async (f) => files[f] ?? "",
});

describe("MissingAuthDetector (route shapes, severity, lines, middleware)", () => {
  const detector = new MissingAuthDetector();

  it("detects const-arrow and export-list handlers", async () => {
    const f = await detector.detect(
      ctx({
        "app/api/a/route.ts": "export const POST = async () => Response.json({});",
        "app/api/b/route.ts": "const h = async () => {};\nexport { h as DELETE };",
      }),
    );
    expect(f).toHaveLength(2);
  });

  it("does not treat a bare auth import as an auth check", async () => {
    const f = await detector.detect(
      ctx({
        "app/api/a/route.ts": 'import { auth } from "@/auth";\nexport async function POST() {}',
      }),
    );
    expect(f).toHaveLength(1);
    expect(f[0]!.line).toBe(2);
  });

  it("sensitive GET-only route is high, mutating sensitive is critical", async () => {
    const f = await detector.detect(
      ctx({
        "app/api/admin/stats/route.ts": "export async function GET() {}",
        "app/api/admin/del/route.ts": "export async function DELETE() {}",
      }),
    );
    const get = f.find((x) => x.file.includes("stats"))!;
    const del = f.find((x) => x.file.includes("del"))!;
    expect(get.severity).toBe("high");
    expect(get.deployBlocking).toBe(false);
    expect(del.severity).toBe("critical");
    expect(del.deployBlocking).toBe(true);
  });

  it("ignores non-route files under api directories", async () => {
    const f = await detector.detect(
      ctx({ "lib/api/client.ts": "export async function POST() {}" }),
    );
    expect(f).toHaveLength(0);
  });

  it("treats auth middleware covering /api as protection", async () => {
    const f = await detector.detect(
      ctx({
        "middleware.ts":
          'export default clerkMiddleware(); export const config = { matcher: ["/api/(.*)"] };',
        "app/api/a/route.ts": "export async function POST() {}",
      }),
    );
    expect(f).toHaveLength(0);
  });
});

describe("MissingAuthorizationDetector (word boundaries, lines)", () => {
  const detector = new MissingAuthorizationDetector();

  it("does not count the word Unauthorized as a role check", async () => {
    const f = await detector.detect(
      ctx({
        "app/api/admin/x/route.ts": `
const s = await getServerSession();
export async function GET() {
  if (!s) return new Response("Unauthorized", { status: 401 });
  return Response.json([]);
}`,
      }),
    );
    expect(f).toHaveLength(1);
    expect(f[0]!.line).toBe(3);
  });

  it("accepts isAdmin and hasPermission( checks", async () => {
    const f = await detector.detect(
      ctx({
        "app/api/admin/a/route.ts":
          "const s = await auth();\nif (!isAdmin(s)) return;\nexport async function GET() {}",
        "app/api/admin/b/route.ts":
          "await auth();\nif (!hasPermission(u, 'x')) return;\nexport async function GET() {}",
      }),
    );
    expect(f).toHaveLength(0);
  });

  it("ignores non-route files", async () => {
    const f = await detector.detect(ctx({ "lib/api/admin/x.ts": "await auth();" }));
    expect(f).toHaveLength(0);
  });
});
