import { describe, it, expect } from "vitest";
import { MissingAuthorizationDetector } from "../../src/detectors/missing-authorization-detector";
import type { ScanContext } from "@vibeguard/shared";

describe("MissingAuthorizationDetector", () => {
  const detector = new MissingAuthorizationDetector();

  const createContext = (files: Record<string, string>): ScanContext => ({
    rootPath: "/fake/path",
    projectContext: {} as any,
    files: Object.keys(files),
    config: {} as any,
    readFile: async (file) => files[file] || "",
  });

  it("should detect admin route with auth but no role check", async () => {
    const context = createContext({
      "app/api/admin/users/route.ts": `
        import { getServerSession } from "next-auth";
        export async function GET(req: Request) {
          const session = await getServerSession();
          if (!session) return new Response("Not Logged In");
          return Response.json([]);
        }
      `,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("authorization/missing-role-check");
  });

  it("should not detect if role check exists", async () => {
    const context = createContext({
      "app/api/admin/users/route.ts": `
        import { getServerSession } from "next-auth";
        export async function GET(req: Request) {
          const session = await getServerSession();
          if (!session || session.user.role !== 'admin') return new Response("Unauthorized");
          return Response.json([]);
        }
      `,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(0);
  });
});
