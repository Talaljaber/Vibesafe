import { describe, it, expect } from "vitest";
import { MissingAuthDetector } from "../../src/detectors/missing-auth-detector";
import type { ScanContext } from "@vibeguard/shared";

describe("MissingAuthDetector", () => {
  const detector = new MissingAuthDetector();

  const createContext = (files: Record<string, string>): ScanContext => ({
    rootPath: "/fake/path",
    projectContext: {} as any,
    files: Object.keys(files),
    config: {} as any,
    readFile: async (file) => files[file] || "",
  });

  it("should detect missing auth in mutating route", async () => {
    const context = createContext({
      "app/api/users/route.ts": `
        export async function POST(req: Request) {
          await db.users.create();
          return Response.json({ success: true });
        }
      `,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("auth/missing-route-auth");
  });

  it("should not detect if auth check exists", async () => {
    const context = createContext({
      "app/api/users/route.ts": `
        import { getServerSession } from "next-auth";
        export async function POST(req: Request) {
          const session = await getServerSession();
          if (!session) return new Response("Unauthorized");
          return Response.json({ success: true });
        }
      `,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(0);
  });
});
