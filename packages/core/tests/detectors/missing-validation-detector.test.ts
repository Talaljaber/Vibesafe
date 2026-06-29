import { describe, it, expect } from "vitest";
import { MissingValidationDetector } from "../../src/detectors/missing-validation-detector";
import type { ScanContext } from "@vibeguard/shared";

describe("MissingValidationDetector", () => {
  const detector = new MissingValidationDetector();

  const createContext = (files: Record<string, string>): ScanContext => ({
    rootPath: "/fake/path",
    projectContext: {} as any,
    files: Object.keys(files),
    config: {} as any,
    readFile: async (file) => files[file] || "",
  });

  it("should detect missing validation when req.json() is used", async () => {
    const context = createContext({
      "app/api/data/route.ts": `
        export async function POST(req: Request) {
          const body = await req.json();
          return Response.json(body);
        }
      `,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("validation/missing-body-validation");
  });

  it("should not detect when zod is imported and parse is called", async () => {
    const context = createContext({
      "app/api/data/route.ts": `
        import { z } from "zod";
        const schema = z.object({ name: z.string() });
        export async function POST(req: Request) {
          const body = await req.json();
          const parsed = schema.parse(body);
          return Response.json(parsed);
        }
      `,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(0);
  });
});
