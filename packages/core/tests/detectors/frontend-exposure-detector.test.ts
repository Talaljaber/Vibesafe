import { describe, it, expect } from "vitest";
import { FrontendExposureDetector } from "../../src/detectors/frontend-exposure-detector";
import type { ScanContext } from "@vibeguard/shared";

describe("FrontendExposureDetector", () => {
  const detector = new FrontendExposureDetector();

  const createContext = (files: Record<string, string>): ScanContext => ({
    rootPath: "/fake/path",
    projectContext: {} as any,
    files: Object.keys(files),
    config: {} as any,
    readFile: async (file) => files[file] || "",
  });

  it("should detect NEXT_PUBLIC_SECRET pattern", async () => {
    const context = createContext({
      "app/page.tsx": `
        "use client";
        const key = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;
      `,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("frontend_exposure/public-secret-var");
  });

  it("should detect SERVICE_ROLE_KEY in client component", async () => {
    const context = createContext({
      "components/MyComponent.tsx": `
        "use client";
        const supabase = createClient(URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
      `,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("frontend_exposure/service-role-key");
  });

  it("should not detect SERVICE_ROLE_KEY in server component", async () => {
    const context = createContext({
      "app/api/test/route.ts": `
        const supabase = createClient(URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
      `,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(0);
  });
});
