import { describe, it, expect } from "vitest";
import { FrontendExposureDetector } from "../../src/detectors/frontend-exposure-detector";
import type { ScanContext } from "@vibesafe/shared";

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

  it("follows relative imports from client files into server-only secrets", async () => {
    const findings = await detector.detect(
      createContext({
        "app/page.tsx": `"use client";\nimport { db } from "../lib/db";\n`,
        "lib/db.ts": `export const db = connect(process.env.DATABASE_PASSWORD);\n`,
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.file).toBe("app/page.tsx");
    expect(findings[0]?.line).toBe(2);
    expect(findings[0]?.plainEnglishProblem).toContain("lib/db.ts");
  });

  it("resolves @/ aliases and index files, ignores public-prefixed vars", async () => {
    const findings = await detector.detect(
      createContext({
        "src/app/a.tsx": `"use client";\nimport x from "@/lib/x";\nimport y from "@/lib/y";\n`,
        "src/lib/x/index.ts": `export default process.env.STRIPE_SECRET_KEY;\n`,
        "src/lib/y.ts": `export default import.meta.env.VITE_API_URL + process.env.NEXT_PUBLIC_API_KEY;\n`,
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.line).toBe(2);
  });

  it("ignores service-role mentions in comments", async () => {
    const findings = await detector.detect(
      createContext({
        "app/page.tsx": `"use client";\n// never use SUPABASE_SERVICE_ROLE_KEY here\n/* service_role */\n`,
      }),
    );
    expect(findings).toHaveLength(0);
  });

  it("detects other public prefixes and .env files", async () => {
    const findings = await detector.detect(
      createContext({
        "app/page.tsx": `"use client";\nconst a = import.meta.env.VITE_DB_PASSWORD;\n`,
        ".env": "NEXT_PUBLIC_API_SECRET=abc\nVITE_OK=1\n",
        ".env.example": "NEXT_PUBLIC_API_SECRET=\n",
      }),
    );
    expect(findings.map((f) => f.file).sort()).toEqual([".env", "app/page.tsx"]);
    expect(findings.every((f) => f.severity === "high" && !f.deployBlocking)).toBe(true);
  });

  it("requires use client as first statement; supports src/pages", async () => {
    const mk = (files: Record<string, string>) => detector.detect(createContext(files));
    expect(
      await mk({ "components/a.tsx": `const s = "use client";\nconst k = process.env.NEXT_PUBLIC_X_SECRET;` }),
    ).toHaveLength(0);
    expect(
      await mk({ "src/pages/a.tsx": `const k = process.env.NEXT_PUBLIC_X_SECRET;` }),
    ).toHaveLength(1);
    expect(
      await mk({ "pages/api/a.ts": `const k = process.env.NEXT_PUBLIC_X_SECRET;` }),
    ).toHaveLength(0);
    expect(
      await mk({ "components/a.tsx": `// header\n\n'use client'\nconst k = process.env.NEXT_PUBLIC_X_SECRET;` }),
    ).toHaveLength(1);
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
