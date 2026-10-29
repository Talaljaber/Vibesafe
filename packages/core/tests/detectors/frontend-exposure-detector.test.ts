import { describe, it, expect } from "vitest";
import { FrontendExposureDetector } from "../../src/detectors/frontend-exposure-detector";
import type { ScanContext } from "@talaljaber/vibesafe-shared";

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
      await mk({
        "components/a.tsx": `const s = "use client";\nconst k = process.env.NEXT_PUBLIC_X_SECRET;`,
      }),
    ).toHaveLength(0);
    expect(
      await mk({ "src/pages/a.tsx": `const k = process.env.NEXT_PUBLIC_X_SECRET;` }),
    ).toHaveLength(1);
    expect(
      await mk({ "pages/api/a.ts": `const k = process.env.NEXT_PUBLIC_X_SECRET;` }),
    ).toHaveLength(0);
    expect(
      await mk({
        "components/a.tsx": `// header\n\n'use client'\nconst k = process.env.NEXT_PUBLIC_X_SECRET;`,
      }),
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

  it("should detect firebase-admin import in client component", async () => {
    const context = createContext({
      "app/components/UserProfile.tsx": `
        "use client";
        import admin from "firebase-admin";
        export function UserProfile() { return <div>User</div>; }
      `,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("frontend_exposure/firebase-admin");
    expect(findings[0].severity).toBe("critical");
    expect(findings[0].deployBlocking).toBe(true);
  });

  it("should detect firebase-admin subpath imports in client component", async () => {
    const context = createContext({
      "components/AuthWidget.tsx": `
        'use client';
        import { getAuth } from 'firebase-admin/auth';
        import { initializeApp } from "firebase-admin/app";
      `,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(2);
    expect(findings[0].ruleId).toBe("frontend_exposure/firebase-admin");
    expect(findings[1].ruleId).toBe("frontend_exposure/firebase-admin");
  });

  it("should detect require('firebase-admin') in Pages router client file", async () => {
    const context = createContext({
      "pages/dashboard.jsx": `
        const admin = require('firebase-admin');
        export default function Dashboard() { return <div>Dashboard</div>; }
      `,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("frontend_exposure/firebase-admin");
  });

  it("should detect dynamic import('firebase-admin') in client component", async () => {
    const context = createContext({
      "app/admin/client-page.tsx": `
        "use client";
        async function loadAdmin() {
          const admin = await import('firebase-admin');
        }
      `,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("frontend_exposure/firebase-admin");
  });

  it("should not detect firebase-admin in server component or API route", async () => {
    const context = createContext({
      "app/api/auth/route.ts": `
        import admin from "firebase-admin";
        export async function POST() { return Response.json({}); }
      `,
      "pages/api/login.js": `
        const admin = require('firebase-admin');
      `,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(0);
  });

  it("should not detect firebase-admin in Server Action file with 'use server'", async () => {
    const context = createContext({
      "app/actions/user.ts": `
        "use server";
        import admin from "firebase-admin";
        export async function deleteUser(id: string) {}
      `,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(0);
  });

  it("should not flag import type from firebase-admin in client file", async () => {
    const context = createContext({
      "app/components/TypeOnly.tsx": `
        "use client";
        import type { App } from 'firebase-admin/app';
        import type { UserRecord } from "firebase-admin/auth";
      `,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(0);
  });

  it("should not flag commented-out firebase-admin import", async () => {
    const context = createContext({
      "app/page.tsx": `
        "use client";
        // import admin from "firebase-admin";
        /* const admin = require('firebase-admin'); */
      `,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(0);
  });

  it("flags a client file that imports a module using firebase-admin", async () => {
    const findings = await detector.detect(
      createContext({
        "app/page.tsx": `"use client";\nimport { adminDb } from "../lib/admin";\n`,
        "lib/admin.ts": `import { getFirestore } from "firebase-admin/firestore";\nexport const adminDb = getFirestore();\n`,
      }),
    );
    const hits = findings.filter((f) => f.ruleId === "frontend_exposure/firebase-admin");
    expect(hits).toHaveLength(1);
    expect(hits[0]?.file).toBe("app/page.tsx");
    expect(hits[0]?.line).toBe(2);
    expect(hits[0]?.severity).toBe("critical");
    expect(hits[0]?.id).toMatch(/^FE-/);
  });

  it("flags a service account JSON imported from client code", async () => {
    const findings = await detector.detect(
      createContext({
        "app/page.tsx": `"use client";\nimport sa from "../serviceAccountKey.json";\n`,
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe("frontend_exposure/firebase-admin");
    expect(findings[0]?.deployBlocking).toBe(true);
  });

  it("does not flag firebase-admin in a src/pages/api route or a client-side firebase import", async () => {
    const findings = await detector.detect(
      createContext({
        "src/pages/api/x.ts": `const admin = require("firebase-admin");\n`,
        "app/page.tsx": `"use client";\nimport { initializeApp } from "firebase/app";\n`,
      }),
    );
    expect(findings).toHaveLength(0);
  });

  it("does not flag a client file importing a 'use server' module that uses firebase-admin", async () => {
    const findings = await detector.detect(
      createContext({
        "app/page.tsx": `"use client";\nimport { del } from "./actions";\n`,
        "app/actions.ts": `"use server";\nimport admin from "firebase-admin";\nexport async function del() {}\n`,
      }),
    );
    expect(findings).toHaveLength(0);
  });

  it("does not flag a client file importing a server-only module that uses firebase-admin", async () => {
    const findings = await detector.detect(
      createContext({
        "app/page.tsx": `"use client";\nimport { db } from "../lib/db";\n`,
        "lib/db.ts": `import "server-only";\nimport admin from "firebase-admin";\nexport const db = 1;\n`,
      }),
    );
    expect(findings).toHaveLength(0);
  });

  it("does not flag multi-line or inline type-only firebase-admin imports", async () => {
    const findings = await detector.detect(
      createContext({
        "app/page.tsx": `"use client";\nimport type {\n  App,\n} from 'firebase-admin/app';\nimport { type UserRecord } from "firebase-admin/auth";\nimport { x } from "../lib/t";\n`,
        "lib/t.ts": `import type {\n  App\n} from "firebase-admin/app";\nexport const x = 1;\n`,
      }),
    );
    expect(findings).toHaveLength(0);
  });

  it("flags a multi-line value import of firebase-admin", async () => {
    const findings = await detector.detect(
      createContext({
        "app/page.tsx": `"use client";\nimport {\n  getAuth,\n} from "firebase-admin/auth";\n`,
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.confidence).toBe("high");
  });

  it("reports medium confidence for a transitive firebase-admin import", async () => {
    const findings = await detector.detect(
      createContext({
        "app/page.tsx": `"use client";\nimport { a } from "../lib/a";\n`,
        "lib/a.ts": `import admin from "firebase-admin";\n`,
      }),
    );
    expect(findings[0]?.confidence).toBe("medium");
  });

  it("flags service account JSON loaded via require or dynamic import", async () => {
    const findings = await detector.detect(
      createContext({
        "app/a.tsx": `"use client";\nconst k = require("./serviceAccountKey.json");\n`,
        "app/b.tsx": `"use client";\nconst k = await import("./firebase-adminsdk-abc12.json");\n`,
      }),
    );
    expect(findings).toHaveLength(2);
  });

  it("does not flag unrelated service-account-like JSON files", async () => {
    const findings = await detector.detect(
      createContext({
        "app/a.tsx": `"use client";\nimport s from "./serviceAccountSchema.json";\nimport l from "./service-accounts-list.json";\nimport c from "./config.json";\nconst x = require("./serviceAccountSchema.json");\n`,
      }),
    );
    expect(findings).toHaveLength(0);
  });

  it("does not flag firebase-admin in a pages file exporting getServerSideProps", async () => {
    const findings = await detector.detect(
      createContext({
        "pages/index.tsx": `import admin from "firebase-admin";\nexport async function getServerSideProps() { return { props: {} }; }\nexport default function P() { return null; }\n`,
        "pages/b.tsx": `import { a } from "../lib/a";\nexport const getStaticProps = async () => ({ props: {} });\n`,
        "lib/a.ts": `import admin from "firebase-admin";\n`,
      }),
    );
    expect(findings).toHaveLength(0);
  });

  it("flags firebase-admin in a src/pages file", async () => {
    const findings = await detector.detect(
      createContext({ "src/pages/index.tsx": `import admin from "firebase-admin";\n` }),
    );
    expect(findings).toHaveLength(1);
  });

  describe("public-by-design keys (anon / publishable)", () => {
    it("does not flag anon or publishable names, in .env files or client code", async () => {
      const findings = await detector.detect(
        createContext({
          ".env.local": [
            "NEXT_PUBLIC_SUPABASE_URL=https://abc.supabase.co",
            "NEXT_PUBLIC_SUPABASE_ANON_KEY=public-anon",
            "NEXT_PUBLIC_ANON_PRIVATE_KEY=public-anon",
            "VITE_STRIPE_PUBLISHABLE_PRIVATE_KEY=pk_test_x",
          ].join("\n"),
          "lib/client/supabase.ts": `"use client";
import { createBrowserClient } from "@supabase/ssr";
export const supabase = createBrowserClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
);
const legacy = process.env.NEXT_PUBLIC_ANON_PRIVATE_KEY;
`,
        }),
      );
      expect(findings).toEqual([]);
    });

    it("still flags secret names, and anon names that also say SERVICE_ROLE", async () => {
      const findings = await detector.detect(
        createContext({
          ".env": [
            "NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_test_x",
            "NEXT_PUBLIC_SUPABASE_ANON_SERVICE_ROLE_KEY=x",
          ].join("\n"),
          "components/Pay.tsx": `"use client";
const key = process.env.NEXT_PUBLIC_PAYMENTS_PRIVATE_KEY;
`,
        }),
      );
      expect(findings.map((f) => `${f.file}:${f.line}:${f.ruleId}`)).toEqual([
        ".env:1:frontend_exposure/public-secret-var",
        ".env:2:frontend_exposure/public-secret-var",
        "components/Pay.tsx:2:frontend_exposure/public-secret-var",
      ]);
    });

    it("does not follow import type into server modules", async () => {
      const findings = await detector.detect(
        createContext({
          "components/ProductForm.tsx": `"use client";
import type { getSession } from "@/lib/server/auth";
type Session = Awaited<ReturnType<typeof getSession>>;
export function ProductForm({ session }: { session: Session }) { return null; }
`,
          "lib/server/auth.ts": `import { createClient } from "@supabase/supabase-js";
const admin = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
export async function getSession() { return admin.auth.getSession(); }
`,
        }),
      );
      expect(findings).toEqual([]);
    });
  });
});
