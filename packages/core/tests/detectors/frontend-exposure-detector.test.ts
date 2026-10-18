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
});
