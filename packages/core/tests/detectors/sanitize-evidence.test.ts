import { describe, it, expect } from "vitest";
import { sanitizeEvidence } from "../../src/detectors/utils/sanitize-evidence";
import { FrontendExposureDetector } from "../../src/detectors/frontend-exposure-detector";
import { HardcodedLocalhostDetector } from "../../src/detectors/hardcoded-localhost-detector";
import { CodebaseMessDetector } from "../../src/detectors/codebase-mess-detector";
import type { ScanContext } from "@vibesafe/shared";

const ctx = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake",
  projectContext: {} as any,
  files: Object.keys(files),
  config: {} as any,
  readFile: async (f) => files[f] || "",
});

const STRIPE = "sk_live_" + "a1B2c3D4e5F6g7H8i9J0k1L2";

describe("sanitizeEvidence", () => {
  it("redacts known secret patterns", () => {
    const out = sanitizeEvidence(`console.log("token", "${STRIPE}")`);
    expect(out).not.toContain(STRIPE);
  });

  it("redacts URL credentials", () => {
    const out = sanitizeEvidence('const u = "postgres://admin:hunter2@localhost:5432/db"');
    expect(out).not.toContain("hunter2");
    expect(out).toContain("admin");
  });

  it("redacts only the value of generic password assignments", () => {
    const out = sanitizeEvidence(`const password = "supersecretvalue123";`);
    expect(out).toContain("password");
    expect(out).not.toContain("supersecretvalue123");
    expect(out).toContain('"supe...e123"');
  });

  it("truncates long lines", () => {
    expect(sanitizeEvidence("x".repeat(5000)).length).toBeLessThanOrEqual(201);
  });

  it("is applied by detectors", async () => {
    const files = {
      "components/a.tsx": `"use client";\nconst SUPABASE_SERVICE_ROLE_KEY = "${STRIPE}";`,
      "src/b.ts": `const u = "postgres://admin:hunter2@localhost:5432/db";\nconsole.log("t", "${STRIPE}");`,
    };
    const findings = (
      await Promise.all(
        [new FrontendExposureDetector(), new HardcodedLocalhostDetector(), new CodebaseMessDetector()].map(
          (d) => d.detect(ctx(files)),
        ),
      )
    ).flat();
    expect(findings.length).toBeGreaterThan(0);
    const json = JSON.stringify(findings);
    expect(json).not.toContain(STRIPE);
    expect(json).not.toContain("hunter2");
  });
});
