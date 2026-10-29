import { describe, it, expect } from "vitest";
import path from "node:path";
import fs from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { FileDiscovery } from "../../src/scanner/file-discovery.js";
import { FrontendExposureDetector } from "../../src/detectors/frontend-exposure-detector.js";
import type { ScanContext } from "@talaljaber/vibesafe-shared";

const fixtureDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../../fixtures/nextjs-vibecoded-bad-app",
);

describe("nextjs-vibecoded-bad-app fixture (#40)", () => {
  it("reports service-role exposure via app/dashboard/page.tsx -> lib/supabase.ts", async () => {
    const files = await new FileDiscovery(fixtureDir).discoverFiles();
    const context = {
      rootPath: fixtureDir,
      projectContext: {},
      files,
      config: {},
      readFile: (f: string) => fs.readFile(path.join(fixtureDir, f), "utf-8"),
    } as unknown as ScanContext;

    const findings = await new FrontendExposureDetector().detect(context);
    const hit = findings.find(
      (f) =>
        f.ruleId === "frontend_exposure/service-role-key" && f.file === "app/dashboard/page.tsx",
    );
    expect(hit).toBeDefined();
    expect(hit?.line).toBe(3);
    expect(hit?.plainEnglishProblem).toContain("lib/supabase.ts");
  });
});
