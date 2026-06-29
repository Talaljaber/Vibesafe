import { describe, it, expect } from "vitest";
import path from "node:path";
import { FileDiscovery } from "../../src/scanner/file-discovery.js";

describe("FileDiscovery", () => {
  const fixturePath = path.resolve(__dirname, "../../../../fixtures/nextjs-vibecoded-bad-app");

  it("should discover expected files and respect ignores", async () => {
    const discovery = new FileDiscovery(fixturePath);
    const files = await discovery.discoverFiles();

    // Normalizing paths for cross-platform comparison
    const normalizedFiles = files.map(f => f.replace(/\\/g, "/"));

    expect(normalizedFiles).toContain("package.json");
    expect(normalizedFiles).toContain("next.config.js");
    expect(normalizedFiles).toContain(".env");
    expect(normalizedFiles).toContain("app/page.tsx");
    expect(normalizedFiles).toContain("app/api/admin/route.ts");
    expect(normalizedFiles).toContain("app/dashboard/page.tsx");
    expect(normalizedFiles).toContain("lib/supabase.ts");

    // Excluded files/dirs
    expect(normalizedFiles).toContain(".gitignore"); // .gitignore is in SCANNABLE_FILENAMES
    expect(normalizedFiles).toContain(".gitignore");

    // Excluded by default dirs
    expect(normalizedFiles).not.toContain("node_modules/fake-module/index.js");
    expect(normalizedFiles).not.toContain(".next/build-manifest.json");
  });

  it("should respect additional excludes", async () => {
    const discovery = new FileDiscovery(fixturePath);
    const files = await discovery.discoverFiles(["app/**"]);
    const normalizedFiles = files.map(f => f.replace(/\\/g, "/"));

    expect(normalizedFiles).not.toContain("app/page.tsx");
    expect(normalizedFiles).toContain("lib/supabase.ts");
  });
});
