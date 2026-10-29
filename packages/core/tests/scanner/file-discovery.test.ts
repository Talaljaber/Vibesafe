import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { FileDiscovery, type SkipReason } from "../../src/scanner/file-discovery.js";
import { ScannerPipeline } from "../../src/scanner/pipeline.js";
import { createDefaultRegistry } from "../../src/scanner/detector-registry.js";
import { SecretDetector } from "../../src/detectors/secret-detector.js";
import { FrontendExposureDetector } from "../../src/detectors/frontend-exposure-detector.js";

describe("FileDiscovery", () => {
  const fixturePath = path.resolve(__dirname, "../../../../fixtures/nextjs-vibecoded-bad-app");

  it("should discover expected files and respect ignores", async () => {
    const discovery = new FileDiscovery(fixturePath);
    const files = await discovery.discoverFiles();

    // Normalizing paths for cross-platform comparison
    const normalizedFiles = files.map((f) => f.replace(/\\/g, "/"));

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
    const normalizedFiles = files.map((f) => f.replace(/\\/g, "/"));

    expect(normalizedFiles).not.toContain("app/page.tsx");
    expect(normalizedFiles).toContain("lib/supabase.ts");
  });
});

describe("FileDiscovery onSkipped and the pipeline's not-scanned warning", () => {
  let root: string;

  beforeAll(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), "vibesafe-skipped-"));
    const files: Record<string, string> = {
      ".gitignore": ".env\n.env.local\nsecret-notes.md\nlogs/\n",
      ".env": "A=1\n",
      ".env.local": "B=2\n",
      ".env.example": "A=\n",
      "README.md": "# app\n",
      "netlify.toml": "[build]\n",
      "index.html": "<html></html>\n",
      "secret-notes.md": "x\n",
      "docs/guide.md": "# guide\n",
      "logs/app.log": "x\n",
      "excluded/thing.toml": "x\n",
      "app.ts": "export const a = 1;\n",
      "node_modules/pkg/README.md": "x\n",
    };
    for (const [rel, content] of Object.entries(files)) {
      const full = path.join(root, rel);
      await fs.mkdir(path.dirname(full), { recursive: true });
      await fs.writeFile(full, content);
    }
  });

  afterAll(async () => {
    await fs.rm(root, { recursive: true, force: true });
  });

  it("reports gitignored and unscannable files, not excluded ones", async () => {
    const skipped: [string, SkipReason][] = [];
    const found = await new FileDiscovery(root).discoverFiles(["excluded/**"], {
      onSkipped: (file, reason) => skipped.push([file.replace(/\\/g, "/"), reason]),
    });
    expect(found.map((f) => f.replace(/\\/g, "/")).sort()).toEqual(
      [".env.example", ".gitignore", "app.ts"].sort(),
    );
    const map = new Map(skipped);
    expect(map.get(".env")).toBe("gitignored");
    expect(map.get(".env.local")).toBe("gitignored");
    expect(map.get("secret-notes.md")).toBe("gitignored");
    expect(map.get("logs/app.log")).toBe("gitignored");
    expect(map.get("README.md")).toBe("unscannable-type");
    expect(map.get("docs/guide.md")).toBe("unscannable-type");
    expect(map.has("excluded/thing.toml")).toBe(false);
    expect(map.has("node_modules/pkg/README.md")).toBe(false);
  });

  it("adds one warning naming gitignored env files and root md/toml/html files", async () => {
    const result = await new ScannerPipeline(createDefaultRegistry()).scan({
      rootPath: root,
      useConfigFile: false,
    });
    const warnings = (result.warnings ?? []).filter((w) => w.startsWith("Not scanned:"));
    expect(warnings).toHaveLength(1);
    const w = warnings[0]!;
    expect(w).toContain("2 gitignored env file(s) (.env, .env.local)");
    expect(w).toContain("3 root file(s) of unsupported types");
    for (const name of ["README.md", "netlify.toml", "index.html"]) expect(w).toContain(name);
    expect(w).not.toContain("docs/guide.md");
    expect(w).not.toContain("secret-notes.md");
  });

  it("adds no warning when targetFiles are given", async () => {
    const result = await new ScannerPipeline(createDefaultRegistry()).scan({
      rootPath: root,
      useConfigFile: false,
      targetFiles: ["app.ts"],
    });
    expect((result.warnings ?? []).some((w) => w.startsWith("Not scanned:"))).toBe(false);
  });
});

describe("secret and frontend-exposure detectors on infrastructure files", () => {
  const createContext = (files: Record<string, string>): ScanContext => ({
    rootPath: "/fake",
    projectContext: {
      framework: "nextjs",
      language: "typescript",
      hasTypeScript: true,
      packageManager: "npm",
      dependencies: {},
      devDependencies: {},
      scripts: {},
      hasGitignore: true,
      hasEnvFile: false,
      hasEnvExample: false,
      hasReadme: true,
      hasTests: false,
    },
    files: Object.keys(files),
    config: { rootPath: "/fake" },
    readFile: async (f) => files[f] ?? "",
  });

  /** Realistic, secret-free infrastructure files full of secret-ish names and references. */
  const SAMPLES: Record<string, string> = {
    Dockerfile: [
      "FROM node:20-alpine AS build",
      "ARG NEXT_PUBLIC_SUPABASE_URL",
      "ARG NEXT_PUBLIC_SUPABASE_ANON_KEY",
      "ENV NEXT_PUBLIC_SUPABASE_ANON_KEY=$NEXT_PUBLIC_SUPABASE_ANON_KEY",
      "RUN --mount=type=secret,id=npm_token NPM_TOKEN=$(cat /run/secrets/npm_token) npm ci",
      "ENV STRIPE_SECRET_KEY=${STRIPE_SECRET_KEY}",
      "USER node",
    ].join("\n"),
    "docker-compose.yml": [
      "services:",
      "  db:",
      "    image: postgres:16",
      "    environment:",
      "      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}",
      "      POSTGRES_PASSWORD_FILE: /run/secrets/pg_password",
      "  app:",
      "    environment:",
      "      DATABASE_URL: postgres://app:${POSTGRES_PASSWORD}@db:5432/app",
      "      SUPABASE_SERVICE_ROLE_KEY: ${SUPABASE_SERVICE_ROLE_KEY}",
      "      NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY: ${NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY}",
    ].join("\n"),
    ".github/workflows/ci.yml": [
      "on: push",
      "jobs:",
      "  build:",
      "    steps:",
      "      - run: npm run build",
      "        env:",
      "          SUPABASE_SERVICE_ROLE_KEY: ${{ secrets.SUPABASE_SERVICE_ROLE_KEY }}",
      "          STRIPE_SECRET_KEY: ${{ secrets.STRIPE_SECRET_KEY }}",
      "          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
      "          NEXT_PUBLIC_SUPABASE_ANON_KEY: ${{ vars.NEXT_PUBLIC_SUPABASE_ANON_KEY }}",
    ].join("\n"),
    "scripts/deploy.sh": [
      "#!/usr/bin/env bash",
      "set -euo pipefail",
      ': "${STRIPE_SECRET_KEY:?STRIPE_SECRET_KEY must be set}"',
      'flyctl secrets set STRIPE_SECRET_KEY="${STRIPE_SECRET_KEY}" --stage',
      'echo "$GH_TOKEN" | gh auth login --with-token',
    ].join("\n"),
  };

  it("the secret detector adds no findings", async () => {
    expect(await new SecretDetector().detect(createContext(SAMPLES))).toEqual([]);
  });

  it("the frontend-exposure detector adds no findings", async () => {
    expect(await new FrontendExposureDetector().detect(createContext(SAMPLES))).toEqual([]);
  });
});
