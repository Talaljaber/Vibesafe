import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { ProjectContext, ScanContext } from "@talaljaber/vibesafe-shared";
import { FileDiscovery } from "../../src/scanner/file-discovery.js";
import { SecretDetector } from "../../src/detectors/secret-detector.js";
import { FrontendExposureDetector } from "../../src/detectors/frontend-exposure-detector.js";
import { SecurityHeadersDetector } from "../../src/detectors/security-headers-detector.js";

const PROJECT: ProjectContext = {
  framework: "nextjs",
  language: "typescript",
  hasTypeScript: true,
  packageManager: "npm",
  dependencies: {},
  devDependencies: {},
  scripts: {},
  hasGitignore: true,
  hasEnvFile: true,
  hasEnvExample: false,
  hasReadme: true,
  hasTests: false,
};

const createContext = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake",
  projectContext: PROJECT,
  files: Object.keys(files),
  config: { rootPath: "/fake" },
  readFile: async (f) => files[f] ?? "",
});

describe("discovery of infrastructure files", () => {
  let root: string;

  const write = async (rel: string, content = "x\n"): Promise<void> => {
    const full = path.join(root, rel);
    await fs.mkdir(path.dirname(full), { recursive: true });
    await fs.writeFile(full, content);
  };

  beforeAll(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), "vibesafe-infra-"));
    for (const f of [
      "Dockerfile",
      "docker/api.Dockerfile",
      "Containerfile",
      ".dockerignore",
      "docker-compose.yml",
      "compose.prod.yaml",
      ".github/workflows/ci.yml",
      ".github/workflows/release.yaml",
      "action.yml",
      "scripts/deploy.sh",
      "tools/setup.zsh",
      ".env.staging2",
      ".env.dist",
      ".env.vault",
      ".env.local",
      "next.config.mts",
      // non-matches
      "pnpm-lock.yaml",
      ".github/ISSUE_TEMPLATE/bug.yml",
      ".github/dependabot.yml",
      "config.yml",
      ".envrc",
      "README.md",
      "node_modules/pkg/install.sh",
      "dist/Dockerfile",
    ]) {
      await write(f);
    }
    await write(".gitignore", ".env.local\nsecret.sh\n");
    await write("secret.sh");
  });

  afterAll(async () => {
    await fs.rm(root, { recursive: true, force: true });
  });

  it("admits infra kinds, skips non-matches, excluded dirs and gitignored files", async () => {
    const found = (await new FileDiscovery(root).discoverFiles())
      .map((f) => f.replace(/\\/g, "/"))
      .sort();
    expect(found).toEqual(
      [
        ".dockerignore",
        ".env.dist",
        ".env.staging2",
        ".env.vault",
        ".github/workflows/ci.yml",
        ".github/workflows/release.yaml",
        ".gitignore",
        "Containerfile",
        "Dockerfile",
        "action.yml",
        "compose.prod.yaml",
        "docker-compose.yml",
        "docker/api.Dockerfile",
        "next.config.mts",
        "pnpm-lock.yaml",
        "scripts/deploy.sh",
        "tools/setup.zsh",
      ].sort(),
    );
  });
});

describe("existing detectors on the new file kinds", () => {
  it("secret/env-not-ignored only targets real env files (not templates or vault files)", async () => {
    const findings = await new SecretDetector().detect(
      createContext({
        ".gitignore": "node_modules\n",
        ".env.staging2": "A=1\n",
        ".env.dist": "A=\n",
        ".env.template": "A=\n",
        ".env.vault": "DOTENV_VAULT_PRODUCTION=encrypted\n",
        ".env.example": "A=\n",
      }),
    );
    const flagged = findings
      .filter((f) => f.ruleId === "secret/env-not-ignored")
      .map((f) => f.file);
    expect(flagged).toEqual([".env.staging2"]);
  });

  it("frontend exposure reads real env files only", async () => {
    const line = "NEXT_PUBLIC_STRIPE_SECRET_KEY=x\n";
    const findings = await new FrontendExposureDetector().detect(
      createContext({
        ".env.staging2": line,
        ".env.template": line,
        ".env.dist": line,
        ".env.vault": line,
        ".envrc": `export ${line}`,
      }),
    );
    expect(findings.map((f) => f.file)).toEqual([".env.staging2"]);
  });

  it("security headers never treats next.config.mts as an Express app", async () => {
    const findings = await new SecurityHeadersDetector().detect(
      createContext({
        "next.config.mts":
          "import express from 'express';\nconst app = express();\nexport default {};\n",
      }),
    );
    expect(findings).toEqual([]);
  });
});
