import { describe, it, expect } from "vitest";
import {
  MAX_FILE_SIZE_BYTES,
  MAX_LOCKFILE_SIZE_BYTES,
  SCANNABLE_FILENAMES,
  classifyEnvFileName,
  classifyInfraFile,
  isInfraFile,
  isLockfileName,
} from "../src/index.js";

describe("classifyEnvFileName", () => {
  it.each([
    [".env", "env"],
    [".env.local", "env"],
    [".env.production", "env"],
    [".env.staging2", "env"],
    [".env.development.local", "env"],
    [".env.example", "env-example"],
    [".env.sample", "env-example"],
    [".env.template", "env-example"],
    [".env.dist", "env-example"],
    [".env.production.example", "env-example"],
    [".env.EXAMPLE", "env-example"],
    [".env.vault", "env-vault"],
  ])("%s -> %s", (name, kind) => {
    expect(classifyEnvFileName(name)).toBe(kind);
  });

  it.each([".envrc", ".env.", "env", "env.example", ".environment", "x.env", ".env-local", ""])(
    "%s is not an env file",
    (name) => {
      expect(classifyEnvFileName(name)).toBeNull();
    },
  );
});

describe("classifyInfraFile / isInfraFile", () => {
  it.each([
    ["Dockerfile", "dockerfile"],
    ["docker/Dockerfile", "dockerfile"],
    ["Dockerfile.prod", "dockerfile"],
    ["api.Dockerfile", "dockerfile"],
    ["web.dockerfile", "dockerfile"],
    ["Containerfile", "dockerfile"],
    ["services\\api\\Dockerfile", "dockerfile"],
    [".dockerignore", "dockerignore"],
    ["docker-compose.yml", "compose"],
    ["docker-compose.yaml", "compose"],
    ["docker-compose.prod.yml", "compose"],
    ["compose.yaml", "compose"],
    ["deploy/compose.override.yml", "compose"],
    [".github/workflows/ci.yml", "workflow"],
    [".github/workflows/deploy.yaml", "workflow"],
    [".github\\workflows\\release.yml", "workflow"],
    ["action.yml", "gh-action"],
    [".github/actions/setup/action.yaml", "gh-action"],
    ["scripts/deploy.sh", "shell"],
    ["install.bash", "shell"],
    ["tools/env.zsh", "shell"],
    [".env", "env"],
    ["apps/api/.env.staging2", "env"],
    [".env.example", "env-example"],
    [".env.vault", "env-vault"],
    ["next.config.mts", "next-config-mts"],
    ["apps/web/next.config.mts", "next-config-mts"],
    ["infra/main.tf", "terraform"],
    ["main.TF", "terraform"],
    ["infra\\terraform\\rds.tf", "terraform"],
    ["prod.tfvars", "tfvars"],
    ["infra/env.auto.tfvars", "tfvars"],
    ["infra/k8s/app.yaml", "k8s-manifest"],
    ["deploy/web.yml", "k8s-manifest"],
    ["charts/app/templates/ingress.yaml", "k8s-manifest"],
    ["Kubernetes/web.yaml", "k8s-manifest"],
    ["gitops/apps/app.yaml", "k8s-manifest"],
    ["overlays/prod/patch.yaml", "k8s-manifest"],
    ["kustomization.yaml", "k8s-manifest"],
    ["app/kustomization.yml", "k8s-manifest"],
    ["deploy/docker-compose.yml", "compose"],
    [".github/workflows/deploy.yaml", "workflow"],
  ])("%s -> %s", (p, kind) => {
    expect(classifyInfraFile(p)).toBe(kind);
    expect(isInfraFile(p)).toBe(true);
  });

  it.each([
    "pnpm-lock.yaml",
    ".github/ISSUE_TEMPLATE/bug.yml",
    ".github/dependabot.yml",
    ".github/workflows/nested/x.yml",
    ".github/workflows/templates/build.yml",
    ".github/deploy/x.yml",
    ".github/actions/deploy/inputs.yml",
    "config.yml",
    ".envrc",
    "Dockerfile.ts",
    "dockerfile.json",
    "Dockerfile.md",
    "next.config.js",
    "src/compose.ts",
    "README.md",
    "app/page.tsx",
    "scripts/sh",
    "openapi.yaml",
    "mkdocs.yml",
    ".gitlab-ci.yml",
    "src/i18n/en.yaml",
    "docs/api/spec.yaml",
    "infra/terraform.tfstate",
    "infra/prod.tfvars.json",
    "infra/.terraform.lock.hcl",
    "deploy/pnpm-lock.yaml",
    "k8s/notes.md",
    "deploy/app.json",
  ])("%s is not an infra file", (p) => {
    expect(classifyInfraFile(p)).toBeNull();
    expect(isInfraFile(p)).toBe(false);
  });
});

describe("lockfiles and discovery names", () => {
  it("recognises lockfile names at any depth", () => {
    expect(isLockfileName("package-lock.json")).toBe(true);
    expect(isLockfileName("apps/web/pnpm-lock.yaml")).toBe(true);
    expect(isLockfileName("a\\yarn.lock")).toBe(true);
    expect(isLockfileName("package.json")).toBe(false);
    expect(isLockfileName("my-yarn.lock")).toBe(false);
  });

  it("reads lockfiles with a larger budget", () => {
    expect(MAX_LOCKFILE_SIZE_BYTES).toBe(8_000_000);
    expect(MAX_LOCKFILE_SIZE_BYTES).toBeGreaterThan(MAX_FILE_SIZE_BYTES);
  });

  it("discovers .dockerignore by name", () => {
    expect(SCANNABLE_FILENAMES).toContain(".dockerignore");
  });
});

describe("firebase rules file name regex", () => {
  it("does not backtrack on adversarial names", async () => {
    const { classifyInfraFile } = await import("../src/constants.js");
    const name = "firestore" + "-a".repeat(120) + "!";
    const t0 = Date.now();
    classifyInfraFile(name);
    expect(Date.now() - t0).toBeLessThan(200);
  });
});
