// ─────────────────────────────────────────────────────────────────────────────
// VibeSafe — Shared Constants
// ─────────────────────────────────────────────────────────────────────────────

import type { FindingCategory, Severity } from "./types.js";

// ─── Scanner Defaults ─────────────────────────────────────────────────────────

/** Default timeout for a full scan in milliseconds. */
export const DEFAULT_SCAN_TIMEOUT_MS = 30_000;

/** Default maximum number of files to scan. Prevents hangs on huge repos. */
export const DEFAULT_MAX_FILES = 5_000;

/** Default minimum severity to include in results. */
export const DEFAULT_MIN_SEVERITY: Severity = "low";

// ─── File Discovery ───────────────────────────────────────────────────────────

/** File extensions that the scanner considers for analysis. */
export const SCANNABLE_EXTENSIONS = [
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".json",
  ".sql",
  ".py",
] as const;

/** File name patterns that are always included regardless of extension. */
export const SCANNABLE_FILENAMES = [
  ".env",
  ".env.local",
  ".env.example",
  ".env.sample",
  ".env.development",
  ".env.production",
  ".env.staging",
  ".gitignore",
  ".dockerignore",
  "package.json",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "requirements.txt",
  "pyproject.toml",
  "Pipfile",
  "manage.py",
] as const;

/**
 * Python requirements files, which are also scanned: `requirements*.txt` anywhere, or
 * any `.txt` file inside a `requirements/` directory (e.g. `requirements/prod.txt`).
 */
export function isPythonRequirementsFile(relativePath: string): boolean {
  const p = relativePath.replace(/\\/g, "/");
  return /(^|\/)requirements[\w.-]*\.txt$/i.test(p) || /(^|\/)requirements\/[^/]+\.txt$/i.test(p);
}

/** Kinds of `.env`-style files, see {@link classifyEnvFileName}. */
export type EnvFileKind = "env" | "env-example" | "env-vault";

const ENV_TEMPLATE_SUFFIXES = [".example", ".sample", ".template", ".dist"] as const;

/**
 * Classifies a file NAME (basename, not a path) as an env file. The single source of
 * truth for env naming across the scanner:
 * - `"env"`: `.env` or `.env.<anything>` holding real values (`.env.local`, `.env.staging2`);
 * - `"env-example"`: a committed template ending in `.example`, `.sample`, `.template` or `.dist`;
 * - `"env-vault"`: `.env.vault` (dotenv-vault ciphertext, meant to be committed);
 * - `null`: anything else, including `.envrc` (direnv shell script) and `.env.` with no suffix.
 */
export function classifyEnvFileName(name: string): EnvFileKind | null {
  if (name === ".env") return "env";
  if (!name.startsWith(".env.") || name.length === ".env.".length) return null;
  if (name === ".env.vault") return "env-vault";
  const lower = name.toLowerCase();
  if (ENV_TEMPLATE_SUFFIXES.some((suffix) => lower.endsWith(suffix))) return "env-example";
  return "env";
}

const DOCKERFILE_RE =
  /^(?:dockerfile|containerfile)(?:\.[\w.-]+)?$|^[\w.-]+\.(?:dockerfile|containerfile)$/i;
/** `Dockerfile.ts` or `dockerfile.json` are source/data files, not Dockerfiles. */
const NOT_DOCKERFILE_EXT_RE = /\.(?:[cm]?[jt]sx?|json|py|md|txt|ya?ml|toml|lock)$/i;
const COMPOSE_RE = /^(?:docker-)?compose(?:\.[\w-]+)*\.ya?ml$/i;
const WORKFLOW_RE = /(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/;
const ACTION_RE = /^action\.ya?ml$/;
const SHELL_RE = /\.(?:sh|bash|zsh)$/;
const TERRAFORM_RE = /\.tf$/i;
const TFVARS_RE = /\.tfvars$/i;
const K8S_YAML_RE = /\.ya?ml$/i;
const KUSTOMIZATION_RE = /^kustomization\.ya?ml$/i;
/** Directory names that hold Kubernetes manifests (matched case-insensitively). */
const K8S_DIRS: ReadonlySet<string> = new Set([
  "k8s",
  "kubernetes",
  "kube",
  "manifests",
  "deploy",
  "deployments",
  "kustomize",
  "overlays",
  "base",
  "helm",
  "charts",
  "templates",
  "argocd",
  "gitops",
  "openshift",
]);

function isK8sManifestPath(p: string, base: string): boolean {
  if (!K8S_YAML_RE.test(base)) return false;
  if (KUSTOMIZATION_RE.test(base)) return true;
  const segments = p.split("/");
  segments.pop();
  if (segments.includes(".github")) return false;
  return segments.some((s) => K8S_DIRS.has(s.toLowerCase()));
}

/** Kinds of infrastructure file, see {@link classifyInfraFile}. */
export type InfraFileKind =
  | "dockerfile"
  | "dockerignore"
  | "compose"
  | "workflow"
  | "gh-action"
  | "shell"
  | "terraform"
  | "tfvars"
  | "k8s-manifest"
  | EnvFileKind
  | "next-config-mts";

/**
 * Classifies infrastructure and deployment files that are scanned even though their
 * extension is not in SCANNABLE_EXTENSIONS: Dockerfile/Containerfile forms
 * (`Dockerfile`, `Dockerfile.prod`, `api.Dockerfile`), `.dockerignore`, compose files
 * (`docker-compose*.yml`, `compose*.yaml`), GitHub workflow files (directly under
 * `.github/workflows/`), composite `action.yml`, shell scripts (`.sh .bash .zsh`), env
 * files of every kind (see classifyEnvFileName), `next.config.mts`, Terraform
 * (`*.tf`, `*.tfvars`, `*.auto.tfvars`) and Kubernetes manifests (YAML under a
 * `k8s/`, `kubernetes/`, `manifests/`, `deploy/`, `helm/`, ... directory, or
 * `kustomization.yaml`; whether a file really is a manifest is decided by content).
 * Returns null for everything else (e.g. `pnpm-lock.yaml`,
 * `.github/ISSUE_TEMPLATE/bug.yml`, `config.yml`, `openapi.yaml`, `.envrc`). Accepts `/` or `\` separators.
 */
export function classifyInfraFile(relativePath: string): InfraFileKind | null {
  const p = relativePath.replace(/\\/g, "/");
  const base = p.slice(p.lastIndexOf("/") + 1);
  const env = classifyEnvFileName(base);
  if (env !== null) return env;
  if (base === ".dockerignore") return "dockerignore";
  if (WORKFLOW_RE.test(p)) return "workflow";
  if (ACTION_RE.test(base)) return "gh-action";
  if (COMPOSE_RE.test(base)) return "compose";
  if (DOCKERFILE_RE.test(base) && !NOT_DOCKERFILE_EXT_RE.test(base)) return "dockerfile";
  if (SHELL_RE.test(base)) return "shell";
  if (base === "next.config.mts") return "next-config-mts";
  if (TERRAFORM_RE.test(base)) return "terraform";
  if (TFVARS_RE.test(base)) return "tfvars";
  if (!(LOCKFILE_NAMES as readonly string[]).includes(base) && isK8sManifestPath(p, base)) {
    return "k8s-manifest";
  }
  return null;
}

/** True when {@link classifyInfraFile} recognises the path. File discovery admits these. */
export function isInfraFile(relativePath: string): boolean {
  return classifyInfraFile(relativePath) !== null;
}

/** Lockfile names read with the larger {@link MAX_LOCKFILE_SIZE_BYTES} limit. */
export const LOCKFILE_NAMES = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock"] as const;

/** True when the path's basename is one of {@link LOCKFILE_NAMES}. */
export function isLockfileName(relativePath: string): boolean {
  const p = relativePath.replace(/\\/g, "/");
  return (LOCKFILE_NAMES as readonly string[]).includes(p.slice(p.lastIndexOf("/") + 1));
}

/**
 * Directories excluded at ANY depth (dependency, VCS and tool-cache dirs whose
 * names are unambiguous).
 */
export const ALWAYS_EXCLUDED_ANYWHERE_DIRS = [
  "node_modules",
  ".git",
  ".svn",
  ".next",
  ".nuxt",
  ".turbo",
  ".vercel",
  ".nyc_output",
  "storybook-static",
  ".cache",
  "__pycache__",
  ".venv",
  "venv",
  "site-packages",
  ".tox",
  ".mypy_cache",
  ".pytest_cache",
  ".ruff_cache",
  ".eggs",
  ".terraform",
  ".terragrunt-cache",
] as const;

/**
 * Generic build-output directory names. These are only excluded at the project
 * root or at a workspace-package root (see WORKSPACE_PACKAGE_CONTAINERS), so a
 * source folder such as `src/lib/build/` or `src/out/` is still scanned.
 */
export const ROOT_ANCHORED_EXCLUDED_DIRS = [
  "dist",
  "build",
  "out",
  "coverage",
  "tmp",
  "temp",
] as const;

/** Directories whose immediate children are workspace packages. */
export const WORKSPACE_PACKAGE_CONTAINERS = [
  "packages",
  "apps",
  "libs",
  "services",
  "examples",
] as const;

/**
 * Every directory name treated as excluded somewhere (union of the two lists
 * above). Prefer buildExcludedDirGlobs() for the scoping rules.
 */
export const ALWAYS_EXCLUDED_DIRS = [
  ...ALWAYS_EXCLUDED_ANYWHERE_DIRS,
  ...ROOT_ANCHORED_EXCLUDED_DIRS,
] as const;

/**
 * Glob patterns (gitignore/fast-glob compatible) for the default directory
 * exclusions: dependency/VCS dirs at any depth, build-ish dirs only at the
 * root or a workspace-package root.
 */
export function buildExcludedDirGlobs(): string[] {
  const globs: string[] = [];
  for (const dir of ALWAYS_EXCLUDED_ANYWHERE_DIRS) globs.push(`**/${dir}/**`);
  const containers = `{${WORKSPACE_PACKAGE_CONTAINERS.join(",")}}`;
  for (const dir of ROOT_ANCHORED_EXCLUDED_DIRS) {
    globs.push(`${dir}/**`);
    globs.push(`${containers}/*/${dir}/**`);
  }
  return globs;
}

/**
 * Test and fixture paths excluded by default (opt in with ScanConfig.includeTests).
 * `fixtures/**` is anchored at the scan root.
 */
export const TEST_PATH_GLOBS = [
  "**/tests/**",
  "**/__tests__/**",
  "**/*.test.*",
  "**/*.spec.*",
  "**/test/**",
  "**/test_*.py",
  "**/*_test.py",
  "**/conftest.py",
  "fixtures/**",
] as const;

/** Files larger than this are skipped by the scanner (with a warning). */
export const MAX_FILE_SIZE_BYTES = 1_000_000;

/** Lockfiles (see LOCKFILE_NAMES) are read up to this size; larger ones read as empty. */
export const MAX_LOCKFILE_SIZE_BYTES = 8_000_000;

// ─── Finding ID Prefixes ──────────────────────────────────────────────────────

/**
 * Category-to-prefix mapping for finding IDs.
 * e.g., a secret finding gets ID "SEC-1a2b3c"
 */
export const CATEGORY_PREFIX: Record<FindingCategory, string> = {
  secret: "SEC",
  auth: "AUTH",
  authorization: "AUTHZ",
  frontend_exposure: "FE",
  validation: "VAL",
  dependency: "DEP",
  code_quality: "QUAL",
  structure: "STRUCT",
  xss: "XSS",
  security_config: "CFG",
  injection: "INJ",
  crypto: "CRYPTO",
};

/** Every finding category (single source of truth; derived from CATEGORY_PREFIX). */
export const ALL_CATEGORIES = Object.keys(CATEGORY_PREFIX) as FindingCategory[];

// ─── Version ──────────────────────────────────────────────────────────────────

export const VIBESAFE_VERSION = "0.4.0";

// ─── Branding ─────────────────────────────────────────────────────────────────

export const PRODUCT_NAME = "VibeSafe";
export const PRODUCT_TAGLINE = "The don't-deploy-that-yet tool for vibe-coded apps.";
