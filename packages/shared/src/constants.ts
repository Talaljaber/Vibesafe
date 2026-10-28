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
  "package.json",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "requirements.txt",
  "pyproject.toml",
  "manage.py",
] as const;

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
  "fixtures/**",
] as const;

/** Files larger than this are skipped by the scanner (with a warning). */
export const MAX_FILE_SIZE_BYTES = 1_000_000;

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
};

// ─── Version ──────────────────────────────────────────────────────────────────

export const VIBESAFE_VERSION = "0.1.5";

// ─── Branding ─────────────────────────────────────────────────────────────────

export const PRODUCT_NAME = "VibeSafe";
export const PRODUCT_TAGLINE = "The don't-deploy-that-yet tool for vibe-coded apps.";
