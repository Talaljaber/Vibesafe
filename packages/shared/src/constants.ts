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
] as const;

/**
 * Directories always excluded from scanning.
 * Never scan these — includes node_modules, build outputs, VCS, and caches.
 */
export const ALWAYS_EXCLUDED_DIRS = [
  "node_modules",
  ".git",
  ".svn",
  "dist",
  "build",
  "out",
  ".next",
  ".nuxt",
  ".turbo",
  ".vercel",
  "coverage",
  ".nyc_output",
  "storybook-static",
  ".cache",
  "tmp",
  "temp",
] as const;

// ─── Finding ID Prefixes ──────────────────────────────────────────────────────

/**
 * Category-to-prefix mapping for finding IDs.
 * e.g., a secret finding gets ID "SEC-001-a1b2"
 */
export const CATEGORY_PREFIX: Record<FindingCategory, string> = {
  secret: "SEC",
  auth: "AUTH",
  authorization: "AUTHZ",
  frontend_exposure: "EXPO",
  validation: "VAL",
  dependency: "DEP",
  code_quality: "QUAL",
  structure: "STRUCT",
};

// ─── Version ──────────────────────────────────────────────────────────────────

export const VIBESAFE_VERSION = "0.1.0";

// ─── Branding ─────────────────────────────────────────────────────────────────

export const PRODUCT_NAME = "VibeSafe";
export const PRODUCT_TAGLINE = "The don't-deploy-that-yet tool for vibe-coded apps.";
