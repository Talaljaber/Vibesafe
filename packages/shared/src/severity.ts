// ─────────────────────────────────────────────────────────────────────────────
// VibeGuard — Severity Utilities
//
// Helper functions and mappings for working with severity levels.
// ─────────────────────────────────────────────────────────────────────────────

import type { DeployStatus, FindingCategory, Severity } from "./types.js";

// ─── Severity Order ───────────────────────────────────────────────────────────

/** Numeric rank for sorting — lower number = more severe */
export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

/** All severity levels ordered from most to least severe */
export const SEVERITY_LEVELS: Severity[] = ["critical", "high", "medium", "low"];

// ─── Scoring Weights ─────────────────────────────────────────────────────────

/**
 * Points deducted from the base score (100) per finding at this severity.
 * These are the raw weights before category multipliers are applied.
 */
export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: -20,
  high: -10,
  medium: -5,
  low: -2,
};

/**
 * Per-category multipliers applied to severity weights.
 * Security issues (secrets, auth) penalize the score harder than quality issues.
 */
export const CATEGORY_MULTIPLIERS: Record<FindingCategory, number> = {
  secret: 1.5,
  frontend_exposure: 1.3,
  auth: 1.2,
  authorization: 1.1,
  validation: 1.0,
  dependency: 0.8,
  code_quality: 0.5,
  structure: 0.3,
};

// ─── Deploy Status Thresholds ────────────────────────────────────────────────

/**
 * Derive the human-readable deploy status from a score and whether any
 * findings are critical (which always triggers "blocker" regardless of score).
 */
export function getDeployStatus(score: number, hasCritical: boolean): DeployStatus {
  if (hasCritical) return "blocker";
  if (score < 40) return "danger";
  if (score < 70) return "warning";
  return "safe";
}

// ─── Deploy Status Display ───────────────────────────────────────────────────

export const DEPLOY_STATUS_LABEL: Record<DeployStatus, string> = {
  blocker: "❌ DO NOT DEPLOY",
  danger: "❌ DO NOT DEPLOY",
  warning: "⚠️  FIX BEFORE PRODUCTION",
  safe: "✅ READY TO DEPLOY",
};

export const DEPLOY_STATUS_MESSAGE: Record<DeployStatus, string> = {
  blocker: "Critical security issues found. Fix these before shipping.",
  danger: "Significant issues need attention before deployment.",
  warning: "Several issues should be addressed before going live.",
  safe: "Looking good! Minor improvements suggested.",
};

// ─── Severity Display ────────────────────────────────────────────────────────

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "🔴 Critical",
  high: "🟠 High",
  medium: "🟡 Medium",
  low: "🔵 Low",
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Returns true if severity A is more severe than severity B. */
export function isMoreSevere(a: Severity, b: Severity): boolean {
  return SEVERITY_RANK[a] < SEVERITY_RANK[b];
}

/** Returns the more severe of two severity levels. */
export function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_RANK[a] <= SEVERITY_RANK[b] ? a : b;
}
