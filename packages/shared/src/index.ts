// ─────────────────────────────────────────────────────────────────────────────
// @vibesafe/shared — Public API
//
// All types, constants, and utilities exported from this package.
// Other packages import ONLY from "@vibesafe/shared", never from sub-paths.
// ─────────────────────────────────────────────────────────────────────────────

// Types — the source of truth for all interfaces
export type {
  AutoFixer,
  Confidence,
  Detector,
  DeployStatus,
  Finding,
  FindingCategory,
  FixPreview,
  FixResult,
  ProjectContext,
  RepairPlan,
  RepairStep,
  ScanConfig,
  ScanContext,
  ScanResult,
  ScanSummary,
  Severity,
} from "./types.js";

// Constants
export {
  ALWAYS_EXCLUDED_DIRS,
  CATEGORY_PREFIX,
  DEFAULT_MAX_FILES,
  DEFAULT_MIN_SEVERITY,
  DEFAULT_SCAN_TIMEOUT_MS,
  PRODUCT_NAME,
  PRODUCT_TAGLINE,
  SCANNABLE_EXTENSIONS,
  SCANNABLE_FILENAMES,
  VIBESAFE_VERSION,
} from "./constants.js";

// Severity utilities
export {
  CATEGORY_MULTIPLIERS,
  DEPLOY_STATUS_LABEL,
  DEPLOY_STATUS_MESSAGE,
  SEVERITY_LABEL,
  SEVERITY_LEVELS,
  SEVERITY_RANK,
  SEVERITY_WEIGHTS,
  getDeployStatus,
  isMoreSevere,
  maxSeverity,
} from "./severity.js";
