import type { ScanConfig, FindingCategory } from "@vibeguard/shared";
import { DEFAULT_MAX_FILES, DEFAULT_MIN_SEVERITY, DEFAULT_SCAN_TIMEOUT_MS } from "@vibeguard/shared";

const ALL_CATEGORIES: FindingCategory[] = [
  "secret",
  "auth",
  "authorization",
  "frontend_exposure",
  "validation",
  "dependency",
  "code_quality",
  "structure",
];

/**
 * Default configuration for VibeGuard scanner.
 */
export const DEFAULT_CONFIG: Omit<ScanConfig, "rootPath"> = {
  enabledCategories: ALL_CATEGORIES,
  minSeverity: DEFAULT_MIN_SEVERITY,
  excludePatterns: [],
  maxFiles: DEFAULT_MAX_FILES,
  timeoutMs: DEFAULT_SCAN_TIMEOUT_MS,
};

/**
 * Merges a partial config with defaults.
 */
export function mergeConfig(rootPath: string, userConfig?: Partial<ScanConfig>): ScanConfig {
  return {
    rootPath,
    enabledCategories: userConfig?.enabledCategories ?? DEFAULT_CONFIG.enabledCategories,
    minSeverity: userConfig?.minSeverity ?? DEFAULT_CONFIG.minSeverity,
    excludePatterns: userConfig?.excludePatterns ?? DEFAULT_CONFIG.excludePatterns,
    maxFiles: userConfig?.maxFiles ?? DEFAULT_CONFIG.maxFiles,
    timeoutMs: userConfig?.timeoutMs ?? DEFAULT_CONFIG.timeoutMs,
  };
}
