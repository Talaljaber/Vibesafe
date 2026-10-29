import type { ScanConfig } from "@talaljaber/vibesafe-shared";
import {
  ALL_CATEGORIES,
  DEFAULT_MAX_FILES,
  DEFAULT_MIN_SEVERITY,
  DEFAULT_SCAN_TIMEOUT_MS,
} from "@talaljaber/vibesafe-shared";

/**
 * Default configuration for VibeSafe scanner.
 */
export const DEFAULT_CONFIG: Omit<ScanConfig, "rootPath"> = {
  enabledCategories: ALL_CATEGORIES,
  minSeverity: DEFAULT_MIN_SEVERITY,
  excludePatterns: [],
  maxFiles: DEFAULT_MAX_FILES,
  timeoutMs: DEFAULT_SCAN_TIMEOUT_MS,
  deep: false,
  includeTests: false,
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
    deep: userConfig?.deep ?? DEFAULT_CONFIG.deep,
    includeTests: userConfig?.includeTests ?? DEFAULT_CONFIG.includeTests,
    ...(userConfig?.ruleOverrides !== undefined ? { ruleOverrides: userConfig.ruleOverrides } : {}),
    ...(userConfig?.disabledDetectors !== undefined
      ? { disabledDetectors: userConfig.disabledDetectors }
      : {}),
    ...(userConfig?.useConfigFile !== undefined ? { useConfigFile: userConfig.useConfigFile } : {}),
    ...(userConfig?.trustConfigScripts !== undefined
      ? { trustConfigScripts: userConfig.trustConfigScripts }
      : {}),
    ...(userConfig?.targetFiles !== undefined ? { targetFiles: userConfig.targetFiles } : {}),
  };
}
