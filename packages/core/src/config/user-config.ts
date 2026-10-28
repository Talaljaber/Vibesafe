import type { FindingCategory, Severity } from "@vibesafe/shared";

/** Shape of a `.vibesafe.config.*` file. Every field is optional. */
export interface VibeSafeConfig {
  /** Per-rule overrides: ruleId (or `*` glob such as `code_quality/*`) -> "off" or a severity. */
  rules?: Record<string, "off" | Severity>;
  /** Detector ids that must not run (e.g. "git-history-detector"). */
  disabledDetectors?: string[];
  /** Categories to run. Omit for all. */
  categories?: FindingCategory[];
  /** Extra glob patterns to exclude from scanning. */
  exclude?: string[];
  /** Also scan test files and fixtures. */
  includeTests?: boolean;
  /** Minimum severity to report. */
  minSeverity?: Severity;
  /** Also scan git history for leaked secrets. */
  deep?: boolean;
}

/** Identity helper that gives config files type checking and autocomplete. */
export function defineConfig(config: VibeSafeConfig): VibeSafeConfig {
  return config;
}
