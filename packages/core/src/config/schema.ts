import type { ScanConfig } from "@talaljaber/vibesafe-shared";
import { ALL_CATEGORIES, SEVERITY_LEVELS } from "@talaljaber/vibesafe-shared";

/**
 * Validates the provided configuration to ensure bounds.
 */
export function validateConfig(config: ScanConfig): Error[] {
  const errors: Error[] = [];

  if (!config.rootPath || config.rootPath.trim() === "") {
    errors.push(new Error("rootPath is required and cannot be empty."));
  }

  if (config.maxFiles !== undefined && config.maxFiles <= 0) {
    errors.push(new Error("maxFiles must be a positive number."));
  }

  if (config.timeoutMs !== undefined && config.timeoutMs <= 0) {
    errors.push(new Error("timeoutMs must be a positive number."));
  }

  return errors;
}

const SEVERITIES: string[] = SEVERITY_LEVELS;
const CATEGORIES: string[] = ALL_CATEGORIES;
const KNOWN_KEYS = [
  "rules",
  "disabledDetectors",
  "categories",
  "exclude",
  "includeTests",
  "minSeverity",
  "deep",
];

const isStringArray = (v: unknown): v is string[] =>
  Array.isArray(v) && v.every((x) => typeof x === "string");

/**
 * Validates the shape of a user config file's exported value. Returns a list of
 * human-readable problems (empty when valid).
 */
export function validateUserConfig(value: unknown): string[] {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return ["config must be an object (export default defineConfig({ ... }))."];
  }
  const cfg = value as Record<string, unknown>;
  const errors: string[] = [];

  for (const key of Object.keys(cfg)) {
    if (!KNOWN_KEYS.includes(key)) {
      errors.push(`unknown option "${key}" (expected one of: ${KNOWN_KEYS.join(", ")}).`);
    }
  }

  if (cfg.rules !== undefined) {
    if (typeof cfg.rules !== "object" || cfg.rules === null || Array.isArray(cfg.rules)) {
      errors.push(`"rules" must be an object mapping rule ids to "off" or a severity.`);
    } else {
      for (const [rule, v] of Object.entries(cfg.rules)) {
        if (v !== "off" && !(typeof v === "string" && SEVERITIES.includes(v))) {
          errors.push(
            `rules["${rule}"] must be "off" or one of ${SEVERITIES.join(", ")} (got ${JSON.stringify(v)}).`,
          );
        }
      }
    }
  }
  if (cfg.disabledDetectors !== undefined && !isStringArray(cfg.disabledDetectors)) {
    errors.push(`"disabledDetectors" must be an array of strings.`);
  }
  if (cfg.exclude !== undefined && !isStringArray(cfg.exclude)) {
    errors.push(`"exclude" must be an array of glob strings.`);
  }
  if (cfg.categories !== undefined) {
    if (!isStringArray(cfg.categories)) {
      errors.push(`"categories" must be an array of category names.`);
    } else {
      for (const c of cfg.categories) {
        if (!CATEGORIES.includes(c)) {
          errors.push(`unknown category "${c}" (expected one of: ${CATEGORIES.join(", ")}).`);
        }
      }
    }
  }
  if (cfg.includeTests !== undefined && typeof cfg.includeTests !== "boolean") {
    errors.push(`"includeTests" must be a boolean.`);
  }
  if (cfg.deep !== undefined && typeof cfg.deep !== "boolean") {
    errors.push(`"deep" must be a boolean.`);
  }
  if (
    cfg.minSeverity !== undefined &&
    !(typeof cfg.minSeverity === "string" && SEVERITIES.includes(cfg.minSeverity))
  ) {
    errors.push(`"minSeverity" must be one of ${SEVERITIES.join(", ")}.`);
  }
  return errors;
}
