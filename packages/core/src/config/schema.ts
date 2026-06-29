import type { ScanConfig } from "@vibesafe/shared";

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
