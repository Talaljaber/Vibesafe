import type { FindingCategory, ScanConfig, Severity } from "@vibesafe/shared";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

/** Minimal view of vscode.WorkspaceConfiguration. */
export interface ConfigReader {
  get<T>(key: string): T | undefined;
}

/**
 * Translate `vibesafe.*` settings into scan config overrides.
 * An empty `enabledCategories` means "all", so it is omitted.
 */
export function readScanOptions(cfg: ConfigReader): Partial<ScanConfig> {
  const out: Partial<ScanConfig> = {};
  const sev = cfg.get<string>("minSeverity");
  if (sev && (SEVERITIES as string[]).includes(sev)) out.minSeverity = sev as Severity;
  const cats = cfg.get<string[]>("enabledCategories");
  if (Array.isArray(cats) && cats.length > 0) out.enabledCategories = cats as FindingCategory[];
  return out;
}
