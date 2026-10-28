import fs from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { createJiti } from "jiti";
import type { ScanConfig } from "@vibesafe/shared";
import { validateUserConfig } from "./schema.js";
import type { VibeSafeConfig } from "./user-config.js";

const EXTENSIONS = ["ts", "mts", "js", "mjs", "cjs", "json"];

/** Candidate config file names, in priority order. */
export const CONFIG_FILE_NAMES = [
  ...EXTENSIONS.map((e) => `.vibesafe.config.${e}`),
  ...EXTENSIONS.map((e) => `vibesafe.config.${e}`),
];

export interface LoadedUserConfig {
  /** Absolute path of the config file that was loaded. */
  filePath: string;
  /** Validated config object. */
  config: VibeSafeConfig;
  /** The config translated into ScanConfig fields (only those that were set). */
  scanConfig: Partial<ScanConfig>;
}

/** Finds the first config file at rootPath (regular files only). */
async function findConfigFile(rootPath: string): Promise<string | undefined> {
  for (const name of CONFIG_FILE_NAMES) {
    const full = path.join(rootPath, name);
    try {
      const stat = await fs.lstat(full);
      if (stat.isFile()) return full;
    } catch {
      // not present
    }
  }
  return undefined;
}

async function readConfigValue(filePath: string): Promise<unknown> {
  if (filePath.endsWith(".json")) {
    return JSON.parse(await fs.readFile(filePath, "utf-8"));
  }
  // jiti transpiles TS/ESM/CJS on the fly and works on Node 20 without flags.
  const jiti = createJiti(pathToFileURL(filePath).href, {
    fsCache: false,
    moduleCache: false,
    interopDefault: true,
  });
  const mod = (await jiti.import(filePath)) as Record<string, unknown> | undefined;
  if (mod && typeof mod === "object" && "default" in mod) return mod.default;
  return mod;
}

/** Translates a validated config file into ScanConfig fields. */
export function configToScanConfig(config: VibeSafeConfig): Partial<ScanConfig> {
  const out: Partial<ScanConfig> = {};
  if (config.rules !== undefined) out.ruleOverrides = { ...config.rules };
  if (config.disabledDetectors !== undefined) out.disabledDetectors = [...config.disabledDetectors];
  if (config.categories !== undefined) out.enabledCategories = [...config.categories];
  if (config.exclude !== undefined) out.excludePatterns = [...config.exclude];
  if (config.includeTests !== undefined) out.includeTests = config.includeTests;
  if (config.minSeverity !== undefined) out.minSeverity = config.minSeverity;
  if (config.deep !== undefined) out.deep = config.deep;
  return out;
}

/**
 * Discovers and loads `.vibesafe.config.*` / `vibesafe.config.*` at rootPath.
 * Returns undefined when no config file exists. Throws an Error with a clear
 * message when the file cannot be loaded or has an invalid shape.
 */
export async function loadUserConfig(rootPath: string): Promise<LoadedUserConfig | undefined> {
  const filePath = await findConfigFile(rootPath);
  if (!filePath) return undefined;
  const name = path.basename(filePath);

  let value: unknown;
  try {
    value = await readConfigValue(filePath);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to load ${name}: ${msg}`);
  }

  const errors = validateUserConfig(value);
  if (errors.length > 0) {
    throw new Error(`Invalid ${name}:\n${errors.map((e) => `  - ${e}`).join("\n")}`);
  }
  const config = value as VibeSafeConfig;
  return { filePath, config, scanConfig: configToScanConfig(config) };
}
