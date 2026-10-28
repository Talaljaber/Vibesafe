import fs from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import type { ScanConfig } from "@vibesafe/shared";
import { validateUserConfig } from "./schema.js";
import type { VibeSafeConfig } from "./user-config.js";

const SCRIPT_EXTENSIONS = ["ts", "mts", "js", "mjs", "cjs"];
const EXTENSIONS = [...SCRIPT_EXTENSIONS, "json"];

/** Candidate config file names, in priority order. */
export const CONFIG_FILE_NAMES = [
  ...EXTENSIONS.map((e) => `.vibesafe.config.${e}`),
  ...EXTENSIONS.map((e) => `vibesafe.config.${e}`),
];

const isJsonName = (name: string): boolean => name.endsWith(".json");

/** Raised when a config file exists but cannot be loaded or is invalid. */
export class ConfigLoadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigLoadError";
  }
}

export interface LoadUserConfigOptions {
  /**
   * Execute `.ts/.js/.mjs/.cjs` configs. Off by default: those files run
   * arbitrary code from the scanned directory. Only the `.json` config is read
   * otherwise.
   */
  allowScripts?: boolean;
}

export interface LoadedUserConfig {
  /** Absolute path of the config file that was loaded. */
  filePath: string;
  /** Validated config object. */
  config: VibeSafeConfig;
  /** The config translated into ScanConfig fields (only those that were set). */
  scanConfig: Partial<ScanConfig>;
}

/** Finds the first config file at rootPath among `names` (regular files only). */
async function findConfigFile(rootPath: string, names: string[]): Promise<string | undefined> {
  for (const name of names) {
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

/**
 * Returns the name of an executable config present at rootPath, if any. Used to
 * warn that it was not executed.
 */
export async function findScriptConfig(rootPath: string): Promise<string | undefined> {
  const found = await findConfigFile(
    rootPath,
    CONFIG_FILE_NAMES.filter((n) => !isJsonName(n)),
  );
  return found ? path.basename(found) : undefined;
}

/** Reads and parses a JSON config through one file handle (no check/use gap). */
async function readJsonConfig(filePath: string): Promise<unknown> {
  const handle = await fs.open(filePath, "r");
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new Error("not a regular file");
    return JSON.parse(await handle.readFile("utf-8"));
  } finally {
    await handle.close();
  }
}

async function readScriptConfig(filePath: string, rootPath: string): Promise<unknown> {
  // Resolve symlinks (including in parent dirs) and make sure the real file is
  // still inside the scan root before executing anything.
  const [realFile, realRoot] = await Promise.all([fs.realpath(filePath), fs.realpath(rootPath)]);
  const rel = path.relative(realRoot, realFile);
  if (rel === "" || rel.startsWith("..") || path.isAbsolute(rel)) {
    throw new Error("config file resolves outside the project root");
  }
  // Loaded lazily so jiti is only touched for trusted script configs.
  const { createJiti } = await import("jiti");
  const jiti = createJiti(pathToFileURL(realFile).href, {
    fsCache: false,
    moduleCache: false,
    interopDefault: true,
  });
  const mod = (await jiti.import(realFile)) as Record<string, unknown> | undefined;
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
 * By default only `.json` configs are considered; script configs need
 * `allowScripts`. Returns undefined when no eligible config file exists. Throws
 * a ConfigLoadError with a clear message when the file cannot be loaded or has
 * an invalid shape.
 */
export async function loadUserConfig(
  rootPath: string,
  options: LoadUserConfigOptions = {},
): Promise<LoadedUserConfig | undefined> {
  const names = options.allowScripts
    ? CONFIG_FILE_NAMES
    : CONFIG_FILE_NAMES.filter(isJsonName);
  const filePath = await findConfigFile(rootPath, names);
  if (!filePath) return undefined;
  const name = path.basename(filePath);

  let value: unknown;
  try {
    value = isJsonName(name)
      ? await readJsonConfig(filePath)
      : await readScriptConfig(filePath, rootPath);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new ConfigLoadError(`Failed to load ${name}: ${msg}`);
  }

  const errors = validateUserConfig(value);
  if (errors.length > 0) {
    throw new ConfigLoadError(`Invalid ${name}:\n${errors.map((e) => `  - ${e}`).join("\n")}`);
  }
  const config = value as VibeSafeConfig;
  return { filePath, config, scanConfig: configToScanConfig(config) };
}
