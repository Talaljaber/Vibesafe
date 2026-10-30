/**
 * CLI flags that shape a scan and interact with the `.vibesafe.config.*` file. Shared by every
 * command that scans (scan, fix, fix --all, fix -i, scan -i, watch) so they honour the config
 * file the same way. Kept free of heavy imports so any command can use it.
 */
export interface ScanFlagOptions {
  /** --deep / --no-deep; undefined = take the config file value. */
  deep?: boolean | undefined;
  /** --include-tests / --no-include-tests; undefined = take the config file value. */
  includeTests?: boolean | undefined;
  /** commander sets this to false for --no-config. */
  config?: boolean | undefined;
  /** --trust-config: allow executing .ts/.js config files. */
  trustConfig?: boolean | undefined;
  /**
   * --online (scan only): allow the OSV advisory lookup (package names and versions to
   * api.osv.dev) and the package existence check (package names to registry.npmjs.org,
   * api.npmjs.org and pypi.org). Never read from a config file.
   */
  online?: boolean | undefined;
}

/**
 * Builds the explicit scan options from CLI flags. Only flags the user actually
 * passed are included, so config-file values apply otherwise.
 */
export function buildScanOptions(rootPath: string, options: ScanFlagOptions) {
  return {
    rootPath,
    ...(options.deep !== undefined ? { deep: options.deep } : {}),
    ...(options.includeTests !== undefined ? { includeTests: options.includeTests } : {}),
    ...(options.config === false ? { useConfigFile: false } : {}),
    ...(options.trustConfig ? { trustConfigScripts: true } : {}),
    ...(options.online === true ? { online: true } : {}),
  };
}
