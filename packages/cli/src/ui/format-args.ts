/**
 * Whether the startup banner should be printed for these CLI args.
 * The banner is skipped for --json/-j and for any --format value (valid or not),
 * so stdout stays machine-readable. If --json and --format markdown are both
 * given, --json takes precedence in runScan.
 */
export function shouldPrintBanner(argv: readonly string[]): boolean {
  const hasFormat = argv.some((a) => a === "--format" || a.startsWith("--format="));
  const isJson = argv.includes("--json") || argv.includes("-j");
  return !(isJson || hasFormat);
}
