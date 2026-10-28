/**
 * Whether the startup banner should be printed for these CLI args.
 * The banner is skipped whenever machine-readable output is requested: --json/-j,
 * any --format value (valid or not, so an unknown format still fails cleanly),
 * and --output (which implies --format json). Checked before commander parses argv.
 * Arguments after a bare `--` are positional (e.g. a directory) and are ignored.
 */
export function shouldPrintBanner(argv: readonly string[]): boolean {
  const end = argv.indexOf("--");
  const opts = end === -1 ? argv : argv.slice(0, end);
  const isMachineOutput = opts.some(
    (a) =>
      a === "--json" ||
      a === "-j" ||
      a === "--format" ||
      a.startsWith("--format=") ||
      a === "--output" ||
      a.startsWith("--output="),
  );
  return !isMachineOutput;
}
