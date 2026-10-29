import type { ScanResult } from "@talaljaber/vibesafe-shared";
import { formatSarif } from "./sarif.js";
import { formatMarkdownReport } from "../ui/markdown-reporter.js";

export interface FormatContext {
  /** VibeSafe CLI version, embedded in machine-readable formats. */
  version: string;
}

/**
 * Registry of machine-readable output formats selectable with `--format`.
 * Each renderer returns the report text; the caller terminates it with exactly one newline
 * when writing it to stdout or the `--output` file. Add new formats by adding an entry here.
 */
export const OUTPUT_FORMATS = {
  json: (result: ScanResult) => JSON.stringify(result, null, 2),
  sarif: (result: ScanResult, ctx: FormatContext) =>
    JSON.stringify(formatSarif(result, ctx.version), null, 2),
  /** Concise PR-comment summary; starts with the sticky marker the GitHub Action looks for. */
  markdown: (result: ScanResult) => formatMarkdownReport(result),
} satisfies Record<string, (result: ScanResult, ctx: FormatContext) => string>;

export type OutputFormat = keyof typeof OUTPUT_FORMATS;

export const OUTPUT_FORMAT_NAMES = Object.keys(OUTPUT_FORMATS) as OutputFormat[];

export function isOutputFormat(value: string): value is OutputFormat {
  return Object.prototype.hasOwnProperty.call(OUTPUT_FORMATS, value);
}

export function renderOutput(format: OutputFormat, result: ScanResult, ctx: FormatContext): string {
  return OUTPUT_FORMATS[format](result, ctx);
}
