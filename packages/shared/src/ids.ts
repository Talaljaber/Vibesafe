import { createHash } from "node:crypto";

/**
 * Build a deterministic finding id: `PREFIX-<10 hex chars>`.
 *
 * The hash covers every input, so the same finding yields the same id on every
 * scan. Pass `discriminator` (e.g. the matched text or an index) when several
 * findings can share the same ruleId/file/line.
 */
export function createFindingId(
  prefix: string,
  ruleId: string,
  file?: string | undefined,
  line?: number | undefined,
  discriminator?: string | number | undefined,
): string {
  const input = [
    ruleId,
    file ?? "",
    line === undefined ? "" : String(line),
    String(discriminator ?? ""),
  ].join("\0");
  const hex = createHash("sha256").update(input).digest("hex").slice(0, 10);
  return `${prefix}-${hex}`;
}
