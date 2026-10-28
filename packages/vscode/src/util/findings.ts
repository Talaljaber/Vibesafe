import path from "path";
import type { Finding, ScanResult } from "@vibesafe/shared";

/**
 * Resolve a finding id from whatever a command was invoked with:
 * a plain id string, `[id]` (command URI args), a tree element
 * (`{ finding: { id } }`), or a diagnostic id. Only the id is ever read;
 * the object itself is never trusted.
 */
export function resolveFindingId(arg: unknown): string | undefined {
  if (typeof arg === "string") return arg;
  if (Array.isArray(arg)) return resolveFindingId(arg[0]);
  if (arg && typeof arg === "object") {
    const o = arg as { id?: unknown; finding?: { id?: unknown }; findingId?: unknown };
    if (typeof o.findingId === "string") return o.findingId;
    if (o.finding && typeof o.finding.id === "string") return o.finding.id;
    if (typeof o.id === "string") return o.id;
  }
  return undefined;
}

/** Look up a finding by id in a scan result. */
export function findFindingById(
  result: ScanResult | null | undefined,
  id: string | undefined
): Finding | undefined {
  if (!result || !id) return undefined;
  return result.findings.find((f) => f.id === id);
}

/** True when `target` resolves to a path inside (or equal to) `root`. */
export function isInsideRoot(root: string, target: string): boolean {
  const rel = path.relative(path.resolve(root), path.resolve(target));
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

/** True when the finding has no file, or its file resolves inside `root`. */
export function isFindingInsideRoot(root: string, finding: Finding): boolean {
  if (!finding.file) return true;
  return isInsideRoot(root, path.resolve(root, finding.file));
}

/** Find a finding by id across several scan results (one per workspace folder). */
export function findFindingInResults(
  results: Iterable<ScanResult>,
  id: string | undefined
): { finding: Finding; result: ScanResult } | undefined {
  if (!id) return undefined;
  for (const result of results) {
    const finding = findFindingById(result, id);
    if (finding) return { finding, result };
  }
  return undefined;
}
