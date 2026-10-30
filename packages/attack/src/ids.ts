import { createHash } from "node:crypto";
import type { AttackCheckId } from "./types.js";

const CATCH_ALL_RE = /^\[\[?\.\.\.[^\]]+\]\]?$/;
const DYNAMIC_RE = /^\[[^\]]+\]$/;

/**
 * Replaces dynamic route segments by position so that renaming a parameter keeps the same id:
 * `[id]` becomes `:1`, `[...slug]` (and `[[...slug]]`) becomes `*1`. Counters are per kind.
 */
export function normalizePattern(pattern: string): string {
  let dyn = 0;
  let rest = 0;
  return pattern
    .split("/")
    .map((segment) => {
      if (CATCH_ALL_RE.test(segment)) return `*${++rest}`;
      if (DYNAMIC_RE.test(segment)) return `:${++dyn}`;
      return segment;
    })
    .join("/");
}

/** Stable attack id: `ATK-` plus the first 12 hex chars of sha256(checkId|METHOD|normalized). */
export function stableAttackId(checkId: AttackCheckId, method: string, pattern: string): string {
  const input = `${checkId}|${method.toUpperCase()}|${normalizePattern(pattern)}`;
  return `ATK-${createHash("sha256").update(input).digest("hex").slice(0, 12)}`;
}
