import type { AttackCheck } from "../types.js";

/**
 * Pre-declared check registry, one entry per line. Later PRs fill in the checks
 * (idor, unauthRoute) without changing this file's shape.
 */
export const ATTACK_CHECKS: readonly AttackCheck[] = [
  // idor,
  // unauthRoute,
];
