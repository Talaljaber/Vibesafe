import type { AttackResult, AttackRun, RunOptions } from "./types.js";

export type * from "./types.js";
export { ATTACK_CHECKS } from "./checks/index.js";

const NOT_IMPLEMENTED = "not implemented";

/** Plans and executes an attack run against a local dev server. */
export async function runAttack(_options: RunOptions): Promise<AttackRun> {
  throw new Error(NOT_IMPLEMENTED);
}

/** Re-sends the requests of one saved result (identified by attackId) and returns its new result. */
export async function replayAttack(_options: RunOptions, _attackId: string): Promise<AttackResult> {
  throw new Error(NOT_IMPLEMENTED);
}

/**
 * Loads a saved run for a project, or undefined when there is none.
 * "baseline" is attack-baseline.json (used by retest), "last" is attack-last.json.
 */
export function loadRun(
  _projectPath: string,
  _which: "baseline" | "last" = "last",
): AttackRun | undefined {
  throw new Error(NOT_IMPLEMENTED);
}
