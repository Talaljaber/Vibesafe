import type { AttackRun, RunOptions } from "./types.js";

export type * from "./types.js";
export { ATTACK_CHECKS } from "./checks/index.js";

const NOT_IMPLEMENTED = "not implemented";

/** Plans and executes an attack run against a local dev server. */
export function runAttack(_options: RunOptions): Promise<AttackRun> {
  throw new Error(NOT_IMPLEMENTED);
}

/** Re-runs the probes of a saved run and diffs the outcomes. */
export function replayAttack(_options: RunOptions): Promise<AttackRun> {
  throw new Error(NOT_IMPLEMENTED);
}

/** Loads the most recent saved run for a project, or undefined when there is none. */
export function loadRun(_projectPath: string): AttackRun | undefined {
  throw new Error(NOT_IMPLEMENTED);
}
