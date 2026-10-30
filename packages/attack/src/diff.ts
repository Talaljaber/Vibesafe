import { normalizePattern } from "./ids.js";
import type { AttackResult, AttackRun, RetestDiff, RetestState } from "./types.js";

/** A baseline group replayed against the live target, plus what the owner control returned. */
export interface ReplayedResult {
  result: AttackResult;
  /** Status of the replayed owner control request (R2), used to recognise GONE. */
  ownerStatus?: number | undefined;
}

export interface DiffInput {
  baseline: AttackRun;
  /** Every baseline group's concrete requests, replayed now (keyed by attackId). */
  replayed: readonly ReplayedResult[];
  /** Results of freshly planned groups (used to find NEW). */
  fresh: readonly AttackResult[];
  /** Route patterns present in the fresh route map. */
  freshRoutes: Iterable<string>;
}

function stateFor(
  was: AttackResult["outcome"],
  replayed: ReplayedResult,
  routePresent: boolean,
): RetestState {
  const now = replayed.result.outcome;
  if (now === "ERROR") return "ERROR";
  if (was === "CONFIRMED") {
    if (now === "CONFIRMED") return "STILL_VULNERABLE";
    if (!routePresent && replayed.ownerStatus === 404) return "GONE";
    if (now === "NOT_REPRODUCED") return replayed.result.ownerOk === true ? "BLOCKED" : "BROKEN";
    return "UNCHANGED";
  }
  return now === "CONFIRMED" ? "NEW" : "UNCHANGED";
}

/** Maps replayed and fresh results onto the seven retest states (spec section 9). */
export function computeRetestDiff(input: DiffInput): RetestDiff[] {
  const present = new Set([...input.freshRoutes].map(normalizePattern));
  const wasById = new Map(input.baseline.results.map((r) => [r.attackId, r.outcome] as const));
  const diff: RetestDiff[] = [];
  const seen = new Set<string>();

  for (const replayed of input.replayed) {
    const { result } = replayed;
    if (seen.has(result.attackId)) continue;
    seen.add(result.attackId);
    const was = wasById.get(result.attackId);
    const routePresent = result.route === undefined || present.has(normalizePattern(result.route));
    const entry: RetestDiff = {
      attackId: result.attackId,
      now: result.outcome,
      state: was === undefined ? "NEW" : stateFor(was, replayed, routePresent),
    };
    if (was !== undefined) entry.was = was;
    if (result.ownerOk !== undefined) entry.ownerOk = result.ownerOk;
    if (was === undefined && result.outcome !== "CONFIRMED") {
      entry.state = result.outcome === "ERROR" ? "ERROR" : "UNCHANGED";
    }
    diff.push(entry);
  }

  for (const result of input.fresh) {
    const was = wasById.get(result.attackId);
    if (result.outcome !== "CONFIRMED" || was === "CONFIRMED") continue;
    const entry: RetestDiff = { attackId: result.attackId, now: result.outcome, state: "NEW" };
    if (was !== undefined) entry.was = was;
    if (result.ownerOk !== undefined) entry.ownerOk = result.ownerOk;
    // A fresh CONFIRMED verdict wins over a replay that could not reproduce it.
    const at = diff.findIndex((d) => d.attackId === result.attackId);
    if (at >= 0) diff[at] = entry;
    else diff.push(entry);
  }
  return diff;
}

/**
 * Process exit code for a finished run: 1 when something is CONFIRMED, STILL_VULNERABLE or NEW,
 * otherwise 0. (Exit code 2, errors and usage problems, is raised as AttackPersistError.)
 */
export function exitCodeForRun(run: AttackRun): 0 | 1 {
  if (run.results.some((r) => r.outcome === "CONFIRMED")) return 1;
  if (run.diff?.some((d) => d.state === "STILL_VULNERABLE" || d.state === "NEW")) return 1;
  return 0;
}
