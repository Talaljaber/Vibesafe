import type { AttackCheck } from "../types.js";
import { idor } from "./idor.js";
import { unauthRoute } from "./unauth-route.js";

/** Pre-declared check registry, one entry per line. */
export const ATTACK_CHECKS: readonly AttackCheck[] = [idor, unauthRoute];
