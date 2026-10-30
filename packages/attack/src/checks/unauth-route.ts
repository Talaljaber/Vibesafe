import type { AttackCheck } from "../types.js";

/** Stub: implemented in a later PR. */
export const unauthRoute: AttackCheck = {
  id: "unauth-route",
  title: "unauth-route",
  plan() {
    throw new Error("not implemented");
  },
  evaluate() {
    throw new Error("not implemented");
  },
};
