import type { AttackCheck } from "../types.js";

/** Stub: implemented in a later PR. */
export const idor: AttackCheck = {
  id: "idor",
  title: "idor",
  plan() {
    throw new Error("not implemented");
  },
  evaluate() {
    throw new Error("not implemented");
  },
};
