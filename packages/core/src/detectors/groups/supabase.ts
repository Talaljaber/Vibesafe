// Detector group "supabase": Supabase SQL policy, grant and function detectors.
//
// Owned by one stream. Export ONLY: the group's *Detector classes (re-exported from
// their detector files), supabaseDetectors, supabasePrecedence and supabaseNonJsExempt. Never
// export utils or types from here (core's index.ts re-exports this file with
// `export *`). Import precedence types with `import type` only.
import type { Detector } from "@talaljaber/vibesafe-shared";
import type { PrecedenceRule } from "../../scanner/precedence.js";
import type { FileKind } from "../utils/file-kind.js";
import { SupabasePolicyDetector } from "../supabase-policy-detector.js";

export { SupabasePolicyDetector } from "../supabase-policy-detector.js";

/** Fresh instances of this group's detectors, registered after the built-in ones. */
export const supabaseDetectors = (): Detector[] => [new SupabasePolicyDetector()];

/** Cross-owner precedence rules declared by this group (see scanner/precedence.ts). */
export const supabasePrecedence: readonly PrecedenceRule[] = [];

/** Detector id -> non-JS file kinds it legitimately reports on (used by non-js-files.test.ts). */
export const supabaseNonJsExempt: Readonly<Record<string, readonly FileKind[]>> = {
  "supabase-policy-detector": ["sql"],
};
