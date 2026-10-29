// Detector group "authz": authentication and authorization detectors (IDOR, mass assignment, auth ordering, route secrets, middleware, error leaks).
//
// Owned by one stream. Export ONLY: the group's *Detector classes (re-exported from
// their detector files), authzDetectors, authzPrecedence and authzNonJsExempt. Never
// export utils or types from here (core's index.ts re-exports this file with
// `export *`). Import precedence types with `import type` only.
import type { Detector } from "@talaljaber/vibesafe-shared";
import type { PrecedenceRule } from "../../scanner/precedence.js";
import type { FileKind } from "../utils/file-kind.js";

/** Fresh instances of this group's detectors, registered after the built-in ones. */
export const authzDetectors = (): Detector[] => [];

/** Cross-owner precedence rules declared by this group (see scanner/precedence.ts). */
export const authzPrecedence: readonly PrecedenceRule[] = [];

/** Detector id -> non-JS file kinds it legitimately reports on (used by non-js-files.test.ts). */
export const authzNonJsExempt: Readonly<Record<string, readonly FileKind[]>> = {};
