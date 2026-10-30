// Detector group "deps": dependency detectors (known-vulnerable versions, typosquats, opt-in online advisories, online package existence checks).
//
// Owned by one stream. Export ONLY: the group's *Detector classes (re-exported from
// their detector files), depsDetectors, depsPrecedence and depsNonJsExempt. Never
// export utils or types from here (core's index.ts re-exports this file with
// `export *`). Import precedence types with `import type` only.
import type { Detector } from "@talaljaber/vibesafe-shared";
import type { PrecedenceRule } from "../../scanner/precedence.js";
import type { FileKind } from "../utils/file-kind.js";
import { NpmAdvisoryDetector } from "../npm-advisory-detector.js";
import { TyposquatDetector } from "../typosquat-detector.js";
import { OsvDetector } from "../osv-detector.js";
import { PackageExistenceDetector } from "../package-existence-detector.js";

export { NpmAdvisoryDetector, TyposquatDetector, OsvDetector, PackageExistenceDetector };

/** Fresh instances of this group's detectors, registered after the built-in ones. */
export const depsDetectors = (): Detector[] => [
  new NpmAdvisoryDetector(),
  new TyposquatDetector(),
  new OsvDetector(),
  new PackageExistenceDetector(),
];

/** Cross-owner precedence rules declared by this group (see scanner/precedence.ts). */
export const depsPrecedence: readonly PrecedenceRule[] = [
  {
    winner: "dependency/typosquat-package",
    losers: ["dependency/package-not-found", "dependency/package-very-new"],
    scope: "line",
    reason:
      "A typosquat finding already names the intended package; the existence result for the same manifest line adds nothing.",
  },
];

/** Detector id -> non-JS file kinds it legitimately reports on (used by non-js-files.test.ts). */
export const depsNonJsExempt: Readonly<Record<string, readonly FileKind[]>> = {
  "npm-advisory-detector": ["package-manifest", "lockfile"],
  "typosquat-detector": ["package-manifest"],
  "osv-detector": ["package-manifest", "lockfile"],
  "package-existence-detector": ["package-manifest", "python-manifest"],
};
