// Detector group "tooling": tooling detectors (placeholder tests, client-trusted prices, check-then-act races).
//
// Owned by one stream. Export ONLY: the group's *Detector classes (re-exported from
// their detector files), toolingDetectors, toolingPrecedence and toolingNonJsExempt. Never
// export utils or types from here (core's index.ts re-exports this file with
// `export *`). Import precedence types with `import type` only.
import type { Detector } from "@talaljaber/vibesafe-shared";
import type { PrecedenceRule } from "../../scanner/precedence.js";
import type { FileKind } from "../utils/file-kind.js";
import { PlaceholderTestsDetector } from "../placeholder-tests-detector.js";
import { ClientTrustedPriceDetector } from "../client-trusted-price-detector.js";
import { CheckThenActDetector } from "../check-then-act-detector.js";

export { PlaceholderTestsDetector, ClientTrustedPriceDetector, CheckThenActDetector };

/** Fresh instances of this group's detectors, registered after the built-in ones. */
export const toolingDetectors = (): Detector[] => [
  new PlaceholderTestsDetector(),
  new ClientTrustedPriceDetector(),
  new CheckThenActDetector(),
];

/** Cross-owner precedence rules declared by this group (see scanner/precedence.ts). */
export const toolingPrecedence: readonly PrecedenceRule[] = [
  {
    winner: "validation/client-trusted-price",
    losers: ["validation/missing-body-validation"],
    scope: "enclosing",
    reason:
      "A handler that charges a client-sent price is reported specifically; the generic unvalidated-body finding for the same handler adds nothing.",
  },
];

/** Detector id -> non-JS file kinds it legitimately reports on (used by non-js-files.test.ts). */
export const toolingNonJsExempt: Readonly<Record<string, readonly FileKind[]>> = {
  "placeholder-tests-detector": ["package-manifest"],
};
