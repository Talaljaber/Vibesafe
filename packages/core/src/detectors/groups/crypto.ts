// Detector group "crypto": crypto detectors (insecure randomness, secret fallbacks, JWT misuse, plaintext credentials).
//
// Owned by one stream. Export ONLY: the group's *Detector classes (re-exported from
// their detector files), cryptoDetectors, cryptoPrecedence and cryptoNonJsExempt. Never
// export utils or types from here (core's index.ts re-exports this file with
// `export *`). Import precedence types with `import type` only.
import type { Detector } from "@talaljaber/vibesafe-shared";
import type { PrecedenceRule } from "../../scanner/precedence.js";
import type { FileKind } from "../utils/file-kind.js";
import { InsecureRandomDetector } from "../insecure-random-detector.js";
import { SecretFallbackDetector } from "../secret-fallback-detector.js";
import { JwtMisuseDetector } from "../jwt-misuse-detector.js";
import { PlaintextCredentialDetector } from "../plaintext-credential-detector.js";

export {
  InsecureRandomDetector,
  SecretFallbackDetector,
  JwtMisuseDetector,
  PlaintextCredentialDetector,
};

/** Fresh instances of this group's detectors, registered after the built-in ones. */
export const cryptoDetectors = (): Detector[] => [
  new InsecureRandomDetector(),
  new SecretFallbackDetector(),
  new JwtMisuseDetector(),
  new PlaintextCredentialDetector(),
];

/**
 * Cross-owner precedence rules declared by this group (see scanner/precedence.ts). None:
 * overlaps with the secret detector are resolved inside the detectors (the fallback and
 * JWT rules skip lines where a SECRET_PATTERNS entry already matches).
 */
export const cryptoPrecedence: readonly PrecedenceRule[] = [];

/** Detector id -> non-JS file kinds it legitimately reports on (used by non-js-files.test.ts). */
export const cryptoNonJsExempt: Readonly<Record<string, readonly FileKind[]>> = {
  "plaintext-credential-detector": ["sql"],
};
