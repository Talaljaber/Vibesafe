// Detector group "client": client-runtime detectors (browser eval and navigation, unsafe href, postMessage, web storage, client role checks).
//
// Owned by one stream. Export ONLY: the group's *Detector classes (re-exported from
// their detector files), clientDetectors, clientPrecedence and clientNonJsExempt. Never
// export utils or types from here (core's index.ts re-exports this file with
// `export *`). Import precedence types with `import type` only.
import type { Detector } from "@talaljaber/vibesafe-shared";
import type { PrecedenceRule } from "../../scanner/precedence.js";
import type { FileKind } from "../utils/file-kind.js";
import { BrowserStorageDetector } from "../browser-storage-detector.js";
import { ClientCodeEvalDetector } from "../client-code-eval-detector.js";
import { ClientRoleCheckDetector } from "../client-role-check-detector.js";
import { PostMessageDetector } from "../postmessage-detector.js";
import { UnsafeHrefDetector } from "../unsafe-href-detector.js";

export {
  BrowserStorageDetector,
  ClientCodeEvalDetector,
  ClientRoleCheckDetector,
  PostMessageDetector,
  UnsafeHrefDetector,
};

/** Fresh instances of this group's detectors, registered after the built-in ones. */
export const clientDetectors = (): Detector[] => [
  new ClientCodeEvalDetector(),
  new UnsafeHrefDetector(),
  new PostMessageDetector(),
  new BrowserStorageDetector(),
  new ClientRoleCheckDetector(),
];

/**
 * Cross-owner precedence rules declared by this group (see scanner/precedence.ts).
 * None: `frontend_exposure/sensitive-data-console-log` coexists with
 * `code_quality/console-log` on purpose (that finding carries the auto-fix).
 */
export const clientPrecedence: readonly PrecedenceRule[] = [];

/** Detector id -> non-JS file kinds it legitimately reports on (used by non-js-files.test.ts). */
export const clientNonJsExempt: Readonly<Record<string, readonly FileKind[]>> = {};
