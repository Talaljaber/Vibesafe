// Detector group "injection": server-side injection detectors (SQL, shell, code eval, SSRF, path traversal, open redirect).
//
// Owned by one stream. Export ONLY: the group's *Detector classes (re-exported from
// their detector files), injectionDetectors, injectionPrecedence and injectionNonJsExempt. Never
// export utils or types from here (core's index.ts re-exports this file with
// `export *`). Import precedence types with `import type` only.
import type { Detector } from "@talaljaber/vibesafe-shared";
import type { PrecedenceRule } from "../../scanner/precedence.js";
import type { FileKind } from "../utils/file-kind.js";
import { SqlInjectionDetector } from "../sql-injection-detector.js";
import { CommandInjectionDetector } from "../command-injection-detector.js";
import { CodeEvalDetector } from "../code-eval-detector.js";
import { SsrfDetector } from "../ssrf-detector.js";
import { PathTraversalDetector } from "../path-traversal-detector.js";
import { OpenRedirectDetector } from "../open-redirect-detector.js";
import { PythonInjectionDetector } from "../python-injection-detector.js";
import { CeleryConfigDetector } from "../celery-config-detector.js";

export {
  SqlInjectionDetector,
  CommandInjectionDetector,
  CodeEvalDetector,
  SsrfDetector,
  PathTraversalDetector,
  OpenRedirectDetector,
  PythonInjectionDetector,
  CeleryConfigDetector,
};

/** Fresh instances of this group's detectors, registered after the built-in ones. */
export const injectionDetectors = (): Detector[] => [
  new SqlInjectionDetector(),
  new CommandInjectionDetector(),
  new CodeEvalDetector(),
  new SsrfDetector(),
  new PathTraversalDetector(),
  new OpenRedirectDetector(),
  new PythonInjectionDetector(),
  new CeleryConfigDetector(),
];

/**
 * Injection rules that are always `high` or `critical`, so they are never less severe
 * than the `high` generic finding they hide. Rules that can be `medium`
 * (`postgrest-filter-interpolation`, `open-redirect`, `sql-built-from-parameter`) coexist
 * with the generic finding instead.
 */
const SEVERE_INJECTION_RULES = [
  "injection/sql-built-from-input",
  "injection/command-exec-interpolation",
  "injection/dynamic-code-eval",
  "injection/ssrf-user-controlled-url",
  "injection/path-traversal",
] as const;

/** Cross-owner precedence rules declared by this group (see scanner/precedence.ts). */
export const injectionPrecedence: readonly PrecedenceRule[] = SEVERE_INJECTION_RULES.map(
  (winner) => ({
    winner,
    losers: ["validation/missing-body-validation"],
    scope: "enclosing" as const,
    reason:
      "An injection finding inside the handler already names the dangerous use of the input and its real fix (parameterize, execFile, allowlist, confine the path); generic schema-validation advice for the same handler points at the wrong fix.",
  }),
);

/** Detector id -> non-JS file kinds it legitimately reports on (used by non-js-files.test.ts). */
export const injectionNonJsExempt: Readonly<Record<string, readonly FileKind[]>> = {
  "python-injection-detector": ["python"],
  "celery-config-detector": ["python"],
};
