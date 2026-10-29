// Detector group "infra": Dockerfile, compose, GitHub workflow, shell script and next.config detectors.
//
// Owned by one stream. Export ONLY: the group's *Detector classes (re-exported from
// their detector files), infraDetectors, infraPrecedence and infraNonJsExempt. Never
// export utils or types from here (core's index.ts re-exports this file with
// `export *`). Import precedence types with `import type` only.
import type { Detector } from "@talaljaber/vibesafe-shared";
import type { PrecedenceRule } from "../../scanner/precedence.js";
import type { FileKind } from "../utils/file-kind.js";
import { DockerfileDetector } from "../dockerfile-detector.js";
import { DockerComposeDetector } from "../docker-compose-detector.js";
import { GithubWorkflowDetector } from "../github-workflow-detector.js";
import { GhaScriptInjectionDetector } from "../gha-script-injection-detector.js";
import { ShellScriptDetector } from "../shell-script-detector.js";
import { NextjsConfigDetector } from "../nextjs-config-detector.js";

export {
  DockerfileDetector,
  DockerComposeDetector,
  GithubWorkflowDetector,
  GhaScriptInjectionDetector,
  ShellScriptDetector,
  NextjsConfigDetector,
};

/** Fresh instances of this group's detectors, registered after the built-in ones. */
export const infraDetectors = (): Detector[] => [
  new DockerfileDetector(),
  new DockerComposeDetector(),
  new GithubWorkflowDetector(),
  new GhaScriptInjectionDetector(),
  new ShellScriptDetector(),
  new NextjsConfigDetector(),
];

/**
 * Cross-owner precedence rules declared by this group (see scanner/precedence.ts).
 * None: overlaps with the secret detector are avoided inside the detectors (lines a
 * known secret pattern matches are skipped).
 */
export const infraPrecedence: readonly PrecedenceRule[] = [];

/** Detector id -> non-JS file kinds it legitimately reports on (used by non-js-files.test.ts). */
export const infraNonJsExempt: Readonly<Record<string, readonly FileKind[]>> = {
  "dockerfile-detector": ["dockerfile"],
  "docker-compose-detector": ["compose"],
  "github-workflow-detector": ["workflow", "gh-action"],
  "gha-script-injection-detector": ["workflow", "gh-action"],
  "shell-script-detector": ["shell"],
};
