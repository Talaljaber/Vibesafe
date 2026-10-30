// Detector group "infra": Dockerfile, compose, GitHub workflow, shell script, next.config and .gitignore env-variant detectors.
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
import { GitignoreEnvDetector } from "../gitignore-env-detector.js";
import { TerraformDetector } from "../terraform-detector.js";
import { K8sManifestDetector } from "../k8s-manifest-detector.js";
import { IacSecretDetector } from "../iac-secret-detector.js";

export {
  DockerfileDetector,
  DockerComposeDetector,
  GithubWorkflowDetector,
  GhaScriptInjectionDetector,
  ShellScriptDetector,
  NextjsConfigDetector,
  GitignoreEnvDetector,
  TerraformDetector,
  K8sManifestDetector,
  IacSecretDetector,
};

/** Fresh instances of this group's detectors, registered after the built-in ones. */
export const infraDetectors = (): Detector[] => [
  new DockerfileDetector(),
  new DockerComposeDetector(),
  new GithubWorkflowDetector(),
  new GhaScriptInjectionDetector(),
  new ShellScriptDetector(),
  new NextjsConfigDetector(),
  new GitignoreEnvDetector(),
  new TerraformDetector(),
  new K8sManifestDetector(),
  new IacSecretDetector(),
];

/**
 * Cross-owner precedence rules declared by this group (see scanner/precedence.ts).
 * The IaC secret rules are specific, so they hide the low-confidence generic
 * password/secret assignment findings reported on the same line.
 */
export const infraPrecedence: readonly PrecedenceRule[] = [
  {
    winner: "secret/terraform-literal-credential",
    losers: ["secret/sec-generic-password", "secret/sec-generic-secret"],
    scope: "line",
    reason: "The Terraform credential rule already reports the literal on this line.",
  },
  {
    winner: "secret/k8s-secret-manifest",
    losers: ["secret/sec-generic-password", "secret/sec-generic-secret"],
    scope: "line",
    reason: "The Kubernetes Secret rule already reports this value.",
  },
  {
    winner: "secret/k8s-configmap-credential",
    losers: ["secret/sec-generic-password", "secret/sec-generic-secret"],
    scope: "line",
    reason: "The ConfigMap credential rule already reports this value.",
  },
];

/** Detector id -> non-JS file kinds it legitimately reports on (used by non-js-files.test.ts). */
export const infraNonJsExempt: Readonly<Record<string, readonly FileKind[]>> = {
  "dockerfile-detector": ["dockerfile"],
  "docker-compose-detector": ["compose"],
  "github-workflow-detector": ["workflow", "gh-action"],
  "gha-script-injection-detector": ["workflow", "gh-action"],
  "shell-script-detector": ["shell"],
  "gitignore-env-detector": ["gitignore"],
  "terraform-detector": ["terraform"],
  "k8s-manifest-detector": ["k8s-manifest"],
  "iac-secret-detector": ["k8s-manifest", "terraform", "tfvars"],
};
