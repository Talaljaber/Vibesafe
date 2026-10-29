import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";

import { SecretDetector } from "../detectors/secret-detector.js";
import { FrontendExposureDetector } from "../detectors/frontend-exposure-detector.js";
import { MissingAuthDetector } from "../detectors/missing-auth-detector.js";
import { MissingValidationDetector } from "../detectors/missing-validation-detector.js";
import { MissingAuthorizationDetector } from "../detectors/missing-authorization-detector.js";
import { DependencyDetector } from "../detectors/dependency-detector.js";
import { CodebaseMessDetector } from "../detectors/codebase-mess-detector.js";
import { ProjectStructureDetector } from "../detectors/project-structure-detector.js";
import { HardcodedLocalhostDetector } from "../detectors/hardcoded-localhost-detector.js";
import { ErrorBoundaryDetector } from "../detectors/error-boundary-detector.js";
import { GitHistoryDetector } from "../detectors/git-history-detector.js";
import { DangerousHtmlDetector } from "../detectors/dangerous-html-detector.js";
import { DjangoSettingsDetector } from "../detectors/django-settings-detector.js";
import { DjangoViewsDetector } from "../detectors/django-views-detector.js";
import { PythonDependencyDetector } from "../detectors/python-dependency-detector.js";
import { SupabaseRlsDetector } from "../detectors/supabase-rls-detector.js";
import { SecurityHeadersDetector } from "../detectors/security-headers-detector.js";
import { CorsDetector } from "../detectors/cors-detector.js";
import { StripeWebhookDetector } from "../detectors/stripe-webhook-detector.js";
import { RateLimitDetector } from "../detectors/rate-limit-detector.js";
import { infraDetectors, infraPrecedence } from "../detectors/groups/infra.js";
import { injectionDetectors, injectionPrecedence } from "../detectors/groups/injection.js";
import { clientDetectors, clientPrecedence } from "../detectors/groups/client.js";
import { authzDetectors, authzPrecedence } from "../detectors/groups/authz.js";
import { cryptoDetectors, cryptoPrecedence } from "../detectors/groups/crypto.js";
import { supabaseDetectors, supabasePrecedence } from "../detectors/groups/supabase.js";
import { depsDetectors, depsPrecedence } from "../detectors/groups/deps.js";
import { toolingDetectors, toolingPrecedence } from "../detectors/groups/tooling.js";
import type { PrecedenceRule } from "./precedence.js";

/** Detector groups in registration order (after the built-in detectors). */
const GROUPS: readonly { detectors: () => Detector[]; precedence: readonly PrecedenceRule[] }[] = [
  { detectors: infraDetectors, precedence: infraPrecedence },
  { detectors: injectionDetectors, precedence: injectionPrecedence },
  { detectors: clientDetectors, precedence: clientPrecedence },
  { detectors: authzDetectors, precedence: authzPrecedence },
  { detectors: cryptoDetectors, precedence: cryptoPrecedence },
  { detectors: supabaseDetectors, precedence: supabasePrecedence },
  { detectors: depsDetectors, precedence: depsPrecedence },
  { detectors: toolingDetectors, precedence: toolingPrecedence },
];

export function createDefaultRegistry(): DetectorRegistry {
  const registry = new DetectorRegistry();
  registry.register(new SecretDetector());
  registry.register(new FrontendExposureDetector());
  registry.register(new MissingAuthDetector());
  registry.register(new MissingValidationDetector());
  registry.register(new MissingAuthorizationDetector());
  registry.register(new DependencyDetector());
  registry.register(new CodebaseMessDetector());
  registry.register(new HardcodedLocalhostDetector());
  registry.register(new ProjectStructureDetector());
  registry.register(new ErrorBoundaryDetector());
  registry.register(new GitHistoryDetector());
  registry.register(new DangerousHtmlDetector());
  registry.register(new DjangoSettingsDetector());
  registry.register(new DjangoViewsDetector());
  registry.register(new PythonDependencyDetector());
  registry.register(new SupabaseRlsDetector());
  registry.register(new SecurityHeadersDetector());
  registry.register(new CorsDetector());
  registry.register(new StripeWebhookDetector());
  registry.register(new RateLimitDetector());
  for (const group of GROUPS) {
    for (const detector of group.detectors()) registry.register(detector);
    registry.registerPrecedence(group.precedence);
  }
  return registry;
}
export class DetectorRegistry {
  private detectors: Detector[] = [];
  private precedence: PrecedenceRule[] = [];

  /**
   * Registers a new detector.
   */
  register(detector: Detector): void {
    this.detectors.push(detector);
  }

  /**
   * Gets all registered detectors.
   */
  getDetectors(): Detector[] {
    return this.detectors;
  }

  /**
   * Adds precedence rules (specific findings hiding generic ones), applied by the
   * pipeline after rule overrides. See scanner/precedence.ts.
   */
  registerPrecedence(rules: readonly PrecedenceRule[]): void {
    this.precedence.push(...rules);
  }

  /** All registered precedence rules, in registration order. */
  getPrecedence(): readonly PrecedenceRule[] {
    return this.precedence;
  }

  /**
   * Runs all registered detectors against the provided context.
   */
  async runAll(
    context: ScanContext,
    onProgress?: (message: string, current: number, total: number) => void,
  ): Promise<{
    findings: Finding[];
    errors: { detectorId: string; detectorName: string; message: string }[];
  }> {
    const findings: Finding[] = [];
    const errors: { detectorId: string; detectorName: string; message: string }[] = [];

    // Filter detectors based on config.enabledCategories
    const enabledCategories = context.config.enabledCategories;
    const disabled = context.config.disabledDetectors ?? [];
    const activeDetectors = this.detectors.filter(
      (d) =>
        (!enabledCategories || enabledCategories.includes(d.category)) && !disabled.includes(d.id),
    );

    const total = activeDetectors.length;
    let completed = 0;

    // Enforce config.timeoutMs: the deadline is checked between detectors. On
    // timeout we stop, keep the findings gathered so far and record an error.
    const timeoutMs = context.config.timeoutMs;
    const deadline = timeoutMs !== undefined ? Date.now() + timeoutMs : undefined;

    // Run detectors sequentially to allow meaningful progress updates
    for (const detector of activeDetectors) {
      if (deadline !== undefined && Date.now() >= deadline) {
        const skipped = activeDetectors.slice(completed).map((d) => d.id);
        errors.push({
          detectorId: "scan-timeout",
          detectorName: "Scan timeout",
          message: `Scan exceeded timeoutMs (${timeoutMs}ms); skipped ${skipped.length} detector(s): ${skipped.join(", ")}. Results are partial.`,
        });
        break;
      }

      if (onProgress) {
        onProgress(`Running ${detector.constructor.name}...`, completed, total);
      }

      try {
        const result = await detector.detect(context);
        findings.push(...result);
      } catch (error: unknown) {
        errors.push({
          detectorId: detector.id,
          detectorName: detector.name,
          message: error instanceof Error ? error.message : String(error),
        });
      }

      completed++;
      if (onProgress) {
        onProgress(`Finished ${detector.constructor.name}`, completed, total);
      }
    }

    return { findings, errors };
  }
}
