import type { Detector, Finding, ScanContext } from "@vibeguard/shared";

import { SecretDetector } from "../detectors/secret-detector.js";
import { FrontendExposureDetector } from "../detectors/frontend-exposure-detector.js";
import { MissingAuthDetector } from "../detectors/missing-auth-detector.js";
import { MissingValidationDetector } from "../detectors/missing-validation-detector.js";
import { MissingAuthorizationDetector } from "../detectors/missing-authorization-detector.js";
import { DependencyDetector } from "../detectors/dependency-detector.js";
import { CodebaseMessDetector } from "../detectors/codebase-mess-detector.js";
import { ProjectStructureDetector } from "../detectors/project-structure-detector.js";

export function createDefaultRegistry(): DetectorRegistry {
  const registry = new DetectorRegistry();
  registry.register(new SecretDetector());
  registry.register(new FrontendExposureDetector());
  registry.register(new MissingAuthDetector());
  registry.register(new MissingValidationDetector());
  registry.register(new MissingAuthorizationDetector());
  registry.register(new DependencyDetector());
  registry.register(new CodebaseMessDetector());
  registry.register(new ProjectStructureDetector());
  return registry;
}
export class DetectorRegistry {
  private detectors: Detector[] = [];

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
   * Runs all registered detectors against the provided context.
   */
  async runAll(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Filter detectors based on config.enabledCategories
    const enabledCategories = context.config.enabledCategories;
    const activeDetectors = this.detectors.filter(d => 
      !enabledCategories || enabledCategories.includes(d.category)
    );

    // Run all detectors in parallel
    const results = await Promise.all(
      activeDetectors.map(async (detector) => {
        try {
          return await detector.detect(context);
        } catch (error) {
          // In a real app, we might want to log this or report detector failures
          // For now, we swallow the error and return no findings for this detector
          // to prevent one bad detector from failing the entire scan.
          return [];
        }
      })
    );

    // Flatten results
    for (const result of results) {
      findings.push(...result);
    }

    return findings;
  }
}
