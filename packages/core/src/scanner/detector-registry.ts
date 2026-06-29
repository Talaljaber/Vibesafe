import type { Detector, Finding, ScanContext } from "@vibesafe/shared";

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
  async runAll(context: ScanContext, onProgress?: (message: string, current: number, total: number) => void): Promise<{ findings: Finding[]; errors: { detectorId: string; detectorName: string; message: string }[] }> {
    const findings: Finding[] = [];
    const errors: { detectorId: string; detectorName: string; message: string }[] = [];

    // Filter detectors based on config.enabledCategories
    const enabledCategories = context.config.enabledCategories;
    const activeDetectors = this.detectors.filter(d => 
      !enabledCategories || enabledCategories.includes(d.category)
    );

    const total = activeDetectors.length;
    let completed = 0;

    // Run detectors sequentially to allow meaningful progress updates
    for (const detector of activeDetectors) {
      if (onProgress) {
        onProgress(`Running ${detector.constructor.name}...`, completed, total);
      }
      
      try {
        const result = await detector.detect(context);
        findings.push(...result);
      } catch (error: any) {
        errors.push({
          detectorId: detector.id,
          detectorName: detector.name,
          message: error.message || String(error)
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
