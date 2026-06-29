import type { Detector, Finding, ScanContext } from "@vibeguard/shared";

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
