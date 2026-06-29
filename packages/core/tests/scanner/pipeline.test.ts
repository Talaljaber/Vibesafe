import { describe, it, expect } from "vitest";
import path from "node:path";
import { ScannerPipeline } from "../../src/scanner/pipeline.js";
import { DetectorRegistry } from "../../src/scanner/detector-registry.js";
import type { Detector, Finding, ScanContext } from "@vibeguard/shared";

class MockDetector implements Detector {
  id = "mock-detector";
  name = "Mock Detector";
  category = "secret" as const;
  description = "A mock detector for testing";

  async detect(context: ScanContext): Promise<Finding[]> {
    // Produce one critical finding
    return [
      {
        id: "SEC-mock-123",
        ruleId: "mock/rule",
        title: "Mock secret found",
        severity: "critical",
        category: "secret",
        deployBlocking: true,
        confidence: "high",
        plainEnglishProblem: "You have a mock secret.",
        whyItMatters: "Mock secrets matter.",
        fixSteps: ["Remove the mock secret."],
        autoFixAvailable: false,
      }
    ];
  }
}

describe("ScannerPipeline", () => {
  const fixturePath = path.resolve(__dirname, "../../../../fixtures/nextjs-vibecoded-bad-app");

  it("should run the pipeline and aggregate results", async () => {
    const registry = new DetectorRegistry();
    registry.register(new MockDetector());

    const pipeline = new ScannerPipeline(registry);
    
    const result = await pipeline.scan({ rootPath: fixturePath });

    expect(result.projectPath).toBe(fixturePath);
    expect(result.findings.length).toBe(1);
    expect(result.findings[0]!.id).toBe("SEC-mock-123");
    
    // Test scoring
    // Base 100
    // Critical: -20 * 1.5 (secret multiplier) = -30
    // Score should be 70
    expect(result.score).toBe(70);
    
    // Test deployStatus
    // Since there's a critical finding, it should be "blocker" regardless of score
    expect(result.deployStatus).toBe("blocker");

    // Summary checks
    expect(result.summary.totalFindings).toBe(1);
    expect(result.summary.criticalCount).toBe(1);
    expect(result.summary.categoryCounts.secret).toBe(1);

    // Repair plan checks
    expect(result.repairPlan.steps.length).toBe(1);
    expect(result.repairPlan.estimatedMinutes).toBe(15); // Critical = 15
  });

  it("should respect minSeverity configuration", async () => {
    const registry = new DetectorRegistry();
    // A detector producing a low severity finding
    registry.register({
      id: "mock-low",
      name: "Mock Low",
      category: "code_quality",
      description: "Low mock",
      detect: async () => [{
        id: "QUAL-mock-low",
        ruleId: "mock/low",
        title: "Low issue",
        severity: "low",
        category: "code_quality",
        deployBlocking: false,
        confidence: "high",
        plainEnglishProblem: "Low issue.",
        whyItMatters: "Doesn't matter much.",
        fixSteps: ["Ignore it."],
        autoFixAvailable: false,
      }]
    });

    const pipeline = new ScannerPipeline(registry);
    
    // minSeverity 'medium' means 'low' findings should be excluded
    const result = await pipeline.scan({ rootPath: fixturePath, minSeverity: "medium" });

    expect(result.findings.length).toBe(0);
  });
});
