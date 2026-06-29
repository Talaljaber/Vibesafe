import fs from "node:fs/promises";
import path from "node:path";
import type { ScanConfig, ScanResult, ScanContext, Finding, ScanSummary, RepairPlan } from "@vibeguard/shared";
import { getDeployStatus, isMoreSevere, SEVERITY_WEIGHTS, CATEGORY_MULTIPLIERS } from "@vibeguard/shared";
import { FileDiscovery } from "./file-discovery.js";
import { ProjectContextBuilder } from "./project-context.js";
import { DetectorRegistry } from "./detector-registry.js";
import { mergeConfig } from "../config/defaults.js";
import { validateConfig } from "../config/schema.js";

export class ScannerPipeline {
  private registry: DetectorRegistry;

  constructor(registry: DetectorRegistry) {
    this.registry = registry;
  }

  /**
   * Runs the full scanning pipeline on a project.
   */
  async scan(userConfig: Partial<ScanConfig> & { rootPath: string }, onProgress?: (message: string, current: number, total: number) => void): Promise<ScanResult> {
    const startTime = Date.now();
    const config = mergeConfig(userConfig.rootPath, userConfig);
    
    // Validate config
    const errors = validateConfig(config);
    if (errors.length > 0) {
      throw new Error(`Invalid configuration: ${errors.map(e => e.message).join(", ")}`);
    }

    // 1. Discover files
    const fileDiscovery = new FileDiscovery(config.rootPath);
    let files = await fileDiscovery.discoverFiles(config.excludePatterns);
    
    if (config.maxFiles && files.length > config.maxFiles) {
      // Trim to maxFiles if we exceed the limit to prevent out-of-memory or hanging
      files = files.slice(0, config.maxFiles);
    }

    // 2. Build project context
    const contextBuilder = new ProjectContextBuilder(config.rootPath);
    const projectContext = await contextBuilder.build();

    // 3. Create ScanContext with file caching
    const fileCache = new Map<string, string>();
    const scanContext: ScanContext = {
      rootPath: config.rootPath,
      projectContext,
      files,
      config,
      readFile: async (relativePath: string) => {
        if (fileCache.has(relativePath)) {
          return fileCache.get(relativePath)!;
        }
        const absolutePath = path.join(config.rootPath, relativePath);
        try {
          const content = await fs.readFile(absolutePath, "utf-8");
          fileCache.set(relativePath, content);
          return content;
        } catch {
          // If we fail to read a file, return empty string so detectors don't crash
          return "";
        }
      }
    };

    // 4. Run detectors
    let findings = await this.registry.runAll(scanContext, onProgress);

    // 5. Filter findings based on config
    if (config.minSeverity) {
      findings = findings.filter(f => 
        // Keep if finding severity is >= minSeverity. lower index means more severe
        !isMoreSevere(config.minSeverity!, f.severity)
      );
    }

    // Sort findings by severity (critical first)
    findings.sort((a, b) => {
      if (a.severity === b.severity) return 0;
      return isMoreSevere(a.severity, b.severity) ? -1 : 1;
    });

    // 6. Calculate scoring and build repair plan
    const { score, deployStatus } = this.calculateScore(findings);
    const summary = this.buildSummary(findings, files.length);
    const repairPlan = this.buildRepairPlan(findings);

    const durationMs = Date.now() - startTime;

    return {
      timestamp: new Date().toISOString(),
      projectPath: config.rootPath,
      projectContext,
      findings,
      score,
      deployStatus,
      summary,
      repairPlan,
      durationMs,
    };
  }

  private calculateScore(findings: Finding[]): { score: number; deployStatus: ReturnType<typeof getDeployStatus> } {
    let score = 100;
    let hasCritical = false;

    for (const finding of findings) {
      if (finding.severity === "critical") {
        hasCritical = true;
      }
      
      const rawWeight = SEVERITY_WEIGHTS[finding.severity];
      const multiplier = CATEGORY_MULTIPLIERS[finding.category];
      score += (rawWeight * multiplier);
    }

    score = Math.max(0, Math.round(score));

    return {
      score,
      deployStatus: getDeployStatus(score, hasCritical),
    };
  }

  private buildSummary(findings: Finding[], filesScanned: number): ScanSummary {
    const summary: ScanSummary = {
      totalFindings: findings.length,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      categoryCounts: {
        secret: 0,
        auth: 0,
        authorization: 0,
        frontend_exposure: 0,
        validation: 0,
        dependency: 0,
        code_quality: 0,
        structure: 0,
      },
      filesScanned,
      linesScanned: 0, // We don't count lines in Phase 1-2 for simplicity
    };

    for (const finding of findings) {
      summary[`${finding.severity}Count`]++;
      summary.categoryCounts[finding.category]++;
    }

    return summary;
  }

  private buildRepairPlan(findings: Finding[]): RepairPlan {
    const steps = findings.map((f, i) => ({
      order: i + 1,
      findingId: f.id,
      title: f.title,
      severity: f.severity,
      category: f.category,
      file: f.file,
      line: f.line,
      description: f.whyItMatters,
      fixSteps: f.fixSteps,
      aiFixPrompt: f.aiFixPrompt,
      autoFixAvailable: f.autoFixAvailable,
      estimatedMinutes: f.severity === 'critical' ? 15 : f.severity === 'high' ? 10 : 5,
    }));

    const totalMinutes = steps.reduce((sum, step) => sum + step.estimatedMinutes, 0);

    return {
      steps,
      estimatedMinutes: totalMinutes,
      summary: `Found ${findings.length} issues needing your attention. Expected fix time: ~${totalMinutes} mins.`,
    };
  }
}
