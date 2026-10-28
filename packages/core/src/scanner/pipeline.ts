import fs from "node:fs/promises";
import path from "node:path";
import type { ScanConfig, ScanResult, ScanContext, Finding, ScanSummary, RepairPlan } from "@vibesafe/shared";
import {
  getDeployStatus,
  isDeployBlocker,
  isMoreSevere,
  MAX_FILE_SIZE_BYTES,
  SEVERITY_WEIGHTS,
  CATEGORY_MULTIPLIERS,
} from "@vibesafe/shared";
import { FileDiscovery } from "./file-discovery.js";
import { applyInlineIgnores } from "./inline-ignores.js";
import { ProjectContextBuilder } from "./project-context.js";
import type { DetectorRegistry } from "./detector-registry.js";
import { mergeConfig } from "../config/defaults.js";
import { validateConfig } from "../config/schema.js";
import { loadUserConfig } from "../config/load-config.js";
import { applyRuleOverrides } from "./rule-overrides.js";

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
    const warnings: string[] = [];
    // Config file values are the base; explicit (defined) options win.
    let effective: Partial<ScanConfig> = userConfig;
    if (userConfig.useConfigFile !== false) {
      const loaded = await loadUserConfig(userConfig.rootPath);
      if (loaded) {
        const explicit = Object.fromEntries(
          Object.entries(userConfig).filter(([, v]) => v !== undefined),
        );
        effective = { ...loaded.scanConfig, ...explicit };
      }
    }
    const config = mergeConfig(userConfig.rootPath, effective);
    
    // Validate config
    const errors = validateConfig(config);
    if (errors.length > 0) {
      throw new Error(`Invalid configuration: ${errors.map(e => e.message).join(", ")}`);
    }

    // 1. Discover files
    const fileDiscovery = new FileDiscovery(config.rootPath);
    let files = config.targetFiles && config.targetFiles.length > 0 
      ? config.targetFiles 
      : await fileDiscovery.discoverFiles(config.excludePatterns, {
          // Not in mergeConfig's defaults; undefined/false = exclude tests.
          includeTests: config.includeTests,
        });
    
    if (config.maxFiles && files.length > config.maxFiles) {
      // Trim to maxFiles if we exceed the limit to prevent out-of-memory or hanging
      warnings.push(
        `Found ${files.length} files but maxFiles is ${config.maxFiles}; only the first ${config.maxFiles} were scanned. Raise maxFiles to scan everything.`,
      );
      files = files.slice(0, config.maxFiles);
    }

    // 2. Build project context
    const contextBuilder = new ProjectContextBuilder(config.rootPath);
    const projectContext = await contextBuilder.build();

    // 3. Create ScanContext with file caching
    const fileCache = new Map<string, string>();
    const skippedLarge = new Set<string>();
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
          // Never read through symlinks, and skip oversized files.
          const stat = await fs.lstat(absolutePath);
          if (stat.isSymbolicLink()) return "";
          if (stat.size > MAX_FILE_SIZE_BYTES) {
            skippedLarge.add(relativePath);
            return "";
          }
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
    const runResult = await this.registry.runAll(scanContext, onProgress);
    const detectorErrors = runResult.errors;
    let findings = runResult.findings;

    // 4.5. Apply inline ignores
    findings = await applyInlineIgnores(findings, scanContext.readFile);

    // 4.6. Apply rule overrides ("off" drops; severity changes are scored/sorted below)
    findings = applyRuleOverrides(findings, config.ruleOverrides);

    // 5. Score BEFORE the minSeverity filter. minSeverity only controls which
    // findings are displayed; filtering must not inflate the score or hide a
    // deploy blocker.
    const { score, deployStatus } = this.calculateScore(findings);

    // 5.5. Filter findings based on config
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
    let linesScanned = 0;
    for (const content of fileCache.values()) linesScanned += countLines(content);
    const summary = this.buildSummary(findings, files.length, linesScanned);
    const repairPlan = this.buildRepairPlan(findings);

    const durationMs = Date.now() - startTime;

    if (skippedLarge.size > 0) {
      warnings.push(
        `Skipped ${skippedLarge.size} file(s) larger than ${MAX_FILE_SIZE_BYTES} bytes: ${[...skippedLarge].slice(0, 5).join(", ")}${skippedLarge.size > 5 ? ", ..." : ""}`,
      );
    }
    if (detectorErrors.some((e) => e.detectorId === "scan-timeout")) {
      warnings.push("Scan timed out; results are partial.");
    }

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
      errors: detectorErrors,
      ...(warnings.length > 0 ? { warnings } : {}),
    };
  }

  public calculateScore(findings: Finding[]): { score: number; deployStatus: ReturnType<typeof getDeployStatus> } {
    let score = 100;
    let hasBlocker = false;

    for (const finding of findings) {
      // Critical severity or an explicit deployBlocking flag forces "blocker".
      if (isDeployBlocker(finding)) {
        hasBlocker = true;
      }

      const rawWeight = SEVERITY_WEIGHTS[finding.severity];
      const multiplier = CATEGORY_MULTIPLIERS[finding.category];
      score += (rawWeight * multiplier);
    }

    score = Math.max(0, Math.round(score));

    return {
      score,
      deployStatus: getDeployStatus(score, hasBlocker),
    };
  }

  public buildSummary(findings: Finding[], filesScanned: number, linesScanned = 0): ScanSummary {
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
        xss: 0,
      },
      filesScanned,
      linesScanned,
    };

    for (const finding of findings) {
      summary[`${finding.severity}Count`]++;
      summary.categoryCounts[finding.category]++;
    }

    return summary;
  }

  public buildRepairPlan(findings: Finding[]): RepairPlan {
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

/** Counts lines in a file's content (0 for empty content). */
function countLines(content: string): number {
  if (content.length === 0) return 0;
  let n = 1;
  for (let i = 0; i < content.length; i++) if (content.charCodeAt(i) === 10) n++;
  return content.endsWith("\n") ? n - 1 : n;
}
