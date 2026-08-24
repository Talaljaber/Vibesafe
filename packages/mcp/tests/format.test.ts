import { describe, it, expect } from "vitest";
import type { Finding, ScanResult, ProjectContext } from "@vibesafe/shared";
import { summarizeScanResult, formatScanSummaryText, DEFAULT_TOP_FINDINGS_LIMIT } from "../src/format.js";

function makeFinding(overrides: Partial<Finding> & { id: string; severity: Finding["severity"] }): Finding {
  return {
    ruleId: "mock/rule",
    title: "Mock finding",
    category: "secret",
    deployBlocking: false,
    confidence: "high",
    plainEnglishProblem: "Something is wrong.",
    whyItMatters: "It matters a lot.",
    fixSteps: ["Fix it."],
    autoFixAvailable: false,
    file: "src/index.ts",
    line: 1,
    ...overrides,
  };
}

const projectContext: ProjectContext = {
  framework: "nextjs",
  language: "typescript",
  hasTypeScript: true,
  packageManager: "pnpm",
  dependencies: {},
  devDependencies: {},
  scripts: {},
  hasGitignore: true,
  hasEnvFile: false,
  hasEnvExample: false,
  hasReadme: true,
  hasTests: false,
};

function makeScanResult(findings: Finding[]): ScanResult {
  return {
    timestamp: new Date().toISOString(),
    projectPath: "/tmp/project",
    projectContext,
    findings,
    score: 24,
    deployStatus: "danger",
    summary: {
      totalFindings: findings.length,
      criticalCount: findings.filter((f) => f.severity === "critical").length,
      highCount: findings.filter((f) => f.severity === "high").length,
      mediumCount: findings.filter((f) => f.severity === "medium").length,
      lowCount: findings.filter((f) => f.severity === "low").length,
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
      filesScanned: 42,
      linesScanned: 0,
    },
    repairPlan: { steps: [], estimatedMinutes: 0, summary: "" },
    durationMs: 123,
    errors: [],
  };
}

describe("summarizeScanResult", () => {
  it("caps topFindings at the limit and reports the truncated count", () => {
    const findings = Array.from({ length: 15 }, (_, i) =>
      makeFinding({ id: `SEC-${i}`, severity: "high", title: `Finding ${i}` }),
    );
    const result = makeScanResult(findings);

    const summary = summarizeScanResult(result);

    expect(summary.topFindings).toHaveLength(DEFAULT_TOP_FINDINGS_LIMIT);
    expect(summary.truncatedCount).toBe(15 - DEFAULT_TOP_FINDINGS_LIMIT);
    expect(summary.totalFindings).toBe(15);
  });

  it("carries through score, deploy status, and severity counts", () => {
    const findings = [
      makeFinding({ id: "SEC-1", severity: "critical" }),
      makeFinding({ id: "SEC-2", severity: "high" }),
      makeFinding({ id: "SEC-3", severity: "medium" }),
      makeFinding({ id: "SEC-4", severity: "low" }),
    ];
    const result = makeScanResult(findings);
    result.score = 24;
    result.deployStatus = "danger";

    const summary = summarizeScanResult(result);

    expect(summary.score).toBe(24);
    expect(summary.deployStatus).toBe("danger");
    expect(summary.severityCounts).toEqual({ critical: 1, high: 1, medium: 1, low: 1 });
    expect(summary.filesScanned).toBe(42);
  });

  it("formats a finding's location as file:line, or file alone, or project-level", () => {
    const findings = [
      makeFinding({ id: "A", severity: "high", file: "src/a.ts", line: 10 }),
      makeFinding({ id: "B", severity: "high", file: "src/b.ts", line: undefined }),
      makeFinding({ id: "C", severity: "high", file: undefined, line: undefined }),
    ];
    const summary = summarizeScanResult(makeScanResult(findings));

    expect(summary.topFindings[0]?.location).toBe("src/a.ts:10");
    expect(summary.topFindings[1]?.location).toBe("src/b.ts");
    expect(summary.topFindings[2]?.location).toBe("(project-level)");
  });

  it("handles an empty findings list", () => {
    const summary = summarizeScanResult(makeScanResult([]));
    expect(summary.topFindings).toHaveLength(0);
    expect(summary.truncatedCount).toBe(0);
  });
});

describe("formatScanSummaryText", () => {
  it("produces a bounded human-readable report with a pointer to vibesafe_explain", () => {
    const findings = [makeFinding({ id: "SEC-1", severity: "critical", title: "Leaked API key" })];
    const summary = summarizeScanResult(makeScanResult(findings));

    const text = formatScanSummaryText(summary);

    expect(text).toContain("score 24/100");
    expect(text).toContain("DANGER");
    expect(text).toContain("SEC-1");
    expect(text).toContain("Leaked API key");
    expect(text).toContain("vibesafe_explain");
    expect(text).toContain("vibesafe_repair_plan");
  });

  it("mentions the truncated count when findings exceed the top-N cap", () => {
    const findings = Array.from({ length: 12 }, (_, i) =>
      makeFinding({ id: `SEC-${i}`, severity: "medium", title: `Finding ${i}` }),
    );
    const text = formatScanSummaryText(summarizeScanResult(makeScanResult(findings)));

    expect(text).toContain("2 more finding(s) not shown");
  });

  it("reports a clean result when there are no findings", () => {
    const text = formatScanSummaryText(summarizeScanResult(makeScanResult([])));
    expect(text).toContain("looks clean");
  });
});
