import type { ScanResult } from "@vibesafe/shared";

/**
 * Token budgeting for vibesafe_scan.
 *
 * A raw ScanResult on a messy project can carry dozens of findings, each with
 * multi-paragraph explanations — far too large to hand an agent directly.
 * We return a bounded summary instead: header stats + the top N findings as
 * one line each, with a pointer to vibesafe_explain for full detail.
 */

export const DEFAULT_TOP_FINDINGS_LIMIT = 10;

export interface TopFinding {
  id: string;
  title: string;
  severity: string;
  category: string;
  location: string;
}

export interface ScanSummaryPayload {
  score: number;
  deployStatus: string;
  totalFindings: number;
  severityCounts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  filesScanned: number;
  durationMs: number;
  topFindings: TopFinding[];
  truncatedCount: number;
}

function locationOf(f: { file?: string | undefined; line?: number | undefined }): string {
  if (!f.file) return "(project-level)";
  return f.line ? `${f.file}:${f.line}` : f.file;
}

export function summarizeScanResult(
  result: ScanResult,
  limit: number = DEFAULT_TOP_FINDINGS_LIMIT,
): ScanSummaryPayload {
  const top = result.findings.slice(0, limit);

  return {
    score: result.score,
    deployStatus: result.deployStatus,
    totalFindings: result.summary.totalFindings,
    severityCounts: {
      critical: result.summary.criticalCount,
      high: result.summary.highCount,
      medium: result.summary.mediumCount,
      low: result.summary.lowCount,
    },
    filesScanned: result.summary.filesScanned,
    durationMs: result.durationMs,
    topFindings: top.map((f) => ({
      id: f.id,
      title: f.title,
      severity: f.severity,
      category: f.category,
      location: locationOf(f),
    })),
    truncatedCount: Math.max(0, result.findings.length - top.length),
  };
}

export function formatScanSummaryText(payload: ScanSummaryPayload): string {
  const lines: string[] = [];

  lines.push(`VibeSafe scan — score ${payload.score}/100 (${payload.deployStatus.toUpperCase()})`);
  lines.push(
    `${payload.totalFindings} finding(s) across ${payload.filesScanned} file(s) — ` +
      `critical: ${payload.severityCounts.critical}, high: ${payload.severityCounts.high}, ` +
      `medium: ${payload.severityCounts.medium}, low: ${payload.severityCounts.low}`,
  );
  lines.push("");

  if (payload.topFindings.length === 0) {
    lines.push("No findings. This project looks clean.");
  } else {
    lines.push(`Top ${payload.topFindings.length} finding(s):`);
    for (const f of payload.topFindings) {
      lines.push(`- [${f.severity.toUpperCase()}] ${f.id} — ${f.title} (${f.location})`);
    }
    if (payload.truncatedCount > 0) {
      lines.push(`...and ${payload.truncatedCount} more finding(s) not shown.`);
    }
  }

  lines.push("");
  lines.push(
    "Call vibesafe_explain with a finding ID for full detail and fix steps, " +
      "or vibesafe_repair_plan for the prioritized fix order.",
  );

  return lines.join("\n");
}
