import type { Finding, ScanResult, Severity } from "@vibesafe/shared";

/** Hidden marker the GitHub Action uses to find and update its sticky PR comment. */
export const PR_COMMENT_MARKER = "<!-- vibesafe-pr-comment -->";

const MAX_TOP_FINDINGS = 10;
const MAX_DETAIL_FINDINGS = 50;

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const SEVERITY_ICON: Record<Severity, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
};
const STATUS_LINE: Record<ScanResult["deployStatus"], string> = {
  blocker: "❌ **Blocker** - do not deploy",
  danger: "❌ **Danger** - do not deploy",
  warning: "⚠️ **Warning** - fix before production",
  safe: "✅ **Safe** - ready to deploy",
};

/** Neutralise characters that would break out of inline markdown, tables or HTML. */
export function escapeMarkdown(text: string): string {
  return text
    .replace(/\r?\n/g, " ")
    .replace(/&/g, "&amp;")
    .replace(/[\\`*_{}[\]<>|#]/g, (c) => `\\${c}`)
    .trim();
}

function location(f: Finding): string {
  if (!f.file) return "";
  const file = f.file.replace(/\\/g, "/").replace(/[`\r\n]/g, "'");
  return f.line ? `${file}:${f.line}` : file;
}

function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      (a.file ?? "").localeCompare(b.file ?? "") ||
      (a.line ?? 0) - (b.line ?? 0),
  );
}

function bullet(f: Finding): string {
  const loc = location(f);
  const where = loc ? ` (\`${loc}\`)` : "";
  return `- ${SEVERITY_ICON[f.severity]} **${f.severity}**: ${escapeMarkdown(f.title)}${where}`;
}

/**
 * Render a concise markdown summary of a scan, suitable for a pull request
 * comment. Never includes finding evidence (it may contain secrets).
 */
export function formatMarkdownReport(result: ScanResult): string {
  const s = result.summary;
  const lines: string[] = [];

  lines.push(PR_COMMENT_MARKER);
  // Machine-readable status, read by the composite action to apply fail-on.
  lines.push(`<!-- vibesafe-status:${result.deployStatus} -->`);
  lines.push("## VibeSafe scan");
  lines.push("");
  lines.push(`**Score:** ${result.score}/100 | **Status:** ${STATUS_LINE[result.deployStatus]}`);
  lines.push("");
  lines.push("| Critical | High | Medium | Low | Total |");
  lines.push("| ---: | ---: | ---: | ---: | ---: |");
  lines.push(
    `| ${s.criticalCount} | ${s.highCount} | ${s.mediumCount} | ${s.lowCount} | ${s.totalFindings} |`,
  );
  lines.push("");

  const sorted = sortFindings(result.findings);

  if (sorted.length === 0) {
    lines.push("No findings. VibeSafe is a heuristic scan, not a full security audit.");
  } else {
    const top = sorted.slice(0, MAX_TOP_FINDINGS);
    lines.push("### Top findings");
    lines.push("");
    for (const f of top) lines.push(bullet(f));
    if (sorted.length > top.length) {
      lines.push("");
      lines.push(`...and ${sorted.length - top.length} more (see details below).`);
    }

    lines.push("");
    lines.push("<details>");
    lines.push(`<summary>All findings (${sorted.length})</summary>`);
    lines.push("");
    for (const f of sorted.slice(0, MAX_DETAIL_FINDINGS)) {
      lines.push(bullet(f));
      lines.push(`  - ${escapeMarkdown(f.plainEnglishProblem)}`);
      const first = f.fixSteps[0];
      if (first) lines.push(`  - Fix: ${escapeMarkdown(first)}`);
    }
    if (sorted.length > MAX_DETAIL_FINDINGS) {
      lines.push("");
      lines.push(
        `...${sorted.length - MAX_DETAIL_FINDINGS} more not shown. Run \`vibesafe scan\` locally for the full list.`,
      );
    }
    lines.push("");
    lines.push("</details>");
  }

  if (result.errors && result.errors.length > 0) {
    lines.push("");
    lines.push(`> ⚠️ ${result.errors.length} detector(s) failed; results may be incomplete.`);
  }
  if (result.warnings && result.warnings.length > 0) {
    for (const w of result.warnings) {
      lines.push("");
      lines.push(`> ⚠️ ${escapeMarkdown(w)}`);
    }
  }

  lines.push("");
  lines.push(
    `<sub>${s.filesScanned} files scanned by [VibeSafe](https://github.com/Talaljaber/Vibesafe)</sub>`,
  );
  return lines.join("\n") + "\n";
}
