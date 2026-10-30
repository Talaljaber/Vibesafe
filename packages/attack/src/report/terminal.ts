import { diffFor, ledgerLine, oneLine, routeText, safeId } from "./text.js";
import type { AttackRun } from "../types.js";

export interface TerminalOptions {
  /** Path shown for the HTML report. */
  htmlReportPath?: string | undefined;
  /** Path of the agent report named in the hint. */
  markdownReportPath?: string | undefined;
}

/**
 * Returns terminal lines for a run. The CLI still passes them through sanitizeTerminal
 * before printing; the text here is already control-character free.
 */
export function renderTerminalSummary(run: AttackRun, options: TerminalOptions = {}): string[] {
  const md = options.markdownReportPath ?? ".vibesafe/attack-report.md";
  const html = options.htmlReportPath ?? ".vibesafe/attack-report.html";
  const lines: string[] = [ledgerLine(run.ledger), ""];
  const rows = run.results.map((r) => {
    const d = diffFor(run, r.attackId);
    return [d ? d.state : r.outcome, safeId(r.attackId), oneLine(r.title, 70), routeText(r)];
  });
  const w0 = Math.max(0, ...rows.map((r) => (r[0] ?? "").length));
  const w1 = Math.max(0, ...rows.map((r) => (r[1] ?? "").length));
  for (const [state = "", id = "", title = "", route = ""] of rows) {
    lines.push(`${state.padEnd(w0)}  ${id.padEnd(w1)}  ${title}${route ? `  ${route}` : ""}`);
  }
  if (rows.length > 0) lines.push("");
  if (run.ledger.errors > 0) lines.push(`Errors: ${run.ledger.errors}`);
  const needsFix = run.results.some((r) => {
    const s = diffFor(run, r.attackId)?.state;
    return s !== undefined
      ? s === "STILL_VULNERABLE" || s === "NEW" || s === "BROKEN"
      : r.outcome === "CONFIRMED";
  });
  if (needsFix) lines.push(`Tell your agent: "Fix the issues in ${oneLine(md, 160)}"`);
  if (run.mode !== "dry-run") lines.push(`HTML report: ${oneLine(html, 160)}`);
  return lines;
}
