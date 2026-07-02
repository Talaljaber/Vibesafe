import fs from "node:fs/promises";
import path from "node:path";
import type { ScanResult } from "@vibesafe/shared";

function escapeHtml(unsafe: string) {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export async function generateHtmlReport(result: ScanResult): Promise<string> {
  const totalFindings = result.summary.totalFindings;
  const critical = result.summary.criticalCount;
  const high = result.summary.highCount;
  const medium = result.summary.mediumCount || 0;
  const low = result.summary.lowCount || 0;
  
  let reason = "No obvious deployment blockers found in this scan.";
  if (critical > 0 && high > 0) {
    reason = critical + " critical issues and " + high + " high severity issues found.";
  } else if (critical > 0) {
    reason = critical + " critical issues found.";
  } else if (high > 0) {
    reason = high + " high severity issues found.";
  } else if (totalFindings > 0) {
    reason = totalFindings + " issues found.";
  }

  const firstStep = result.repairPlan.steps[0];
  const nextAction = firstStep ? "Start with: " + escapeHtml(firstStep.title) : "No actions required.";

  const statusClass = result.deployStatus.toLowerCase() === 'ready' ? 'low-pill' : 
                     (critical > 0 ? 'critical-pill' : 'high-pill');

  const critPct = totalFindings ? (critical / totalFindings) * 100 : 0;
  const highPct = totalFindings ? (high / totalFindings) * 100 : 0;
  const medPct = totalFindings ? (medium / totalFindings) * 100 : 0;
  const lowPct = totalFindings ? (low / totalFindings) * 100 : 0;

  let errorsHtml = '';
  if (result.errors && result.errors.length > 0) {
    errorsHtml = `
      <div class="error-banner">
        <h3>Some detectors failed. Results may be incomplete.</h3>
        <ul>
          ${result.errors.map((e: any) => `<li>${escapeHtml(e.detector)}: ${escapeHtml(e.message)}</li>`).join('')}
        </ul>
      </div>
    `;
  }

  let stepsHtml = '';
  if (result.repairPlan.steps.length === 0) {
    stepsHtml = `
      <div class="empty-state" style="padding: 40px 0;">
        <h3 style="margin-bottom: 8px;">No obvious deployment blockers found.</h3>
        <p style="color: var(--text-muted); font-size: 14px;">VibeSafe performs a heuristic scan and is not a full security audit.</p>
      </div>
    `;
  } else {
    stepsHtml = result.repairPlan.steps.map((step: any) => {
      const sevClass = step.severity.toLowerCase();
      return `
        <div class="issue-card" data-severity="${sevClass}">
          <div class="issue-header">
            <span class="severity-pill ${sevClass}-pill">${escapeHtml(step.severity)}</span>
            <h3 class="issue-title">${escapeHtml(step.title)}</h3>
          </div>
          ${step.file ? `<div class="filepath-pill">${escapeHtml(step.file)}${step.line ? `:${step.line}` : ''}</div>` : ''}
          <div class="issue-desc">${escapeHtml(step.description)}</div>
          <ol class="fix-steps">
            ${step.fixSteps.map((f: string) => `<li>${escapeHtml(f)}</li>`).join('')}
          </ol>
          ${step.aiFixPrompt ? `
            <div class="ai-prompt">
              <div class="ai-prompt-header">✨ AI Prompt</div>
              ${escapeHtml(step.aiFixPrompt)}
            </div>
          ` : ''}
        </div>
      `;
    }).join('');
  }

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VibeSafe Security Report</title>
  <style>
    :root {
      --bg: #0d1117;
      --text: #c9d1d9;
      --text-muted: #8b949e;
      --panel: #161b22;
      --border: #30363d;
      --primary: #58a6ff;
      --critical: #f85149;
      --high: #d29922;
      --medium: #e3b341;
      --low: #2ea043;
      
      --critical-bg: rgba(248, 81, 73, 0.1);
      --high-bg: rgba(210, 153, 34, 0.1);
      --medium-bg: rgba(227, 179, 65, 0.1);
      --low-bg: rgba(46, 160, 67, 0.1);
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.5;
      margin: 0;
      padding: 40px 20px;
    }
    .container {
      max-width: 900px;
      margin: 0 auto;
    }
    h1, h2, h3, h4, h5 {
      margin-top: 0;
      margin-bottom: 16px;
      font-weight: 600;
    }
    h1 {
      font-size: 24px;
      margin-bottom: 4px;
    }
    .subtitle {
      color: var(--text-muted);
      font-size: 14px;
      margin-bottom: 24px;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 24px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 24px;
    }
    .header-left {
      display: flex;
      flex-direction: column;
    }
    .meta-info {
      font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
      font-size: 12px;
      color: var(--text-muted);
      margin-top: 8px;
    }
    .status-pill {
      padding: 6px 12px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 600;
      border: 1px solid;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    
    .panel {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 24px;
    }
    .panel-header {
      margin-bottom: 16px;
      font-size: 16px;
      font-weight: 600;
    }
    
    /* Deployment Decision */
    .decision-panel {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .decision-title {
      font-size: 16px;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .decision-reason {
      color: var(--text-muted);
      font-size: 14px;
    }
    .decision-action {
      margin-top: 4px;
      font-weight: 500;
      font-size: 14px;
    }
    
    /* Metrics Row */
    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .metric-card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
    }
    .metric-value {
      font-size: 24px;
      font-weight: 600;
      margin-bottom: 4px;
    }
    .metric-label {
      font-size: 12px;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    
    /* Severity Chart */
    .chart-container {
      margin-top: 16px;
    }
    .chart-bar {
      display: flex;
      height: 8px;
      border-radius: 4px;
      overflow: hidden;
      background: var(--border);
    }
    .chart-segment {
      height: 100%;
    }
    .chart-legend {
      display: flex;
      gap: 16px;
      margin-top: 12px;
      font-size: 13px;
    }
    .legend-item {
      display: flex;
      align-items: center;
      gap: 6px;
      color: var(--text-muted);
    }
    .legend-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
    }
    
    /* Findings */
    .filter-bar {
      display: flex;
      gap: 8px;
      margin-bottom: 16px;
      flex-wrap: wrap;
    }
    .filter-btn {
      background: var(--panel);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 13px;
      cursor: pointer;
    }
    .filter-btn:hover {
      background: var(--border);
    }
    .filter-btn.active {
      background: var(--primary);
      color: var(--bg);
      border-color: var(--primary);
    }
    
    .issue-card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 16px;
    }
    .issue-header {
      display: flex;
      align-items: flex-start;
      gap: 12px;
      margin-bottom: 12px;
    }
    .severity-pill {
      font-size: 12px;
      font-weight: 600;
      padding: 2px 8px;
      border-radius: 12px;
      border: 1px solid;
      text-transform: capitalize;
    }
    .issue-title {
      font-size: 16px;
      font-weight: 600;
      margin: 0;
      flex: 1;
      line-height: 1.3;
    }
    .filepath-pill {
      font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
      font-size: 12px;
      background: var(--bg);
      border: 1px solid var(--border);
      padding: 4px 8px;
      border-radius: 4px;
      color: var(--text-muted);
      display: inline-block;
      margin-bottom: 12px;
    }
    .issue-desc {
      font-size: 14px;
      margin-bottom: 16px;
    }
    .fix-steps {
      margin: 0 0 16px 0;
      padding-left: 20px;
      font-size: 14px;
    }
    .fix-steps li {
      margin-bottom: 6px;
    }
    .ai-prompt {
      background: var(--bg);
      border: 1px solid var(--border);
      border-left: 3px solid var(--primary);
      padding: 12px 16px;
      border-radius: 4px;
      font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
      font-size: 13px;
      color: var(--text-muted);
      white-space: pre-wrap;
    }
    .ai-prompt-header {
      font-weight: 600;
      color: var(--text);
      margin-bottom: 8px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    }
    
    /* Errors banner */
    .error-banner {
      background: var(--critical-bg);
      border: 1px solid var(--critical);
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 24px;
      color: var(--critical);
    }
    .error-banner h3 {
      margin: 0 0 8px 0;
      font-size: 14px;
    }
    .error-banner ul {
      margin: 0;
      padding-left: 20px;
      font-size: 13px;
    }
    
    /* Utilities */
    .critical-color { color: var(--critical); }
    .high-color { color: var(--high); }
    .medium-color { color: var(--medium); }
    .low-color { color: var(--low); }
    
    .critical-pill { color: var(--critical); border-color: var(--critical); background: var(--critical-bg); }
    .high-pill { color: var(--high); border-color: var(--high); background: var(--high-bg); }
    .medium-pill { color: var(--medium); border-color: var(--medium); background: var(--medium-bg); }
    .low-pill { color: var(--low); border-color: var(--low); background: var(--low-bg); }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="header-left">
        <h1>VibeSafe Report</h1>
        <div class="subtitle">Pre-deploy safety scan</div>
        <div class="meta-info">
          Project: ${escapeHtml(result.projectPath)}
        </div>
      </div>
      <div>
        <div class="status-pill ${statusClass}">${escapeHtml(result.deployStatus)}</div>
      </div>
    </header>

    ${errorsHtml}

    <div class="panel decision-panel">
      <div class="decision-title">
        Deploy Status: <span class="${critical > 0 ? 'critical-color' : (high > 0 ? 'high-color' : 'low-color')}">${escapeHtml(result.deployStatus)}</span>
      </div>
      <div class="decision-reason">${escapeHtml(reason)}</div>
      <div class="decision-action">${escapeHtml(nextAction)}</div>
    </div>

    <div class="metrics-grid">
      <div class="metric-card">
        <div class="metric-value" style="color: ${result.score > 80 ? 'var(--low)' : result.score > 50 ? 'var(--medium)' : 'var(--critical)'}">${result.score}</div>
        <div class="metric-label">Score / 100</div>
      </div>
      <div class="metric-card">
        <div class="metric-value">${totalFindings}</div>
        <div class="metric-label">Total Findings</div>
      </div>
      <div class="metric-card">
        <div class="metric-value critical-color">${critical}</div>
        <div class="metric-label">Critical</div>
      </div>
      <div class="metric-card">
        <div class="metric-value high-color">${high}</div>
        <div class="metric-label">High</div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">Severity Breakdown</div>
      <div class="chart-container">
        <div class="chart-bar">
          <div class="chart-segment" style="width: ${critPct}%; background: var(--critical)"></div>
          <div class="chart-segment" style="width: ${highPct}%; background: var(--high)"></div>
          <div class="chart-segment" style="width: ${medPct}%; background: var(--medium)"></div>
          <div class="chart-segment" style="width: ${lowPct}%; background: var(--low)"></div>
        </div>
        <div class="chart-legend">
          <div class="legend-item"><div class="legend-dot" style="background: var(--critical)"></div> ${critical} Critical</div>
          <div class="legend-item"><div class="legend-dot" style="background: var(--high)"></div> ${high} High</div>
          <div class="legend-item"><div class="legend-dot" style="background: var(--medium)"></div> ${medium} Medium</div>
          <div class="legend-item"><div class="legend-dot" style="background: var(--low)"></div> ${low} Low</div>
        </div>
      </div>
    </div>

    <div class="findings-section">
      <div style="display: flex; justify-content: space-between; align-items: flex-end; margin-bottom: 16px;">
        <h2 style="margin: 0;">Repair Plan</h2>
      </div>
      
      <div class="filter-bar">
        <button class="filter-btn active" onclick="filterSteps('all')">All</button>
        <button class="filter-btn" onclick="filterSteps('critical')">Critical</button>
        <button class="filter-btn" onclick="filterSteps('high')">High</button>
        <button class="filter-btn" onclick="filterSteps('medium')">Medium</button>
        <button class="filter-btn" onclick="filterSteps('low')">Low</button>
      </div>
      
      <div id="repair-steps">
        ${stepsHtml}
      </div>
    </div>
  </div>

  <script>
    function filterSteps(severity) {
      document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.innerText.toLowerCase() === severity) {
          btn.classList.add('active');
        }
      });
      
      const steps = document.querySelectorAll('.issue-card');
      steps.forEach(step => {
        if (severity === 'all' || step.dataset.severity === severity) {
          step.style.display = 'block';
        } else {
          step.style.display = 'none';
        }
      });
    }
  </script>
</body>
</html>`;

  const reportPath = path.resolve(result.projectPath, "vibesafe-report.html");
  await fs.writeFile(reportPath, html, "utf-8");
  return reportPath;
}
