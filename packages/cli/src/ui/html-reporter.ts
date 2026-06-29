import fs from "node:fs/promises";
import path from "node:path";
import type { ScanResult } from "@vibesafe/shared";

export async function generateHtmlReport(result: ScanResult): Promise<string> {
  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VibeSafe Security Report</title>
  <style>
    :root {
      --bg: #0f111a;
      --text: #e0e6ed;
      --panel: #1a1d27;
      --border: #2d3142;
      --primary: #00d2ff;
      --critical: #ff3b30;
      --high: #ff9500;
      --medium: #ffcc00;
      --low: #34c759;
    }
    body {
      font-family: 'Inter', -apple-system, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.6;
      margin: 0;
      padding: 40px 20px;
    }
    .container {
      max-width: 1000px;
      margin: 0 auto;
    }
    h1 {
      color: var(--primary);
      border-bottom: 2px solid var(--border);
      padding-bottom: 10px;
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 24px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.2);
    }
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
    }
    .stat {
      text-align: center;
      padding: 16px;
      background: rgba(255,255,255,0.02);
      border-radius: 8px;
    }
    .stat-value {
      font-size: 2rem;
      font-weight: bold;
    }
    .badge {
      display: inline-block;
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 0.85rem;
      font-weight: bold;
      text-transform: uppercase;
    }
    .critical { color: var(--critical); border: 1px solid var(--critical); }
    .high { color: var(--high); border: 1px solid var(--high); }
    .medium { color: var(--medium); border: 1px solid var(--medium); }
    .low { color: var(--low); border: 1px solid var(--low); }
    
    .finding {
      border-left: 4px solid var(--border);
      padding-left: 16px;
      margin-bottom: 24px;
    }
    .finding.critical { border-color: var(--critical); }
    .finding.high { border-color: var(--high); }
    .finding.medium { border-color: var(--medium); }
    .finding.low { border-color: var(--low); }
    
    .code-block {
      background: #000;
      color: #00ff00;
      padding: 12px;
      border-radius: 6px;
      overflow-x: auto;
      font-family: monospace;
      margin: 10px 0;
    }
    
    .repair-step {
      background: rgba(255, 255, 255, 0.03);
      padding: 16px;
      border-radius: 8px;
      margin-bottom: 16px;
    }
    .prompt-box {
      background: #2a2d3d;
      border: 1px dashed var(--primary);
      padding: 12px;
      border-radius: 6px;
      margin-top: 10px;
      font-style: italic;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ VibeSafe Report</h1>
    
    <div class="card">
      <h2>Overview</h2>
      <div class="summary-grid">
        <div class="stat">
          <div class="stat-value" style="color: ${result.score > 80 ? 'var(--low)' : result.score > 50 ? 'var(--medium)' : 'var(--critical)'}">${result.score}/100</div>
          <div>Health Score</div>
        </div>
        <div class="stat">
          <div class="stat-value">${result.summary.totalFindings}</div>
          <div>Total Issues</div>
        </div>
        <div class="stat">
          <div class="stat-value" style="color: var(--critical)">${result.summary.criticalCount}</div>
          <div>Critical</div>
        </div>
        <div class="stat">
          <div class="stat-value" style="color: var(--high)">${result.summary.highCount}</div>
          <div>High</div>
        </div>
      </div>
      <p style="text-align: center; margin-top: 20px; font-weight: bold; font-size: 1.2rem;">
        Deploy Status: <span style="color: var(--primary)">${result.deployStatus.toUpperCase()}</span>
      </p>
    </div>

    <div class="card">
      <h2>🛠️ Repair Plan</h2>
      <p>${result.repairPlan.summary}</p>
      ${result.repairPlan.steps.map(step => `
        <div class="repair-step">
          <h3>Step ${step.order}: ${step.title} <span class="badge ${step.severity}">${step.severity}</span></h3>
          ${step.file ? `<p><strong>Location:</strong> <code>${step.file}${step.line ? `:${step.line}` : ''}</code></p>` : ''}
          <p><strong>Description:</strong> ${step.description}</p>
          <ul>
            ${step.fixSteps.map(f => `<li>${f}</li>`).join('')}
          </ul>
          ${step.aiFixPrompt ? `
            <div class="prompt-box">
              <strong>✨ AI Prompt:</strong><br/>
              ${step.aiFixPrompt}
            </div>
          ` : ''}
        </div>
      `).join('')}
    </div>

  </div>
</body>
</html>
  `;

  const reportPath = path.resolve(result.projectPath, "vibesafe-report.html");
  await fs.writeFile(reportPath, html, "utf-8");
  return reportPath;
}
