import fs from "node:fs/promises";
import path from "node:path";
import type { ScanResult } from "@vibesafe/shared";

export async function generateHtmlReport(result: ScanResult): Promise<string> {
  const severities = ["critical", "high", "medium", "low"] as const;
  const groupedSteps = severities.map(sev => ({
    severity: sev,
    steps: result.repairPlan.steps.filter(s => s.severity === sev)
  })).filter(g => g.steps.length > 0);

  const categoryLabels = Object.keys(result.summary.categoryCounts);
  const categoryData = Object.values(result.summary.categoryCounts);

  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VibeSafe Security Report</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    :root {
      --bg: #090a0f;
      --text: #e2e8f0;
      --text-muted: #94a3b8;
      --panel: rgba(26, 29, 39, 0.7);
      --panel-hover: rgba(35, 39, 53, 0.9);
      --border: rgba(255, 255, 255, 0.1);
      --primary: #38bdf8;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #eab308;
      --low: #10b981;
      --blur: blur(12px);
    }
    body {
      font-family: 'Outfit', -apple-system, sans-serif;
      background: radial-gradient(circle at top right, #131c31, var(--bg) 40%);
      background-attachment: fixed;
      color: var(--text);
      line-height: 1.6;
      margin: 0;
      padding: 40px 20px;
    }
    .container {
      max-width: 1100px;
      margin: 0 auto;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 40px;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--border);
    }
    h1 {
      margin: 0;
      font-size: 2.5rem;
      background: linear-gradient(to right, #38bdf8, #818cf8);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .status-badge {
      padding: 8px 16px;
      border-radius: 999px;
      font-weight: 700;
      font-size: 1.1rem;
      text-transform: uppercase;
      letter-spacing: 1px;
      box-shadow: 0 4px 15px rgba(0,0,0,0.2);
    }
    .status-safe { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }
    .status-warning { background: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid #eab308; }
    .status-danger { background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316; }
    .status-blocker { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }

    .grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 24px;
      margin-bottom: 40px;
    }
    @media (max-width: 768px) {
      .grid { grid-template-columns: 1fr; }
    }
    
    .card {
      background: var(--panel);
      backdrop-filter: var(--blur);
      -webkit-backdrop-filter: var(--blur);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 30px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.3);
      transition: transform 0.3s ease;
    }
    .card:hover {
      transform: translateY(-2px);
    }
    .card h2 {
      margin-top: 0;
      font-size: 1.5rem;
      font-weight: 600;
      margin-bottom: 24px;
      color: #fff;
    }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 16px;
    }
    .stat-box {
      background: rgba(0,0,0,0.2);
      padding: 20px;
      border-radius: 12px;
      border: 1px solid rgba(255,255,255,0.05);
      text-align: center;
    }
    .stat-value {
      font-size: 2.5rem;
      font-weight: 700;
      line-height: 1;
      margin-bottom: 8px;
    }
    .stat-label {
      color: var(--text-muted);
      font-size: 0.9rem;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .chart-container {
      position: relative;
      height: 250px;
      width: 100%;
      display: flex;
      justify-content: center;
    }

    /* Accordions for groupings */
    .severity-group {
      margin-bottom: 30px;
    }
    .severity-header {
      font-size: 1.4rem;
      font-weight: 600;
      margin-bottom: 16px;
      display: flex;
      align-items: center;
      gap: 12px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 8px;
    }
    .badge {
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 0.8rem;
      font-weight: 700;
      text-transform: uppercase;
    }
    .badge.critical { background: rgba(239,68,68,0.2); color: #fca5a5; border: 1px solid var(--critical); }
    .badge.high { background: rgba(249,115,22,0.2); color: #fdba74; border: 1px solid var(--high); }
    .badge.medium { background: rgba(234,179,8,0.2); color: #fde047; border: 1px solid var(--medium); }
    .badge.low { background: rgba(16,185,129,0.2); color: #6ee7b7; border: 1px solid var(--low); }
    
    details {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      margin-bottom: 12px;
      overflow: hidden;
      transition: background 0.2s;
    }
    details:hover {
      background: var(--panel-hover);
    }
    summary {
      padding: 20px;
      font-weight: 600;
      font-size: 1.1rem;
      cursor: pointer;
      display: flex;
      align-items: center;
      list-style: none;
    }
    summary::-webkit-details-marker {
      display: none;
    }
    summary::after {
      content: '+';
      margin-left: auto;
      font-size: 1.5rem;
      color: var(--text-muted);
      transition: transform 0.3s;
    }
    details[open] summary::after {
      content: '-';
    }
    .details-content {
      padding: 0 20px 20px 20px;
      border-top: 1px solid rgba(255,255,255,0.05);
      margin-top: 10px;
      padding-top: 20px;
    }
    
    .code-block {
      background: #0f111a;
      color: #38bdf8;
      padding: 12px 16px;
      border-radius: 8px;
      font-family: 'Fira Code', monospace;
      font-size: 0.9rem;
      border: 1px solid #1e293b;
      margin: 10px 0;
    }
    
    .prompt-box {
      background: linear-gradient(145deg, #1e1b4b, #312e81);
      border: 1px solid #4f46e5;
      padding: 20px;
      border-radius: 12px;
      margin-top: 16px;
      box-shadow: inset 0 2px 10px rgba(0,0,0,0.2);
    }
    .prompt-box strong {
      display: flex;
      align-items: center;
      gap: 8px;
      color: #a5b4fc;
      margin-bottom: 10px;
      font-size: 1.1rem;
    }
    .prompt-text {
      font-family: 'Fira Code', monospace;
      font-size: 0.95rem;
      color: #e0e7ff;
      white-space: pre-wrap;
    }
    
    ul.fix-steps {
      padding-left: 20px;
      color: #cbd5e1;
    }
    ul.fix-steps li {
      margin-bottom: 8px;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>🛡️ VibeSafe Report</h1>
      <div class="status-badge status-${result.deployStatus}">
        ${result.deployStatus}
      </div>
    </header>
    
    <div class="grid">
      <div class="card">
        <h2>Health Overview</h2>
        <div class="stats-grid">
          <div class="stat-box">
            <div class="stat-value" style="color: ${result.score > 80 ? 'var(--low)' : result.score > 50 ? 'var(--medium)' : 'var(--critical)'}">${result.score}</div>
            <div class="stat-label">Score / 100</div>
          </div>
          <div class="stat-box">
            <div class="stat-value">${result.summary.totalFindings}</div>
            <div class="stat-label">Total Issues</div>
          </div>
          <div class="stat-box">
            <div class="stat-value" style="color: var(--critical)">${result.summary.criticalCount}</div>
            <div class="stat-label">Critical</div>
          </div>
          <div class="stat-box">
            <div class="stat-value" style="color: var(--high)">${result.summary.highCount}</div>
            <div class="stat-label">High</div>
          </div>
        </div>
      </div>

      <div class="card">
        <h2>Issue Distribution</h2>
        <div class="chart-container">
          <canvas id="categoryChart"></canvas>
        </div>
      </div>
    </div>

    <div class="card" style="margin-bottom: 40px;">
      <h2>🛠️ Repair Plan</h2>
      <p style="color: var(--text-muted); margin-bottom: 30px; font-size: 1.1rem;">${result.repairPlan.summary}</p>
      
      ${groupedSteps.map(group => `
        <div class="severity-group">
          <div class="severity-header" style="color: var(--${group.severity})">
            ${group.severity.toUpperCase()} ISSUES (${group.steps.length})
          </div>
          
          ${group.steps.map(step => `
            <details>
              <summary>
                <span style="flex-grow: 1;">Step ${step.order}: ${step.title}</span>
                <span class="badge ${step.severity}">${step.severity}</span>
              </summary>
              <div class="details-content">
                ${step.file ? `<p><strong>Location:</strong> <span class="code-block">${step.file}${step.line ? `:${step.line}` : ''}</span></p>` : ''}
                <p><strong>Description:</strong> ${step.description}</p>
                <ul class="fix-steps">
                  ${step.fixSteps.map(f => `<li>${f}</li>`).join('')}
                </ul>
                ${step.aiFixPrompt ? `
                  <div class="prompt-box">
                    <strong>✨ AI Fix Prompt</strong>
                    <div class="prompt-text">${step.aiFixPrompt}</div>
                  </div>
                ` : ''}
              </div>
            </details>
          `).join('')}
        </div>
      `).join('')}
    </div>
  </div>

  <script>
    const ctx = document.getElementById('categoryChart').getContext('2d');
    new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ${JSON.stringify(categoryLabels)},
        datasets: [{
          data: ${JSON.stringify(categoryData)},
          backgroundColor: [
            '#ef4444', '#f97316', '#eab308', '#10b981', '#38bdf8', '#8b5cf6', '#ec4899'
          ],
          borderWidth: 0,
          hoverOffset: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: { color: '#e2e8f0', font: { family: 'Outfit' } }
          }
        },
        cutout: '70%'
      }
    });
  </script>
</body>
</html>
  `;

  const reportPath = path.resolve(result.projectPath, "vibesafe-report.html");
  await fs.writeFile(reportPath, html, "utf-8");
  return reportPath;
}
