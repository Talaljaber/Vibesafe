import * as vscode from "vscode";
import type { ScanResult } from "@vibesafe/shared";

let currentPanel: vscode.WebviewPanel | undefined;

export function openDashboard(extensionUri: vscode.Uri, result: ScanResult | null) {
  const column = vscode.window.activeTextEditor
    ? vscode.window.activeTextEditor.viewColumn
    : undefined;

  if (currentPanel) {
    currentPanel.reveal(column);
    if (result) {
      updateDashboard(currentPanel, result);
    }
    return;
  }

  currentPanel = vscode.window.createWebviewPanel(
    "vibesafeDashboard",
    "VibeSafe Dashboard",
    column || vscode.ViewColumn.One,
    {
      enableScripts: true,
      localResourceRoots: [vscode.Uri.joinPath(extensionUri, "media")]
    }
  );

  currentPanel.onDidDispose(() => {
    currentPanel = undefined;
  });

  if (result) {
    updateDashboard(currentPanel, result);
  } else {
    currentPanel.webview.html = getEmptyHtml();
  }
}

export function updateDashboardIfOpen(result: ScanResult) {
  if (currentPanel) {
    updateDashboard(currentPanel, result);
  }
}

function updateDashboard(panel: vscode.WebviewPanel, result: ScanResult) {
  panel.webview.html = getHtmlForResult(result);
}

function getEmptyHtml() {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VibeSafe Dashboard</title>
  <style>
    body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #0f111a; color: #fff; }
  </style>
</head>
<body>
  <div>
    <h2>🛡️ VibeSafe Dashboard</h2>
    <p>Run a scan to see your codebase health.</p>
  </div>
</body>
</html>
  `;
}

function getHtmlForResult(result: ScanResult) {
  // Using the same styles as the HTML reporter, adapted for the VS Code Webview
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VibeSafe Security Report</title>
  <style>
    :root {
      --bg: var(--vscode-editor-background, #0f111a);
      --text: var(--vscode-editor-foreground, #e0e6ed);
      --panel: var(--vscode-editorWidget-background, #1a1d27);
      --border: var(--vscode-panel-border, #2d3142);
      --primary: var(--vscode-textLink-foreground, #00d2ff);
      --critical: #ff3b30;
      --high: #ff9500;
      --medium: #ffcc00;
      --low: #34c759;
    }
    body {
      font-family: var(--vscode-font-family), -apple-system, sans-serif;
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
    
    .repair-step {
      background: rgba(255, 255, 255, 0.03);
      padding: 16px;
      border-radius: 8px;
      margin-bottom: 16px;
    }
    .prompt-box {
      background: rgba(0,0,0,0.2);
      border: 1px dashed var(--primary);
      padding: 12px;
      border-radius: 6px;
      margin-top: 10px;
      font-style: italic;
    }
    
    /* Interactive parts */
    .filter-btn {
      background: transparent;
      border: 1px solid var(--border);
      color: var(--text);
      padding: 6px 12px;
      cursor: pointer;
      border-radius: 4px;
      margin-right: 8px;
    }
    .filter-btn:hover { background: rgba(255,255,255,0.1); }
    .filter-btn.active { border-color: var(--primary); color: var(--primary); }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ VibeSafe Dashboard</h1>
    
    <div class="card">
      <h2>Overview</h2>
      <div class="summary-grid">
        <div class="stat">
          <div class="stat-value" style="color: \${result.score > 80 ? 'var(--low)' : result.score > 50 ? 'var(--medium)' : 'var(--critical)'}">\${result.score}/100</div>
          <div>Health Score</div>
        </div>
        <div class="stat">
          <div class="stat-value">\${result.summary.totalFindings}</div>
          <div>Total Issues</div>
        </div>
        <div class="stat">
          <div class="stat-value" style="color: var(--critical)">\${result.summary.criticalCount}</div>
          <div>Critical</div>
        </div>
        <div class="stat">
          <div class="stat-value" style="color: var(--high)">\${result.summary.highCount}</div>
          <div>High</div>
        </div>
      </div>
      <p style="text-align: center; margin-top: 20px; font-weight: bold; font-size: 1.2rem;">
        Deploy Status: <span style="color: var(--primary)">\${result.deployStatus.toUpperCase()}</span>
      </p>
    </div>

    <div class="card">
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <h2>🛠️ Repair Plan</h2>
        <div>
          <button class="filter-btn active" onclick="filterSteps('all')">All</button>
          <button class="filter-btn" onclick="filterSteps('critical')">Critical</button>
          <button class="filter-btn" onclick="filterSteps('high')">High</button>
        </div>
      </div>
      
      <p>\${result.repairPlan.summary}</p>
      
      <div id="repair-steps">
        \${result.repairPlan.steps.map(step => \`
          <div class="repair-step" data-severity="\${step.severity}">
            <h3>Step \${step.order}: \${step.title} <span class="badge \${step.severity}">\${step.severity}</span></h3>
            \${step.file ? \`<p><strong>Location:</strong> <code>\${step.file}\${step.line ? \`:\${step.line}\` : ''}</code></p>\` : ''}
            <p><strong>Description:</strong> \${step.description}</p>
            <ul>
              \${step.fixSteps.map(f => \`<li>\${f}</li>\`).join('')}
            </ul>
            \${step.aiFixPrompt ? \`
              <div class="prompt-box">
                <strong>✨ AI Prompt:</strong><br/>
                \${step.aiFixPrompt}
              </div>
            \` : ''}
          </div>
        \`).join('')}
      </div>
    </div>
  </div>

  <script>
    function filterSteps(severity) {
      // Update buttons
      document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.innerText.toLowerCase() === severity) {
          btn.classList.add('active');
        }
      });
      
      // Filter steps
      const steps = document.querySelectorAll('.repair-step');
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
</html>
   `;
}