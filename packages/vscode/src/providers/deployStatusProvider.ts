import * as vscode from "vscode";
import type { ScanResult } from "@vibesafe/shared";

export class VibeSafeDeployStatusProvider implements vscode.WebviewViewProvider {
  public static readonly viewType = "vibesafe.deployStatus";
  private _view?: vscode.WebviewView;
  private _latestResult?: ScanResult;

  constructor(private readonly _extensionUri: vscode.Uri) {}

  public resolveWebviewView(
    webviewView: vscode.WebviewView,
    context: vscode.WebviewViewResolveContext,
    _token: vscode.CancellationToken
  ) {
    this._view = webviewView;

    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: [this._extensionUri],
    };

    webviewView.webview.html = this._getHtmlForWebview(webviewView.webview);
  }

  public update(result: ScanResult) {
    this._latestResult = result;
    if (this._view) {
      this._view.webview.html = this._getHtmlForWebview(this._view.webview);
    }
  }

  private _getHtmlForWebview(webview: vscode.Webview) {
    if (!this._latestResult) {
      return this._getEmptyHtml();
    }

    const { score, deployStatus, summary } = this._latestResult;
    
    let statusColor = "var(--vscode-testing-iconPassed)";
    if (deployStatus === "warning") statusColor = "var(--vscode-testing-iconFailed)";
    if (deployStatus === "danger" || deployStatus === "blocker") statusColor = "var(--vscode-errorForeground)";

    return `<!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Deploy Status</title>
        <style>
          body {
            font-family: var(--vscode-font-family);
            padding: 10px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
          }
          .score-circle {
            width: 100px;
            height: 100px;
            border-radius: 50%;
            border: 8px solid ${statusColor};
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 10px;
            color: var(--vscode-editor-foreground);
          }
          .status-text {
            font-size: 1.2em;
            font-weight: 600;
            color: ${statusColor};
            text-transform: uppercase;
            margin-bottom: 15px;
          }
          .stats {
            display: flex;
            gap: 15px;
            font-size: 0.9em;
            opacity: 0.8;
          }
          .stat {
            display: flex;
            flex-direction: column;
          }
          .stat-val {
            font-weight: bold;
            font-size: 1.2em;
          }
        </style>
      </head>
      <body>
        <div class="score-circle">
          ${score}
        </div>
        <div class="status-text">${deployStatus}</div>
        <div class="stats">
          <div class="stat">
            <span class="stat-val" style="color: var(--vscode-errorForeground)">${summary.criticalCount}</span>
            <span>Critical</span>
          </div>
          <div class="stat">
            <span class="stat-val" style="color: var(--vscode-testing-iconFailed)">${summary.highCount}</span>
            <span>High</span>
          </div>
        </div>
      </body>
      </html>`;
  }

  private _getEmptyHtml() {
    return `<!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <style>
          body { font-family: var(--vscode-font-family); padding: 20px; text-align: center; opacity: 0.6; }
        </style>
      </head>
      <body>
        <p>Run a scan to see your deploy status.</p>
      </body>
      </html>`;
  }
}
