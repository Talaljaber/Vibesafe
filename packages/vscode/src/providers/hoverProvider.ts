import * as vscode from "vscode";
import path from "path";
import type { ScanResult } from "@vibesafe/shared";

export class VibeSafeHoverProvider implements vscode.HoverProvider {
  private latestResult?: ScanResult;

  public update(result: ScanResult) {
    this.latestResult = result;
  }

  public provideHover(
    document: vscode.TextDocument,
    position: vscode.Position,
    _token: vscode.CancellationToken
  ): vscode.ProviderResult<vscode.Hover> {
    if (!this.latestResult) return null;

    const rootPath = this.latestResult.projectPath;
    const relativePath = path.relative(rootPath, document.uri.fsPath).replace(/\\/g, "/");

    // Find a finding that overlaps with this line
    const finding = this.latestResult.findings.find(f => {
      if (f.file !== relativePath) return false;
      const startLine = Math.max(0, (f.line || 1) - 1);
      const endLine = Math.max(0, (f.endLine || f.line || 1) - 1);
      return position.line >= startLine && position.line <= endLine;
    });

    if (!finding) return null;

    const markdown = new vscode.MarkdownString();
    markdown.isTrusted = true;
    markdown.supportHtml = true;

    markdown.appendMarkdown(`### 🛡️ VibeSafe: ${finding.title}\n\n`);
    markdown.appendMarkdown(`${finding.plainEnglishProblem}\n\n`);
    
    markdown.appendMarkdown(`**Why It Matters:**\n${finding.whyItMatters}\n\n`);

    if (finding.fixSteps && finding.fixSteps.length > 0) {
      markdown.appendMarkdown(`**How to Fix:**\n`);
      finding.fixSteps.forEach(step => markdown.appendMarkdown(`- ${step}\n`));
      markdown.appendMarkdown(`\n`);
    }

    if (finding.aiFixPrompt) {
      markdown.appendMarkdown(`---\n`);
      markdown.appendMarkdown(`[✨ Copy AI Prompt for Copilot](command:vibesafe.copyFixPrompt?${encodeURIComponent(JSON.stringify(finding.aiFixPrompt))})\n`);
    }

    if (finding.autoFixAvailable) {
      markdown.appendMarkdown(`\n[🔧 Apply Safe Fix](command:vibesafe.applyFix?${encodeURIComponent(JSON.stringify(finding))})\n`);
    }

    return new vscode.Hover(markdown);
  }
}
