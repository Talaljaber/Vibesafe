import * as vscode from "vscode";
import path from "path";
import type { ScanResult } from "@vibesafe/shared";
import { escapeMarkdown, findingCommandUri, TRUSTED_COMMANDS } from "../util/markdown.js";

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
    const finding = this.latestResult.findings.find((f) => {
      if (f.file !== relativePath) return false;
      const startLine = Math.max(0, (f.line || 1) - 1);
      const endLine = Math.max(0, (f.endLine || f.line || 1) - 1);
      return position.line >= startLine && position.line <= endLine;
    });

    if (!finding) return null;

    // Finding text may contain content from the scanned repository, so it is
    // escaped and only a minimal set of command links is trusted.
    const markdown = new vscode.MarkdownString();
    markdown.isTrusted = { enabledCommands: [...TRUSTED_COMMANDS] };
    markdown.supportHtml = false;

    markdown.appendMarkdown(`### 🛡️ VibeSafe: ${escapeMarkdown(finding.title)}\n\n`);
    markdown.appendMarkdown(`${escapeMarkdown(finding.plainEnglishProblem)}\n\n`);
    markdown.appendMarkdown(`**Why It Matters:**\n\n${escapeMarkdown(finding.whyItMatters)}\n\n`);

    if (finding.fixSteps && finding.fixSteps.length > 0) {
      markdown.appendMarkdown(`**How to Fix:**\n\n`);
      finding.fixSteps.forEach((step) => markdown.appendMarkdown(`- ${escapeMarkdown(step)}\n`));
      markdown.appendMarkdown(`\n`);
    }

    if (finding.aiFixPrompt) {
      markdown.appendMarkdown(`---\n`);
      markdown.appendMarkdown(
        `[✨ Copy AI Prompt for Copilot](${findingCommandUri("vibesafe.copyFixPrompt", finding.id)})\n`
      );
    }

    if (finding.autoFixAvailable) {
      markdown.appendMarkdown(
        `\n[🔧 Apply Safe Fix](${findingCommandUri("vibesafe.applyFix", finding.id)})\n`
      );
    }

    return new vscode.Hover(markdown);
  }
}
