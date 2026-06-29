import * as vscode from "vscode";
import type { Finding } from "@vibeguard/shared";

/**
 * Provides Quick Fixes for VibeGuard diagnostics.
 */
export class VibeGuardCodeActionProvider implements vscode.CodeActionProvider {
  public static readonly providedCodeActionKinds = [
    vscode.CodeActionKind.QuickFix
  ];

  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
    token: vscode.CancellationToken
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    // Filter diagnostics that belong to VibeGuard
    const vibeguardDiagnostics = context.diagnostics.filter(
      (diagnostic) => diagnostic.source === "VibeGuard"
    );

    for (const diagnostic of vibeguardDiagnostics) {
      const finding: Finding | undefined = (diagnostic as any).vibeguardFinding;

      if (!finding) {
        continue;
      }

      // If there's an AI Fix Prompt available, offer it as a Code Action
      if (finding.aiFixPrompt) {
        const action = new vscode.CodeAction(
          `✨ VibeGuard: Copy AI Fix Prompt for Copilot`,
          vscode.CodeActionKind.QuickFix
        );
        
        // Tie it to the diagnostic so it clears if fixed
        action.diagnostics = [diagnostic];
        action.isPreferred = true;
        
        // This command will be registered in extension.ts
        action.command = {
          command: "vibeguard.copyFixPrompt",
          title: "Copy AI Fix Prompt",
          arguments: [finding.aiFixPrompt]
        };

        actions.push(action);
      }
    }

    return actions;
  }
}
