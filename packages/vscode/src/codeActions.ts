import * as vscode from "vscode";
import type { Finding } from "@vibesafe/shared";

/**
 * Provides Quick Fixes for VibeSafe diagnostics.
 */
export class VibeSafeCodeActionProvider implements vscode.CodeActionProvider {
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

    // Filter diagnostics that belong to VibeSafe
    const vibesafeDiagnostics = context.diagnostics.filter(
      (diagnostic) => diagnostic.source === "VibeSafe"
    );

    for (const diagnostic of vibesafeDiagnostics) {
      const finding: Finding | undefined = (diagnostic as any).vibesafeFinding;

      if (!finding) {
        continue;
      }

      // If there's an AI Fix Prompt available, offer it as a Code Action
      if (finding.aiFixPrompt) {
        const action = new vscode.CodeAction(
          `✨ VibeSafe: Copy AI Fix Prompt for Copilot`,
          vscode.CodeActionKind.QuickFix
        );
        
        // Tie it to the diagnostic so it clears if fixed
        action.diagnostics = [diagnostic];
        action.isPreferred = true;
        
        // This command will be registered in extension.ts
        action.command = {
          command: "vibesafe.copyFixPrompt",
          title: "Copy AI Fix Prompt",
          arguments: [finding.aiFixPrompt]
        };

        actions.push(action);
      }
    }

    return actions;
  }
}
