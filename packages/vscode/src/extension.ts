import * as vscode from "vscode";
import path from "path";
import { ScannerPipeline, createDefaultRegistry } from "@vibeguard/core";
import { updateDiagnostics, updateAllDiagnostics } from "./diagnostics.js";
import { VibeGuardCodeActionProvider } from "./codeActions.js";

// Keep a reference to the collection so we can clear/update it
let diagnosticCollection: vscode.DiagnosticCollection;
let pipeline: ScannerPipeline;

export function activate(context: vscode.ExtensionContext): void {
  console.log('VibeGuard extension is now active!');

  // Initialize the core scanner
  pipeline = new ScannerPipeline(createDefaultRegistry());

  // Create a diagnostic collection for our squiggles
  diagnosticCollection = vscode.languages.createDiagnosticCollection("vibeguard");
  context.subscriptions.push(diagnosticCollection);

  // Register the Quick Fix Provider for all supported vibe-coding languages
  const documentSelector: vscode.DocumentSelector = [
    { scheme: "file", language: "javascript" },
    { scheme: "file", language: "javascriptreact" },
    { scheme: "file", language: "typescript" },
    { scheme: "file", language: "typescriptreact" }
  ];

  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      documentSelector,
      new VibeGuardCodeActionProvider(),
      {
        providedCodeActionKinds: VibeGuardCodeActionProvider.providedCodeActionKinds
      }
    )
  );

  // Register command to copy the AI fix prompt to clipboard
  context.subscriptions.push(
    vscode.commands.registerCommand("vibeguard.copyFixPrompt", async (prompt: string) => {
      await vscode.env.clipboard.writeText(prompt);
      vscode.window.showInformationMessage("✨ VibeGuard AI Fix Prompt copied to clipboard! Paste it into Copilot.");
    })
  );

  // Register command to scan the entire project manually
  context.subscriptions.push(
    vscode.commands.registerCommand("vibeguard.scan", async () => {
      if (!vscode.workspace.workspaceFolders) {
        vscode.window.showErrorMessage("VibeGuard: No workspace open.");
        return;
      }
      const rootPath = vscode.workspace.workspaceFolders[0].uri.fsPath;
      
      await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "VibeGuard: Scanning project for issues...",
        cancellable: false
      }, async () => {
        try {
          const result = await pipeline.scan({ rootPath });
          updateAllDiagnostics(rootPath, diagnosticCollection, result.findings);
          
          if (result.findings.length > 0) {
            vscode.window.showWarningMessage(`VibeGuard found ${result.findings.length} issues. Check the Problems panel!`);
            vscode.commands.executeCommand("workbench.action.problems.focus");
          } else {
            vscode.window.showInformationMessage("VibeGuard: No issues found! Your code is pristine ✨");
          }
        } catch (error: any) {
          vscode.window.showErrorMessage("VibeGuard scan failed: " + error.message);
        }
      });
    })
  );

  // Run the scanner whenever a document is saved
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (document) => {
      // Only scan code files
      if (!["javascript", "javascriptreact", "typescript", "typescriptreact"].includes(document.languageId)) {
        return;
      }

      await runScannerOnDocument(document);
    })
  );

  // Optionally run it on open documents right away
  if (vscode.workspace.getConfiguration("vibeguard").get("scanOnOpen")) {
    vscode.commands.executeCommand("vibeguard.scan");
  }
}

async function runScannerOnDocument(document: vscode.TextDocument) {
  try {
    const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri);
    if (!workspaceFolder) return;

    // Run the pipeline. To keep it fast, we scan the whole project directory 
    // but filter findings to just this document in updateDiagnostics.
    // In a highly optimized version, we would pass only the single file to the scanner.
    const result = await pipeline.scan({ rootPath: workspaceFolder.uri.fsPath });

    // Filter findings to only those originating from the saved file
    const docRelativePath = path.relative(workspaceFolder.uri.fsPath, document.uri.fsPath).replace(/\\/g, "/");
    const documentFindings = result.findings.filter(f => f.file === docRelativePath);

    // Update squiggles
    updateDiagnostics(document, diagnosticCollection, documentFindings);
  } catch (error) {
    console.error("VibeGuard scan failed:", error);
  }
}

export function deactivate(): void {
  // Clean up
  diagnosticCollection?.clear();
  diagnosticCollection?.dispose();
}
