import * as vscode from "vscode";
import path from "path";
import { ScannerPipeline, createDefaultRegistry, createDefaultFixRegistry } from "@vibesafe/core";
import { updateDiagnostics, updateAllDiagnostics } from "./diagnostics.js";
import { VibeSafeCodeActionProvider } from "./codeActions.js";
import { VibeSafeStatusBar } from "./ui/statusBar.js";
import { VibeSafeDeployStatusProvider } from "./providers/deployStatusProvider.js";
import { VibeSafeIssuesProvider } from "./providers/issuesTreeProvider.js";
import { VibeSafeHoverProvider } from "./providers/hoverProvider.js";
import { openDashboard, updateDashboardIfOpen } from "./views/dashboard-webview.js";
import type { Finding, ScanResult } from "@vibesafe/shared";

// Keep a reference to the collection so we can clear/update it
let diagnosticCollection: vscode.DiagnosticCollection;
let pipeline: ScannerPipeline;
let statusBar: VibeSafeStatusBar;
let deployStatusProvider: VibeSafeDeployStatusProvider;
let issuesProvider: VibeSafeIssuesProvider;
let hoverProvider: VibeSafeHoverProvider;

let scanTimeout: NodeJS.Timeout | null = null;
let latestScanPromise: Promise<void> | null = null;
let lastFullScanResult: ScanResult | null = null;

export function activate(context: vscode.ExtensionContext): void {
  console.log('VibeSafe extension is now active!');

  // Initialize the core scanner
  pipeline = new ScannerPipeline(createDefaultRegistry());

  // Initialize UI components
  statusBar = new VibeSafeStatusBar();
  deployStatusProvider = new VibeSafeDeployStatusProvider(context.extensionUri);
  issuesProvider = new VibeSafeIssuesProvider();
  hoverProvider = new VibeSafeHoverProvider();

  // Register views
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider(VibeSafeDeployStatusProvider.viewType, deployStatusProvider)
  );
  context.subscriptions.push(
    vscode.window.registerTreeDataProvider("vibesafe.issues", issuesProvider)
  );

  // Create a diagnostic collection for our squiggles
  diagnosticCollection = vscode.languages.createDiagnosticCollection("vibesafe");
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
      new VibeSafeCodeActionProvider(),
      {
        providedCodeActionKinds: VibeSafeCodeActionProvider.providedCodeActionKinds
      }
    )
  );

  context.subscriptions.push(
    vscode.languages.registerHoverProvider(documentSelector, hoverProvider)
  );

  // Register command to copy the AI fix prompt to clipboard
  context.subscriptions.push(
    vscode.commands.registerCommand("vibesafe.copyFixPrompt", async (prompt: string) => {
      await vscode.env.clipboard.writeText(prompt);
      vscode.window.showInformationMessage("✨ VibeSafe AI Fix Prompt copied to clipboard! Paste it into Copilot.");
    })
  );

  // Register command to open dashboard
  context.subscriptions.push(
    vscode.commands.registerCommand("vibesafe.openDashboard", () => {
      openDashboard(context.extensionUri, lastFullScanResult);
    })
  );

  // Register applySafeFix command with Workspace Trust check
  context.subscriptions.push(
    vscode.commands.registerCommand("vibesafe.applyFix", async (finding: Finding) => {
      if (!vscode.workspace.isTrusted) {
        vscode.window.showErrorMessage("VibeSafe: Cannot apply fixes in Restricted Mode. Please trust this workspace first.");
        return;
      }

      const rootFolder = vscode.workspace.workspaceFolders?.[0];
      if (!rootFolder) return;
      const rootPath = rootFolder.uri.fsPath;

      const fixRegistry = createDefaultFixRegistry();
      const fixer = fixRegistry.getFixer(finding.ruleId);

      if (!fixer) {
        vscode.window.showErrorMessage(`VibeSafe: No AutoFixer is registered for rule '${finding.ruleId}'.`);
        return;
      }

      const preview = await fixer.preview(finding, rootPath);
      
      const confirm = await vscode.window.showInformationMessage(
        `VibeSafe Auto-Fix:\n\n${preview.description}\n\nAre you sure you want to apply this fix?`,
        { modal: true },
        "Apply Fix"
      );

      if (confirm === "Apply Fix") {
        const result = await fixer.apply(finding, rootPath);
        if (result.success) {
          vscode.window.showInformationMessage(`✅ VibeSafe Fix Applied: ${result.message}`);
          // Trigger a re-scan to clear the squiggles
          vscode.commands.executeCommand("vibesafe.scan");
        } else {
          vscode.window.showErrorMessage(`❌ VibeSafe Fix Failed: ${result.message}\n${result.error || ''}`);
        }
      }
    })
  );

  // Register command to scan the entire project manually
  context.subscriptions.push(
    vscode.commands.registerCommand("vibesafe.scan", async () => {
      const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
      if (!workspaceFolder) {
        vscode.window.showErrorMessage("VibeSafe: No workspace open.");
        return;
      }
      const rootPath = workspaceFolder.uri.fsPath;
      
      await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "VibeSafe: Scanning project for issues...",
        cancellable: false
      }, async () => {
        try {
          const result = await pipeline.scan({ rootPath });
          lastFullScanResult = result;
          
          // Update all UI pieces
          updateAllDiagnostics(rootPath, diagnosticCollection, result.findings);
          statusBar.update(result);
          deployStatusProvider.update(result);
          issuesProvider.update(result);
          hoverProvider.update(result);
          updateDashboardIfOpen(result);
          
          if (result.findings.length > 0) {
            vscode.window.showWarningMessage(`VibeSafe found ${result.findings.length} issues. Check the Problems panel!`);
            vscode.commands.executeCommand("workbench.action.problems.focus");
          } else {
            vscode.window.showInformationMessage("VibeSafe: No issues found! Your code is pristine ✨");
          }
        } catch (error: any) {
          vscode.window.showErrorMessage("VibeSafe scan failed: " + error.message);
        }
      });
    })
  );

  // Run the scanner whenever a document is saved
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((document) => {
      // Check if scanOnSave is enabled
      if (!vscode.workspace.getConfiguration("vibesafe").get("scanOnSave")) {
        return;
      }

      // Only scan code files
      if (!["javascript", "javascriptreact", "typescript", "typescriptreact"].includes(document.languageId)) {
        return;
      }

      // Debounce the scan request
      if (scanTimeout) {
        clearTimeout(scanTimeout);
      }
      
      scanTimeout = setTimeout(() => {
        // Queue the promise to prevent overlapping concurrent scans
        const previousPromise = latestScanPromise || Promise.resolve();
        latestScanPromise = previousPromise.then(() => runScannerOnDocument(document)).catch(() => {});
      }, 1500);
    })
  );

  // Optionally run it on open documents right away
  if (vscode.workspace.getConfiguration("vibesafe").get("scanOnOpen")) {
    vscode.commands.executeCommand("vibesafe.scan");
  }
}

async function runScannerOnDocument(document: vscode.TextDocument) {
  try {
    const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri);
    if (!workspaceFolder) return;

    const docRelativePath = path.relative(workspaceFolder.uri.fsPath, document.uri.fsPath).replace(/\\/g, "/");

    // Perform targeted scan on just the saved file
    const targetedResult = await pipeline.scan({ 
      rootPath: workspaceFolder.uri.fsPath,
      targetFiles: [docRelativePath]
    });

    const newDocumentFindings = targetedResult.findings;

    // Update squiggles immediately for the file
    updateDiagnostics(document, diagnosticCollection, newDocumentFindings);
    
    // Merge into the global cached state if it exists
    if (lastFullScanResult) {
      // Remove old findings for this file
      lastFullScanResult.findings = lastFullScanResult.findings.filter(f => f.file !== docRelativePath);
      // Add new findings
      lastFullScanResult.findings.push(...newDocumentFindings);
      
      // Recalculate score and summary
      const { score, deployStatus } = pipeline.calculateScore(lastFullScanResult.findings);
      lastFullScanResult.score = score;
      lastFullScanResult.deployStatus = deployStatus;
      lastFullScanResult.summary = pipeline.buildSummary(lastFullScanResult.findings, lastFullScanResult.summary.filesScanned);
      lastFullScanResult.repairPlan = pipeline.buildRepairPlan(lastFullScanResult.findings);
      
      // Update global UI with merged result
      statusBar.update(lastFullScanResult);
      deployStatusProvider.update(lastFullScanResult);
      issuesProvider.update(lastFullScanResult);
      hoverProvider.update(lastFullScanResult);
      updateDashboardIfOpen(lastFullScanResult);
    }
  } catch (error) {
    console.error("VibeSafe targeted scan failed:", error);
  }
}

export function deactivate(): void {
  // Clean up
  diagnosticCollection?.clear();
  diagnosticCollection?.dispose();
  statusBar?.dispose();
}
