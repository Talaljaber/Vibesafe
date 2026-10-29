import * as vscode from "vscode";
import path from "path";
import {
  ScannerPipeline,
  createDefaultRegistry,
  createDefaultFixRegistry,
} from "@talaljaber/vibesafe-core";
import { updateDiagnostics, updateAllDiagnostics } from "./diagnostics.js";
import { VibeSafeCodeActionProvider } from "./codeActions.js";
import { VibeSafeStatusBar } from "./ui/statusBar.js";
import { VibeSafeDeployStatusProvider } from "./providers/deployStatusProvider.js";
import { VibeSafeIssuesProvider } from "./providers/issuesTreeProvider.js";
import { VibeSafeHoverProvider } from "./providers/hoverProvider.js";
import { openDashboard, updateDashboardIfOpen } from "./views/dashboard-webview.js";
import {
  findFindingInResults,
  resolveFindingId,
  isFindingInsideRoot,
  isInsideRoot,
} from "./util/findings.js";
import { readScanOptions } from "./util/scanOptions.js";
import type { ScanResult } from "@talaljaber/vibesafe-shared";

// Keep a reference to the collection so we can clear/update it
let diagnosticCollection: vscode.DiagnosticCollection;
let pipeline: ScannerPipeline;
let statusBar: VibeSafeStatusBar;
let deployStatusProvider: VibeSafeDeployStatusProvider;
let issuesProvider: VibeSafeIssuesProvider;
let hoverProvider: VibeSafeHoverProvider;

let scanTimeout: NodeJS.Timeout | null = null;
let latestScanPromise: Promise<void> | null = null;

/** Latest full-scan result per workspace folder (keyed by folder fsPath). */
const resultsByFolder = new Map<string, ScanResult>();
/** The result shown in the single-project views (most recently updated folder). */
let primaryResult: ScanResult | null = null;

/** Folders whose config file failed to load; warned once, reset when the config file changes. */
const brokenConfigRoots = new Set<string>();

const CODE_LANGUAGES = ["javascript", "javascriptreact", "typescript", "typescriptreact"];

function scanOptions() {
  return readScanOptions(vscode.workspace.getConfiguration("vibesafe"));
}

function refreshViews(result: ScanResult): void {
  primaryResult = result;
  statusBar.update(result);
  deployStatusProvider.update(result);
  issuesProvider.update(result);
  hoverProvider.update(result);
  updateDashboardIfOpen(result);
}

/**
 * Scans, but never lets a broken .vibesafe.config.json take the extension down:
 * on a config error the scan is retried without the config file and a warning
 * is shown. Script configs are never executed here (trustConfigScripts is unset).
 */
async function scanWithConfigFallback(
  opts: Parameters<ScannerPipeline["scan"]>[0],
): Promise<ScanResult> {
  const root = opts.rootPath;
  // Already known broken for this folder: skip the failing load (and the repeat warning).
  if (brokenConfigRoots.has(root)) return pipeline.scan({ ...opts, useConfigFile: false });
  try {
    return await pipeline.scan(opts);
  } catch (error) {
    if (error instanceof Error && error.name === "ConfigLoadError") {
      brokenConfigRoots.add(root);
      vscode.window.showWarningMessage(
        `VibeSafe: ${error.message} Scanning without the config file.`,
      );
      return pipeline.scan({ ...opts, useConfigFile: false });
    }
    throw error;
  }
}

/** Run a full scan of one workspace folder and update every view. */
async function runFullScan(folder: vscode.WorkspaceFolder, notify: boolean): Promise<void> {
  const rootPath = folder.uri.fsPath;
  try {
    const result = await scanWithConfigFallback({ rootPath, ...scanOptions() });
    resultsByFolder.set(rootPath, result);
    updateAllDiagnostics(rootPath, diagnosticCollection, result.findings);
    refreshViews(result);

    if (!notify) return;

    if (result.warnings && result.warnings.length > 0) {
      vscode.window.showWarningMessage(`VibeSafe: ${result.warnings.join(" ")}`);
    }

    if (result.findings.length > 0) {
      vscode.window.showWarningMessage(
        `VibeSafe found ${result.findings.length} issues. Check the Problems panel!`,
      );
      if (vscode.workspace.getConfiguration("vibesafe").get<boolean>("focusProblemsOnScan")) {
        vscode.commands.executeCommand("workbench.action.problems.focus");
      }
    } else {
      vscode.window.showInformationMessage("VibeSafe: No issues found! Your code is pristine ✨");
    }
  } catch (error) {
    vscode.window.showErrorMessage(
      "VibeSafe scan failed: " + (error instanceof Error ? error.message : String(error)),
    );
  }
}

async function scanAllFolders(notify: boolean): Promise<void> {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    vscode.window.showErrorMessage("VibeSafe: No workspace open.");
    return;
  }
  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "VibeSafe: Scanning project for issues...",
      cancellable: false,
    },
    async () => {
      for (const folder of folders) {
        await runFullScan(folder, notify);
      }
    },
  );
}

function dropDiagnosticsUnder(uri: vscode.Uri): void {
  const doomed: vscode.Uri[] = [];
  diagnosticCollection.forEach((u) => {
    if (isInsideRoot(uri.fsPath, u.fsPath)) doomed.push(u);
  });
  for (const u of doomed) diagnosticCollection.delete(u);
}

export function activate(context: vscode.ExtensionContext): void {
  console.log("VibeSafe extension is now active!");

  // Initialize the core scanner
  pipeline = new ScannerPipeline(createDefaultRegistry());

  // A changed config file may now be valid: forget the fallback and warn again if still broken.
  const configWatcher = vscode.workspace.createFileSystemWatcher(
    "**/{.vibesafe.config,vibesafe.config}.*",
  );
  const resetBroken = () => brokenConfigRoots.clear();
  configWatcher.onDidChange(resetBroken);
  configWatcher.onDidCreate(resetBroken);
  configWatcher.onDidDelete(resetBroken);
  context.subscriptions.push(configWatcher);

  // Initialize UI components
  statusBar = new VibeSafeStatusBar();
  deployStatusProvider = new VibeSafeDeployStatusProvider(context.extensionUri);
  issuesProvider = new VibeSafeIssuesProvider();
  hoverProvider = new VibeSafeHoverProvider();

  // Register views
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider(
      VibeSafeDeployStatusProvider.viewType,
      deployStatusProvider,
    ),
  );
  context.subscriptions.push(
    vscode.window.registerTreeDataProvider("vibesafe.issues", issuesProvider),
  );

  // Create a diagnostic collection for our squiggles
  diagnosticCollection = vscode.languages.createDiagnosticCollection("vibesafe");
  context.subscriptions.push(diagnosticCollection);

  // Register the Quick Fix Provider for all supported vibe-coding languages
  const documentSelector: vscode.DocumentSelector = CODE_LANGUAGES.map((language) => ({
    scheme: "file",
    language,
  }));

  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      documentSelector,
      new VibeSafeCodeActionProvider(),
      {
        providedCodeActionKinds: VibeSafeCodeActionProvider.providedCodeActionKinds,
      },
    ),
  );

  context.subscriptions.push(
    vscode.languages.registerHoverProvider(documentSelector, hoverProvider),
  );

  // Register command to copy the AI fix prompt to clipboard
  context.subscriptions.push(
    vscode.commands.registerCommand("vibesafe.copyFixPrompt", async (arg: unknown) => {
      // Never trust finding data from arguments; look it up by id.
      const found = findFindingInResults(resultsByFolder.values(), resolveFindingId(arg));
      if (!found?.finding.aiFixPrompt) {
        vscode.window.showWarningMessage(
          "VibeSafe: Finding not found. Re-run the scan and try again.",
        );
        return;
      }
      await vscode.env.clipboard.writeText(found.finding.aiFixPrompt);
      vscode.window.showInformationMessage(
        "✨ VibeSafe AI Fix Prompt copied to clipboard! Paste it into Copilot.",
      );
    }),
  );

  // Register command to open dashboard
  context.subscriptions.push(
    vscode.commands.registerCommand("vibesafe.openDashboard", () => {
      openDashboard(context.extensionUri, primaryResult);
    }),
  );

  // Register applySafeFix command with Workspace Trust check
  context.subscriptions.push(
    vscode.commands.registerCommand("vibesafe.applyFix", async (arg: unknown) => {
      if (!vscode.workspace.isTrusted) {
        vscode.window.showErrorMessage(
          "VibeSafe: Cannot apply fixes in Restricted Mode. Please trust this workspace first.",
        );
        return;
      }

      // Never trust finding data from arguments; look it up by id.
      const found = findFindingInResults(resultsByFolder.values(), resolveFindingId(arg));
      if (!found) {
        vscode.window.showWarningMessage(
          "VibeSafe: Finding not found. Re-run the scan and try again.",
        );
        return;
      }
      const { finding } = found;

      // Use the folder the finding was scanned in.
      const rootPath = found.result.projectPath;
      const rootFolder = vscode.workspace.getWorkspaceFolder(vscode.Uri.file(rootPath));
      if (!rootFolder) {
        vscode.window.showErrorMessage(
          "VibeSafe: The scanned folder is no longer part of the workspace.",
        );
        return;
      }

      // Defense in depth: never touch files outside the workspace folder.
      if (!isFindingInsideRoot(rootFolder.uri.fsPath, finding)) {
        vscode.window.showErrorMessage("VibeSafe: Refusing to fix a file outside the workspace.");
        return;
      }

      const fixRegistry = createDefaultFixRegistry();
      const fixer = fixRegistry.getFixer(finding.ruleId);

      if (!fixer) {
        vscode.window.showErrorMessage(
          `VibeSafe: No AutoFixer is registered for rule '${finding.ruleId}'.`,
        );
        return;
      }

      const preview = await fixer.preview(finding, rootPath);

      const confirm = await vscode.window.showInformationMessage(
        `VibeSafe Auto-Fix:\n\n${preview.description}\n\nAre you sure you want to apply this fix?`,
        { modal: true },
        "Apply Fix",
      );

      if (confirm === "Apply Fix") {
        const result = await fixer.apply(finding, rootPath);
        if (result.success) {
          vscode.window.showInformationMessage(`✅ VibeSafe Fix Applied: ${result.message}`);
          // Re-scan the same folder to clear the squiggles
          await runFullScan(rootFolder, false);
        } else {
          vscode.window.showErrorMessage(
            `❌ VibeSafe Fix Failed: ${result.message}\n${result.error || ""}`,
          );
        }
      }
    }),
  );

  // Scan the entire workspace manually; "rescan" is an alias.
  const scanCommand = () => scanAllFolders(true);
  context.subscriptions.push(vscode.commands.registerCommand("vibesafe.scan", scanCommand));
  context.subscriptions.push(vscode.commands.registerCommand("vibesafe.rescan", scanCommand));

  // Run the scanner whenever a document is saved
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((document) => {
      // Check if scanOnSave is enabled
      if (!vscode.workspace.getConfiguration("vibesafe").get("scanOnSave")) {
        return;
      }

      // Only scan code files
      if (!CODE_LANGUAGES.includes(document.languageId)) {
        return;
      }

      // Debounce the scan request
      if (scanTimeout) {
        clearTimeout(scanTimeout);
      }

      scanTimeout = setTimeout(() => {
        // Queue the promise to prevent overlapping concurrent scans
        const previousPromise = latestScanPromise || Promise.resolve();
        latestScanPromise = previousPromise
          .then(() => runScannerOnDocument(document))
          .catch(() => {});
      }, 1500);
    }),
  );

  // Re-scan when scan-affecting settings change
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (
        resultsByFolder.size > 0 &&
        (e.affectsConfiguration("vibesafe.minSeverity") ||
          e.affectsConfiguration("vibesafe.enabledCategories"))
      ) {
        void scanAllFolders(false);
      }
    }),
  );

  // Clear squiggles for deleted / renamed files
  context.subscriptions.push(
    vscode.workspace.onDidDeleteFiles((e) => e.files.forEach(dropDiagnosticsUnder)),
  );
  context.subscriptions.push(
    vscode.workspace.onDidRenameFiles((e) =>
      e.files.forEach((f) => dropDiagnosticsUnder(f.oldUri)),
    ),
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
    const rootPath = workspaceFolder.uri.fsPath;

    const existing = resultsByFolder.get(rootPath);
    if (!existing) {
      // No baseline yet: run a full scan so every view updates consistently.
      await runFullScan(workspaceFolder, false);
      return;
    }

    const docRelativePath = path.relative(rootPath, document.uri.fsPath).replace(/\\/g, "/");

    // Perform targeted scan on just the saved file
    const targetedResult = await scanWithConfigFallback({
      rootPath,
      targetFiles: [docRelativePath],
      ...scanOptions(),
    });

    // Project-level (file-less) findings belong to the full scan; keep only this file's findings
    // so counts do not drift when the same project-level finding is re-appended.
    const newDocumentFindings = targetedResult.findings.filter((f) => f.file === docRelativePath);

    // Update squiggles immediately for the file
    updateDiagnostics(document, diagnosticCollection, newDocumentFindings);

    // Merge into the folder's cached state
    existing.findings = existing.findings.filter((f) => f.file !== docRelativePath);
    existing.findings.push(...newDocumentFindings);

    // Recalculate score and summary
    const { score, deployStatus } = pipeline.calculateScore(existing.findings);
    existing.score = score;
    existing.deployStatus = deployStatus;
    existing.summary = pipeline.buildSummary(existing.findings, existing.summary.filesScanned);
    existing.repairPlan = pipeline.buildRepairPlan(existing.findings);

    refreshViews(existing);
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
