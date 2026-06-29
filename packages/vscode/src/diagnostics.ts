import * as vscode from "vscode";
import type { Finding, Severity } from "@vibeguard/shared";

// Map VibeGuard severity to VS Code DiagnosticSeverity
function mapSeverity(severity: Severity): vscode.DiagnosticSeverity {
  switch (severity) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error; // Red squiggle
    case "medium":
    case "low":
      return vscode.DiagnosticSeverity.Warning; // Yellow squiggle
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

/**
 * Updates the VS Code DiagnosticCollection with VibeGuard findings for a specific document.
 */
export function updateDiagnostics(
  document: vscode.TextDocument,
  collection: vscode.DiagnosticCollection,
  findings: Finding[]
): void {
  const diagnostics: vscode.Diagnostic[] = [];

  for (const finding of findings) {
    // If finding has no file or line, we can't easily highlight it in a specific document.
    // In a full implementation, project-wide findings might go to a custom TreeView.
    if (!finding.file || !finding.line) {
      continue;
    }

    // Convert 1-based finding.line to 0-based VS Code line
    const lineIndex = finding.line - 1;
    
    // Ensure the line exists in the document
    if (lineIndex < 0 || lineIndex >= document.lineCount) {
      continue;
    }

    const lineText = document.lineAt(lineIndex);
    
    // Create a range that spans the entire line
    const range = new vscode.Range(
      lineIndex, 
      lineText.firstNonWhitespaceCharacterIndex, 
      lineIndex, 
      lineText.text.length
    );

    const message = `VibeGuard [${finding.ruleId}]: ${finding.title}\n\n${finding.plainEnglishProblem}\n\nWhy it matters: ${finding.whyItMatters}`;
    
    const diagnostic = new vscode.Diagnostic(
      range,
      message,
      mapSeverity(finding.severity)
    );

    diagnostic.source = "VibeGuard";
    diagnostic.code = finding.ruleId;

    // Attach the finding data so our CodeActionProvider can read it later
    (diagnostic as any).vibeguardFinding = finding;

    diagnostics.push(diagnostic);
  }

  // Update the collection for this specific document's URI
  collection.set(document.uri, diagnostics);
}
