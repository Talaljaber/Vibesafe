import * as vscode from "vscode";
import type { Finding, Severity } from "@vibesafe/shared";

// Map VibeSafe severity to VS Code DiagnosticSeverity
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
 * Updates the VS Code DiagnosticCollection with VibeSafe findings for a specific document.
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

    const message = `VibeSafe [${finding.ruleId}]: ${finding.title}\n\n${finding.plainEnglishProblem}\n\nWhy it matters: ${finding.whyItMatters}`;
    
    const diagnostic = new vscode.Diagnostic(
      range,
      message,
      mapSeverity(finding.severity)
    );

    diagnostic.source = "VibeSafe";
    diagnostic.code = finding.ruleId;

    // Attach the finding data so our CodeActionProvider can read it later
    (diagnostic as any).vibesafeFinding = finding;

    diagnostics.push(diagnostic);
  }

  // Update the collection for this specific document's URI
  collection.set(document.uri, diagnostics);
}

import * as path from "path";

/**
 * Updates the VS Code DiagnosticCollection with VibeSafe findings for the entire project.
 */
export function updateAllDiagnostics(
  rootPath: string,
  collection: vscode.DiagnosticCollection,
  findings: Finding[]
): void {
  // Clear existing diagnostics to avoid stale squiggles
  collection.clear();

  // Group findings by file path
  const findingsByFile = new Map<string, Finding[]>();
  for (const finding of findings) {
    if (!finding.file || !finding.line) continue;
    
    // Convert relative path to absolute
    const absPath = path.resolve(rootPath, finding.file);
    if (!findingsByFile.has(absPath)) {
      findingsByFile.set(absPath, []);
    }
    findingsByFile.get(absPath)!.push(finding);
  }

  // Iterate over files and create Diagnostics
  for (const [absPath, fileFindings] of findingsByFile.entries()) {
    const uri = vscode.Uri.file(absPath);
    const diagnostics: vscode.Diagnostic[] = [];
    
    for (const finding of fileFindings) {
      const lineIndex = finding.line! - 1;
      
      // Since we don't have the TextDocument loaded, we highlight the first 100 chars of the line.
      const range = new vscode.Range(lineIndex, 0, lineIndex, 100);
      
      const message = `VibeSafe [${finding.ruleId}]: ${finding.title}\n\n${finding.plainEnglishProblem}\n\nWhy it matters: ${finding.whyItMatters}`;
      const diagnostic = new vscode.Diagnostic(
        range,
        message,
        mapSeverity(finding.severity)
      );
      
      diagnostic.source = "VibeSafe";
      diagnostic.code = finding.ruleId;
      (diagnostic as any).vibesafeFinding = finding;
      
      diagnostics.push(diagnostic);
    }
    
    collection.set(uri, diagnostics);
  }
}
