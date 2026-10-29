import * as vscode from "vscode";
import type { Finding, Severity } from "@talaljaber/vibesafe-shared";

/** A VS Code diagnostic carrying the originating VibeSafe finding. */
export type DiagnosticWithFinding = vscode.Diagnostic & { vibesafeFinding?: Finding };

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
  findings: Finding[],
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
      lineText.text.length,
    );

    const message = `VibeSafe [${finding.ruleId}]: ${finding.title}\n\n${finding.plainEnglishProblem}\n\nWhy it matters: ${finding.whyItMatters}`;

    const diagnostic = new vscode.Diagnostic(range, message, mapSeverity(finding.severity));

    diagnostic.source = "VibeSafe";
    diagnostic.code = finding.ruleId;

    // Attach the finding data so our CodeActionProvider can read it later
    (diagnostic as DiagnosticWithFinding).vibesafeFinding = finding;

    diagnostics.push(diagnostic);
  }

  // Update the collection for this specific document's URI
  collection.set(document.uri, diagnostics);
}

import * as path from "path";
import { isInsideRoot } from "./util/findings.js";
import { diagnosticRangeCoords } from "./util/range.js";

/**
 * Updates the VS Code DiagnosticCollection with VibeSafe findings for the entire project.
 */
export function updateAllDiagnostics(
  rootPath: string,
  collection: vscode.DiagnosticCollection,
  findings: Finding[],
): void {
  // Clear existing diagnostics for this root only (other workspace folders keep theirs)
  const stale: vscode.Uri[] = [];
  collection.forEach((uri) => {
    if (isInsideRoot(rootPath, uri.fsPath)) stale.push(uri);
  });
  for (const uri of stale) collection.delete(uri);

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
      // Use the real line length when the document is open, otherwise extend to end of line.
      const openDoc = vscode.workspace.textDocuments.find((d) => d.uri.fsPath === absPath);
      const lineIdx = finding.line! - 1;
      const lineText =
        openDoc && lineIdx >= 0 && lineIdx < openDoc.lineCount
          ? openDoc.lineAt(lineIdx).text
          : undefined;
      const [sl, sc, el, ec] = diagnosticRangeCoords(finding.line!, lineText);
      const range = new vscode.Range(sl, sc, el, ec);

      const message = `VibeSafe [${finding.ruleId}]: ${finding.title}\n\n${finding.plainEnglishProblem}\n\nWhy it matters: ${finding.whyItMatters}`;
      const diagnostic = new vscode.Diagnostic(range, message, mapSeverity(finding.severity));

      diagnostic.source = "VibeSafe";
      diagnostic.code = finding.ruleId;
      (diagnostic as DiagnosticWithFinding).vibesafeFinding = finding;

      diagnostics.push(diagnostic);
    }

    collection.set(uri, diagnostics);
  }
}
