import * as vscode from "vscode";
import path from "path";
import type { ScanResult, Finding, Severity } from "@vibesafe/shared";

type TreeElement = GroupItem | FindingItem;

export class VibeSafeIssuesProvider implements vscode.TreeDataProvider<TreeElement> {
  private _onDidChangeTreeData: vscode.EventEmitter<TreeElement | undefined | null | void> = new vscode.EventEmitter<TreeElement | undefined | null | void>();
  readonly onDidChangeTreeData: vscode.Event<TreeElement | undefined | null | void> = this._onDidChangeTreeData.event;

  private latestResult?: ScanResult;

  constructor() {}

  public update(result: ScanResult) {
    this.latestResult = result;
    this.refresh();
  }

  public refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: TreeElement): vscode.TreeItem {
    return element;
  }

  getChildren(element?: TreeElement): Thenable<TreeElement[]> {
    if (!this.latestResult) {
      return Promise.resolve([]);
    }

    if (!element) {
      // Root level - group by Severity (Critical, High, Medium, Low)
      const severityGroups = ["critical", "high", "medium", "low"] as Severity[];
      const groups = severityGroups.map(sev => {
        const count = this.latestResult!.findings.filter(f => f.severity === sev).length;
        if (count === 0) return null;
        return new GroupItem(sev, count, vscode.TreeItemCollapsibleState.Expanded);
      }).filter(Boolean) as GroupItem[];
      
      return Promise.resolve(groups);
    }

    if (element instanceof GroupItem) {
      // Children of a severity group are the actual findings
      const findings = this.latestResult.findings.filter(f => f.severity === element.severity);
      return Promise.resolve(findings.map(f => new FindingItem(f, this.latestResult!.projectPath)));
    }

    return Promise.resolve([]);
  }
}

class GroupItem extends vscode.TreeItem {
  constructor(
    public readonly severity: Severity,
    public readonly count: number,
    collapsibleState: vscode.TreeItemCollapsibleState
  ) {
    super(`${severity.charAt(0).toUpperCase() + severity.slice(1)} (${count})`, collapsibleState);
    
    let icon = "info";
    if (severity === "critical" || severity === "high") icon = "error";
    if (severity === "medium") icon = "warning";
    
    this.iconPath = new vscode.ThemeIcon(icon, getSeverityColor(severity));
    this.contextValue = "severityGroup";
  }
}

class FindingItem extends vscode.TreeItem {
  constructor(
    public readonly finding: Finding,
    private readonly projectPath: string
  ) {
    super(finding.title, vscode.TreeItemCollapsibleState.None);
    
    this.description = finding.file ? `${finding.file}:${finding.line || 1}` : "Project level";
    this.tooltip = finding.plainEnglishProblem;
    
    let icon = "info";
    if (finding.severity === "critical" || finding.severity === "high") icon = "error";
    if (finding.severity === "medium") icon = "warning";
    
    this.iconPath = new vscode.ThemeIcon(icon, getSeverityColor(finding.severity));
    this.contextValue = finding.autoFixAvailable ? "findingWithFix" : "finding";

    if (finding.file) {
      const fullPath = path.join(projectPath, finding.file);
      this.command = {
        command: "vscode.open",
        title: "Open File",
        arguments: [
          vscode.Uri.file(fullPath),
          {
            selection: new vscode.Range(
              Math.max(0, (finding.line || 1) - 1),
              0,
              Math.max(0, (finding.endLine || finding.line || 1) - 1),
              200
            )
          }
        ]
      };
    }
  }
}

function getSeverityColor(severity: Severity): vscode.ThemeColor | undefined {
  switch (severity) {
    case "critical":
    case "high":
      return new vscode.ThemeColor("problemsErrorIcon.foreground");
    case "medium":
      return new vscode.ThemeColor("problemsWarningIcon.foreground");
    case "low":
    default:
      return new vscode.ThemeColor("problemsInfoIcon.foreground");
  }
}
