import * as vscode from "vscode";
import type { ScanResult } from "@vibesafe/shared";

export class VibeSafeStatusBar {
  private statusBarItem: vscode.StatusBarItem;

  constructor() {
    this.statusBarItem = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Left,
      100
    );
    this.statusBarItem.command = "vibesafe.scan";
    this.statusBarItem.text = "$(shield) VibeSafe: Ready";
    this.statusBarItem.show();
  }

  public update(result: ScanResult) {
    const { deployStatus, score } = result;

    let icon = "$(shield)";
    let color: vscode.ThemeColor | undefined;

    switch (deployStatus) {
      case "safe":
        icon = "$(check)";
        color = new vscode.ThemeColor("testing.iconPassed");
        break;
      case "warning":
        icon = "$(warning)";
        color = new vscode.ThemeColor("testing.iconFailed");
        break;
      case "danger":
      case "blocker":
        icon = "$(error)";
        color = new vscode.ThemeColor("errorForeground");
        break;
    }

    this.statusBarItem.text = `${icon} VibeSafe: ${score} (${deployStatus})`;
    this.statusBarItem.color = color;
    this.statusBarItem.tooltip = `VibeSafe Deploy Score: ${score}\nStatus: ${deployStatus}\nFindings: ${result.findings.length}`;
  }

  public dispose() {
    this.statusBarItem.dispose();
  }
}
