# VibeGuard VS Code Extension

**VibeGuard** is your pre-deploy safety scanner, specifically designed to catch security flaws, exposed secrets, and codebase messes often introduced by AI "vibe coding."

## Features

- **Pre-Deploy Scanning**: Scans your codebase for issues before you ship.
- **Detailed Repair Plans**: Gives you a step-by-step repair plan with exact file locations and line numbers.
- **AI Prompts**: Provides copy-pasteable AI prompts for each issue so you can drop them straight into Cursor or Copilot to fix the problem instantly.
- **Beautiful HTML Reports**: Generates a clean, detailed dashboard summarizing your code health and deployment blockers.

## Usage

1. Open a project you want to scan.
2. Open the **Command Palette** (\`Ctrl+Shift+P\` or \`Cmd+Shift+P\`).
3. Type and select **VibeGuard: Scan Project**.
4. Review the findings in the VibeGuard sidebar (or check the generated HTML report).
5. Fix the issues before deploying!

## Settings

You can customize VibeGuard in your VS Code Settings:
- \`vibeguard.enabledCategories\`: Which categories of rules to run (e.g., \`security\`, \`quality\`).
- \`vibeguard.minSeverity\`: The minimum severity level to report (\`critical\`, \`high\`, \`medium\`, \`low\`).
- \`vibeguard.scanOnOpen\`: Automatically run a scan when you open a workspace.

## License
MIT
