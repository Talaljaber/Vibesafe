# 🛡️ VibeGuard

**The Pre-Deploy Safety Scanner for Vibe-Coded Apps.**

"Vibe coding" with AI tools (like Cursor, GitHub Copilot, or Claude) is incredibly fast and fun, but it often leads to messy codebases, exposed secrets, and subtle security flaws. VibeGuard acts as your automated security engineer. It scans your code before you deploy and tells you exactly what to fix.

## 🚀 Quick Start (CLI)

You can run VibeGuard instantly in any of your projects without installing it:

\`\`\`bash
npx @vibeguard/cli scan .
\`\`\`

VibeGuard will scan your project, output a detailed **Repair Plan** in the terminal, and generate a beautiful `vibeguard-report.html` dashboard with your code health score.

## 💻 VS Code Extension

Prefer working entirely within your editor? Install the **VibeGuard** extension from the VS Code Marketplace!

1. Open the Command Palette (\`Ctrl+Shift+P\` / \`Cmd+Shift+P\`)
2. Run **\`VibeGuard: Scan Project\`**
3. View the issues and fix prompts right inside your editor.

## 📦 Monorepo Structure

This project is structured as a `pnpm` monorepo:

- \`packages/core\`: The main scanning engine and detectors (secrets, auth, codebase mess).
- \`packages/shared\`: Shared types and interfaces.
- \`packages/cli\`: The interactive command-line interface.
- \`packages/vscode\`: The Visual Studio Code extension.

## 🛠️ Local Development

To contribute or run VibeGuard locally:

1. Clone the repository:
   \`\`\`bash
   git clone https://github.com/talaljaber/vibeguard.git
   cd vibeguard
   \`\`\`

2. Install dependencies using \`pnpm\`:
   \`\`\`bash
   pnpm install
   \`\`\`

3. Build all packages:
   \`\`\`bash
   pnpm run build
   \`\`\`

4. Run the CLI locally:
   \`\`\`bash
   pnpm --filter @vibeguard/cli exec vibeguard scan .
   \`\`\`

## 📝 License
MIT
