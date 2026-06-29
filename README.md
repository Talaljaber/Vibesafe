<div align="center">
  <h1>🛡️ VibeSafe</h1>
  <p><strong>The Pre-Deploy Safety Scanner for Vibe-Coded Apps</strong></p>
  <p>
    <a href="https://www.npmjs.com/package/@vibesafe/cli"><img src="https://img.shields.io/npm/v/@vibesafe/cli?style=flat-square&color=blue" alt="NPM Version"></a>
    <a href="https://marketplace.visualstudio.com/items?itemName=talaljaber.vibesafe"><img src="https://img.shields.io/visual-studio-marketplace/v/talaljaber.vibesafe?style=flat-square&color=blueviolet" alt="VS Code Marketplace"></a>
    <img src="https://img.shields.io/badge/License-MIT-green.svg?style=flat-square" alt="License">
  </p>
</div>

<hr />

## 🚨 The "Vibe Coding" Problem
"Vibe coding" with AI tools (like Cursor, GitHub Copilot, or Claude) is incredibly fast and fun, but it often leads to messy codebases, exposed secrets, and subtle security flaws. 

**VibeSafe** acts as your automated security engineer. It scans your code before you deploy and tells you exactly what to fix, complete with copy-pasteable AI prompts and one-click auto-fixes.

## 📦 Installation & Usage

### 💻 Command Line Interface (CLI)
You can run VibeSafe instantly using `npx`, or install it as a development dependency.

**Option 1: Run instantly (No installation)**
```bash
npx vibesafe scan .
```

**Option 2: Install locally in your project**
```bash
npm install -D @vibesafe/cli
# or
pnpm add -D @vibesafe/cli
# or
yarn add -D @vibesafe/cli
```

**CLI Commands:**
- `npx vibesafe scan [path]` - Scans the specified directory, outputs a detailed **Repair Plan**, and generates a beautiful `vibesafe-report.html` dashboard.
- `npx vibesafe --help` - Shows all available options and commands.

### 🔌 VS Code Extension
Prefer working entirely within your editor? Install the **VibeSafe** extension!

1. Search for **VibeSafe** in the VS Code Extensions marketplace and click Install.
2. Open the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`).
3. Run **`VibeSafe: Scan Project`**.
4. View issues natively in the sidebar, get AI fix prompts, and apply automated safe fixes right from your editor.

## 🏗️ Monorepo Structure

This project is structured as a `pnpm` monorepo:

- `packages/core`: The main scanning engine and detectors (secrets, auth, codebase mess).
- `packages/shared`: Shared types, interfaces, and configurations.
- `packages/cli`: The interactive command-line interface.
- `packages/vscode`: The Visual Studio Code extension.

## 🛠️ Local Development

To contribute or run VibeSafe locally:

1. Clone the repository:
   ```bash
   git clone https://github.com/talaljaber/vibesafe.git
   cd vibesafe
   ```

2. Install dependencies using `pnpm`:
   ```bash
   pnpm install
   ```

3. Build all packages:
   ```bash
   pnpm run build
   ```

4. Run the CLI locally:
   ```bash
   pnpm --filter @vibesafe/cli exec vibesafe scan .
   ```

## 📝 License
[MIT](LICENSE)
