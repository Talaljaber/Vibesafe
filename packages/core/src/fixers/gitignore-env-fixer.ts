import type { AutoFixer, Finding, FixPreview, FixResult } from "@vibesafe/shared";
import fs from "node:fs/promises";
import path from "node:path";

export class GitignoreEnvFixer implements AutoFixer {
  // We can handle both missing gitignore and env not ignored
  ruleId = "secret/env-not-ignored"; 
  description = "Safely adds .env to .gitignore to prevent committing secrets.";

  canFix(finding: Finding): boolean {
    return finding.ruleId === "secret/env-not-ignored" || finding.ruleId === "structure/missing-gitignore";
  }

  async preview(finding: Finding, rootPath: string): Promise<FixPreview> {
    const gitignorePath = path.join(rootPath, ".gitignore");
    let exists = true;
    try {
      await fs.access(gitignorePath);
    } catch {
      exists = false;
    }

    return {
      description: "Appends `.env` and `.env.*` to .gitignore to protect secrets.",
      filesToModify: exists ? [".gitignore"] : [],
      filesToCreate: exists ? [] : [".gitignore"],
      diff: exists ? "+ .env\n+ .env.*\n" : "Created .gitignore with:\nnode_modules\n.env\n.env.*\n"
    };
  }

  async apply(finding: Finding, rootPath: string): Promise<FixResult> {
    const gitignorePath = path.join(rootPath, ".gitignore");
    let exists = true;
    let content = "";
    try {
      content = await fs.readFile(gitignorePath, "utf-8");
    } catch {
      exists = false;
    }

    try {
      if (!exists) {
        await fs.writeFile(gitignorePath, "node_modules\n.env\n.env.*\n", "utf-8");
        return {
          success: true,
          filesModified: [],
          filesCreated: [".gitignore"],
          message: "Created .gitignore and added .env protections."
        };
      }

      // Check if it already has .env
      const lines = content.split("\n");
      const hasEnv = lines.some(line => line.trim() === ".env");
      
      let toAppend = "";
      if (!hasEnv) {
        toAppend += (content.endsWith("\n") || content.length === 0 ? "" : "\n") + ".env\n.env.*\n";
        await fs.appendFile(gitignorePath, toAppend, "utf-8");
      }

      return {
        success: true,
        filesModified: [".gitignore"],
        filesCreated: [],
        message: hasEnv ? ".env was already in .gitignore" : "Added .env to .gitignore."
      };
    } catch (error: any) {
      return {
        success: false,
        filesModified: [],
        filesCreated: [],
        message: "Failed to update .gitignore",
        error: error.message
      };
    }
  }
}
