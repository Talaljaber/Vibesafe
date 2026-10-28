import type { AutoFixer, Finding, FixPreview, FixResult } from "@vibesafe/shared";
import fs from "node:fs/promises";
import { resolveInsideRoot } from "./safe-path.js";

const NEW_GITIGNORE = "node_modules\n.env\n.env.*\n!.env.example\n";

export class GitignoreEnvFixer implements AutoFixer {
  // We can handle both missing gitignore and env not ignored
  ruleId = "secret/env-not-ignored";
  description =
    "Safely adds .env and .env.* to .gitignore (keeping .env.example tracked) to prevent committing secrets.";

  canFix(finding: Finding): boolean {
    return (
      finding.ruleId === "secret/env-not-ignored" ||
      finding.ruleId === "structure/missing-gitignore"
    );
  }

  private plan(content: string): { hasEnv: boolean; append: string } {
    const lines = content.split(/\r?\n/).map((l) => l.trim());
    const hasEnv = lines.includes(".env");
    const hasWildcard = lines.includes(".env.*");
    const hasNegation = lines.includes("!.env.example");

    let append = "";
    if (!hasEnv) append += ".env\n.env.*\n!.env.example\n";
    else if (hasWildcard && !hasNegation) append += "!.env.example\n";
    if (append && content.length > 0 && !content.endsWith("\n")) append = "\n" + append;
    return { hasEnv, append };
  }

  private async read(rootPath: string): Promise<{ path: string; content: string | null }> {
    const gitignorePath = await resolveInsideRoot(rootPath, ".gitignore");
    try {
      return { path: gitignorePath, content: await fs.readFile(gitignorePath, "utf-8") };
    } catch (error) {
      if ((error as NodeJS.ErrnoException)?.code === "ENOENT")
        return { path: gitignorePath, content: null };
      throw error;
    }
  }

  async preview(_finding: Finding, rootPath: string): Promise<FixPreview> {
    let content: string | null;
    try {
      content = (await this.read(rootPath)).content;
    } catch (error) {
      return {
        description: `Cannot update .gitignore: ${(error as Error).message}`,
        filesToModify: [],
        filesToCreate: [],
      };
    }
    const exists = content !== null;
    const added =
      content !== null
        ? this.plan(content)
            .append.split("\n")
            .filter(Boolean)
            .map((l) => `+ ${l}`)
            .join("\n") + "\n"
        : "";
    return {
      description: "Appends `.env`, `.env.*` and `!.env.example` to .gitignore to protect secrets.",
      filesToModify: exists ? [".gitignore"] : [],
      filesToCreate: exists ? [] : [".gitignore"],
      diff: exists ? added : `Created .gitignore with:\n${NEW_GITIGNORE}`,
    };
  }

  async apply(_finding: Finding, rootPath: string): Promise<FixResult> {
    try {
      const { path: gitignorePath, content } = await this.read(rootPath);

      if (content === null) {
        await fs.writeFile(gitignorePath, NEW_GITIGNORE, { encoding: "utf-8", flag: "wx" });
        return {
          success: true,
          filesModified: [],
          filesCreated: [".gitignore"],
          message: "Created .gitignore and added .env protections.",
        };
      }

      const { hasEnv, append } = this.plan(content);
      if (append) await fs.appendFile(gitignorePath, append, "utf-8");

      return {
        success: true,
        filesModified: append ? [".gitignore"] : [],
        filesCreated: [],
        message: append
          ? hasEnv
            ? "Added !.env.example to .gitignore."
            : "Added .env to .gitignore."
          : ".env was already in .gitignore",
      };
    } catch (error) {
      return {
        success: false,
        filesModified: [],
        filesCreated: [],
        message: "Failed to update .gitignore",
        error: (error as Error).message,
      };
    }
  }
}
