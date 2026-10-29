import type { AutoFixer, Finding, FixPreview, FixResult } from "@talaljaber/vibesafe-shared";
import fs from "node:fs/promises";
import { resolveInsideRoot } from "./safe-path.js";

const NEW_GITIGNORE = "node_modules\n.env\n.env.*\n!.env.example\n";

const asDiff = (lines: string[]): string => lines.map((l) => `+ ${l}`).join("\n") + "\n";

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

  /**
   * Lines to append so that `.env` and every `.env.*` file are ignored while `.env.example`
   * stays tracked. A `.gitignore` that lists only `.env` still lets `.env.local` be committed,
   * so the wildcard is added too, and the negation always follows a wildcard we add.
   */
  private plan(content: string): { added: string[]; append: string } {
    // Root-anchored forms (`/.env`, `!/.env.example`) count the same as the plain ones.
    const lines = new Set(content.split(/\r?\n/).map((l) => l.trim().replace(/^(!?)\//, "$1")));
    const hasStar = lines.has(".env*");
    const hasEnv = hasStar || lines.has(".env");
    const hasWildcard = hasStar || lines.has(".env.*");
    const hasNegation = lines.has("!.env.example");

    const added: string[] = [];
    if (!hasEnv) added.push(".env");
    if (!hasWildcard) added.push(".env.*");
    if (!hasWildcard || !hasNegation) added.push("!.env.example");

    let append = added.length > 0 ? added.join("\n") + "\n" : "";
    if (append && content.length > 0 && !content.endsWith("\n")) append = "\n" + append;
    return { added, append };
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
    if (content === null) {
      return {
        description:
          "Creates .gitignore ignoring node_modules, .env and .env.* (keeping .env.example tracked).",
        filesToModify: [],
        filesToCreate: [".gitignore"],
        diff: asDiff(NEW_GITIGNORE.split("\n").filter(Boolean)),
      };
    }
    const { added } = this.plan(content);
    if (added.length === 0) {
      return {
        description: ".gitignore already ignores .env and .env.* files; nothing to change.",
        filesToModify: [],
        filesToCreate: [],
      };
    }
    return {
      description: `Appends ${added.join(", ")} to .gitignore so env files holding secrets are never committed.`,
      filesToModify: [".gitignore"],
      filesToCreate: [],
      diff: asDiff(added),
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

      const { added, append } = this.plan(content);
      if (append) await fs.appendFile(gitignorePath, append, "utf-8");

      return {
        success: true,
        filesModified: append ? [".gitignore"] : [],
        filesCreated: [],
        message: append
          ? `Added ${added.join(", ")} to .gitignore.`
          : ".env and .env.* were already in .gitignore",
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
