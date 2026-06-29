import type { AutoFixer, Finding, FixPreview, FixResult } from "@vibeguard/shared";
import fs from "node:fs/promises";
import path from "node:path";

export class EnvExampleFixer implements AutoFixer {
  ruleId = "structure/missing-env-example";
  description = "Generates a .env.example file from an existing .env file, removing sensitive values.";

  canFix(finding: Finding): boolean {
    return finding.ruleId === this.ruleId;
  }

  async preview(finding: Finding, rootPath: string): Promise<FixPreview> {
    const envPath = path.join(rootPath, ".env");
    let content = "";
    try {
      content = await fs.readFile(envPath, "utf-8");
    } catch {
      return {
        description: "Cannot find .env file to generate from.",
        filesToModify: [],
        filesToCreate: [],
      };
    }

    const exampleContent = this.generateExampleContent(content);

    return {
      description: "Creates `.env.example` by stripping values from `.env`.",
      filesToModify: [],
      filesToCreate: [".env.example"],
      diff: `+ ${exampleContent.split("\n").join("\n+ ")}`
    };
  }

  async apply(finding: Finding, rootPath: string): Promise<FixResult> {
    const envPath = path.join(rootPath, ".env");
    const examplePath = path.join(rootPath, ".env.example");

    try {
      const content = await fs.readFile(envPath, "utf-8");
      const exampleContent = this.generateExampleContent(content);
      await fs.writeFile(examplePath, exampleContent, "utf-8");

      return {
        success: true,
        filesModified: [],
        filesCreated: [".env.example"],
        message: "Generated .env.example successfully."
      };
    } catch (error: any) {
      return {
        success: false,
        filesModified: [],
        filesCreated: [],
        message: "Failed to create .env.example",
        error: error.message
      };
    }
  }

  private generateExampleContent(envContent: string): string {
    const lines = envContent.split("\n");
    const exampleLines = lines.map(line => {
      // Keep comments and empty lines
      if (!line.trim() || line.trim().startsWith("#")) {
        return line;
      }
      
      // Strip values from key=value pairs
      const match = line.match(/^([^=]+)=.*$/);
      if (match) {
        return `${match[1]}=`;
      }
      
      return line; // Fallback
    });

    return exampleLines.join("\n");
  }
}
