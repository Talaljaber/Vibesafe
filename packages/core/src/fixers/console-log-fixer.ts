import type { AutoFixer, Finding, FixPreview, FixResult } from "@vibesafe/shared";
import fs from "node:fs/promises";
import path from "node:path";

export class ConsoleLogFixer implements AutoFixer {
  ruleId = "code_quality/console-log";
  description = "Safely comments out leftover console.log statements to keep production logs clean.";

  canFix(finding: Finding): boolean {
    return finding.ruleId === this.ruleId && !!finding.file && !!finding.line;
  }

  async preview(finding: Finding, rootPath: string): Promise<FixPreview> {
    if (!finding.file || !finding.line) {
      return { description: "Missing file or line number.", filesToModify: [], filesToCreate: [] };
    }

    const filePath = path.join(rootPath, finding.file);
    let content = "";
    try {
      content = await fs.readFile(filePath, "utf-8");
    } catch {
      return { description: "Cannot read file.", filesToModify: [], filesToCreate: [] };
    }

    const lines = content.split("\n");
    const targetLineIdx = finding.line - 1;
    
    if (targetLineIdx < 0 || targetLineIdx >= lines.length) {
      return { description: "Invalid line number.", filesToModify: [], filesToCreate: [] };
    }

    const originalLine = lines[targetLineIdx] || "";
    const fixedLine = originalLine.replace(/console\.log/g, "/* console.log */");

    return {
      description: `Comments out console.log on line ${finding.line} in ${finding.file}`,
      filesToModify: [finding.file],
      filesToCreate: [],
      diff: `- ${originalLine}\n+ ${fixedLine}`
    };
  }

  async apply(finding: Finding, rootPath: string): Promise<FixResult> {
    if (!finding.file || !finding.line) {
      return { success: false, filesModified: [], filesCreated: [], message: "Missing location." };
    }

    const filePath = path.join(rootPath, finding.file);
    try {
      const content = await fs.readFile(filePath, "utf-8");
      const lines = content.split("\n");
      const targetLineIdx = finding.line - 1;

      if (targetLineIdx >= 0 && targetLineIdx < lines.length) {
        const lineToFix = lines[targetLineIdx] || "";
        lines[targetLineIdx] = lineToFix.replace(/console\.log/g, "/* console.log */");
        await fs.writeFile(filePath, lines.join("\n"), "utf-8");

        return {
          success: true,
          filesModified: [finding.file],
          filesCreated: [],
          message: `Commented out console.log on line ${finding.line}.`
        };
      } else {
        return { success: false, filesModified: [], filesCreated: [], message: "Invalid line." };
      }
    } catch (error: any) {
      return {
        success: false,
        filesModified: [],
        filesCreated: [],
        message: "Failed to apply fix.",
        error: error.message
      };
    }
  }
}
