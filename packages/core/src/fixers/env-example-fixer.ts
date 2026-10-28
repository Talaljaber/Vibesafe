import type { AutoFixer, Finding, FixPreview, FixResult } from "@vibesafe/shared";
import fs from "node:fs/promises";
import { resolveInsideRoot } from "./safe-path.js";

const SOURCE_FILES = [".env", ".env.local"];
const KEY_PATTERN = /^(export\s+)?[A-Za-z_][A-Za-z0-9_.-]*$/;

export class EnvExampleFixer implements AutoFixer {
  ruleId = "structure/missing-env-example";
  description =
    "Generates a .env.example file from .env (or .env.local), keeping only variable names. Never overwrites an existing .env.example.";

  canFix(finding: Finding): boolean {
    return finding.ruleId === this.ruleId;
  }

  private async readSource(rootPath: string): Promise<{ name: string; content: string } | null> {
    for (const name of SOURCE_FILES) {
      try {
        const p = await resolveInsideRoot(rootPath, name);
        return { name, content: await fs.readFile(p, "utf-8") };
      } catch {
        // try next candidate
      }
    }
    return null;
  }

  private async exampleExists(rootPath: string): Promise<boolean> {
    try {
      await fs.lstat(await resolveInsideRoot(rootPath, ".env.example"));
      return true;
    } catch (error: any) {
      // A rejected (e.g. symlinked) path is treated as "exists" so we never write to it.
      return error?.code !== "ENOENT";
    }
  }

  async preview(_finding: Finding, rootPath: string): Promise<FixPreview> {
    if (await this.exampleExists(rootPath)) {
      return {
        description: ".env.example already exists; it will not be overwritten.",
        filesToModify: [],
        filesToCreate: [],
      };
    }
    const source = await this.readSource(rootPath);
    if (!source) {
      return {
        description: "Cannot find .env or .env.local file to generate from.",
        filesToModify: [],
        filesToCreate: [],
      };
    }

    const exampleContent = this.generateExampleContent(source.content);
    return {
      description: `Creates \`.env.example\` by stripping values from \`${source.name}\`.`,
      filesToModify: [],
      filesToCreate: [".env.example"],
      diff: `+ ${exampleContent.split(/\r?\n/).join("\n+ ")}`,
    };
  }

  async apply(_finding: Finding, rootPath: string): Promise<FixResult> {
    const fail = (message: string, error?: string): FixResult => ({
      success: false,
      filesModified: [],
      filesCreated: [],
      message,
      ...(error ? { error } : {}),
    });

    try {
      const source = await this.readSource(rootPath);
      if (!source) return fail("Cannot find .env or .env.local file to generate from.");

      const examplePath = await resolveInsideRoot(rootPath, ".env.example");
      await fs.writeFile(examplePath, this.generateExampleContent(source.content), {
        encoding: "utf-8",
        flag: "wx",
      });

      return {
        success: true,
        filesModified: [],
        filesCreated: [".env.example"],
        message: `Generated .env.example from ${source.name}.`,
      };
    } catch (error: any) {
      if (error?.code === "EEXIST") {
        return fail(".env.example already exists; not overwriting it.", error.message);
      }
      return fail("Failed to create .env.example", error?.message);
    }
  }

  /**
   * Emits only `KEY=` lines (preserving `export ` and the original EOL style).
   * Anything that is not a plain `KEY=...` assignment is dropped, including
   * multi-line quoted continuation lines and comments containing `=`.
   */
  private generateExampleContent(envContent: string): string {
    const eol = envContent.includes("\r\n") ? "\r\n" : "\n";
    const lines = envContent.split(/\r?\n/);
    const out: string[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? "";
      const trimmed = line.trim();
      if (!trimmed) {
        out.push("");
        continue;
      }
      if (trimmed.startsWith("#")) {
        if (!trimmed.includes("=")) out.push(trimmed);
        continue;
      }

      const eq = line.indexOf("=");
      if (eq <= 0) continue;
      const key = line.slice(0, eq).trim();
      if (!KEY_PATTERN.test(key)) continue;
      out.push(`${key}=`);

      // Skip continuation lines of an unterminated quoted value.
      const value = line.slice(eq + 1).trimStart();
      const quote = value[0];
      if (quote === '"' || quote === "'" || quote === "`") {
        let closed = value.indexOf(quote, 1) !== -1;
        while (!closed && i + 1 < lines.length) {
          i++;
          closed = (lines[i] ?? "").includes(quote);
        }
      }
    }

    return out.join(eol);
  }
}
