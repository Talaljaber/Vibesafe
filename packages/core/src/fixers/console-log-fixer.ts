import type { AutoFixer, Finding, FixPreview, FixResult } from "@vibesafe/shared";
import fs from "node:fs/promises";
import path from "node:path";
import { resolveInsideRoot } from "./safe-path.js";

type Edit = { startLine: number; endLine: number; before: string[]; after: string[] };
type Analysis = { ok: true; content: string; edit: Edit } | { ok: false; reason: string };

/** Returns "code" if `offset` is at top-level code, otherwise what it is inside. */
function lexStateAt(content: string, offset: number): "code" | "string" | "comment" {
  let i = 0;
  while (i < offset) {
    const c = content[i];
    const n = content[i + 1];
    if (c === "/" && n === "/") {
      const nl = content.indexOf("\n", i);
      if (nl === -1 || nl >= offset) return "comment";
      i = nl + 1;
    } else if (c === "/" && n === "*") {
      const close = content.indexOf("*/", i + 2);
      if (close === -1 || close + 2 > offset) return "comment";
      i = close + 2;
    } else if (c === '"' || c === "'" || c === "`") {
      let j = i + 1;
      while (j < content.length && content[j] !== c) {
        if (content[j] === "\\") j++;
        else if (c !== "`" && content[j] === "\n") break;
        j++;
      }
      if (j >= offset) return "string";
      i = j + 1;
    } else {
      i++;
    }
  }
  return "code";
}

/**
 * Finds the end offset (exclusive) of the call whose opening paren is at `open`,
 * or null when the parentheses do not balance or the call contains constructs
 * we do not scan safely (template literals with substitutions).
 */
function findCallEnd(content: string, open: number): number | null {
  let depth = 0;
  let i = open;
  while (i < content.length) {
    const c = content[i];
    const n = content[i + 1];
    if (c === "/" && n === "/") {
      const nl = content.indexOf("\n", i);
      if (nl === -1) return null;
      i = nl + 1;
      continue;
    }
    if (c === "/" && n === "*") {
      const close = content.indexOf("*/", i + 2);
      if (close === -1) return null;
      i = close + 2;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      let j = i + 1;
      while (j < content.length && content[j] !== c) {
        if (c === "`" && content[j] === "$" && content[j + 1] === "{") return null;
        if (content[j] === "\\") j++;
        else if (c !== "`" && content[j] === "\n") return null;
        j++;
      }
      if (j >= content.length) return null;
      i = j + 1;
      continue;
    }
    if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth === 0) return i + 1;
    }
    i++;
  }
  return null;
}

function analyze(content: string, line: number): Analysis {
  const lines = content.split("\n");
  const idx = line - 1;
  if (idx < 0 || idx >= lines.length) return { ok: false, reason: "Invalid line number." };

  const first = lines[idx] ?? "";
  const m = /^([ \t]*)console\.log\s*\(/.exec(first);
  if (!m) {
    return {
      ok: false,
      reason: `Line ${line} no longer contains a standalone console.log( statement.`,
    };
  }

  let lineStart = 0;
  for (let k = 0; k < idx; k++) lineStart += (lines[k] ?? "").length + 1;

  if (lexStateAt(content, lineStart) !== "code") {
    return { ok: false, reason: `Line ${line} is inside a string or comment; not modifying it.` };
  }

  // A braceless if/else/for/while body would change meaning if its statement were removed.
  for (let k = idx - 1; k >= 0; k--) {
    const prev = (lines[k] ?? "").trim();
    if (!prev) continue;
    if (prev.endsWith(")") || prev.endsWith("=>") || /(^|[\s}])else$/.test(prev)) {
      return {
        ok: false,
        reason:
          "Previous line may be a control statement or unterminated expression; not safe to comment out.",
      };
    }
    break;
  }

  const open = lineStart + m[0].length - 1;
  const end = findCallEnd(content, open);
  if (end === null) {
    return { ok: false, reason: "Could not find the end of the console.log(...) call safely." };
  }

  const endLineIdx = content.slice(0, end).split("\n").length - 1;
  const lastLine = lines[endLineIdx] ?? "";
  const lastLineEnd = end - (content.slice(0, end).lastIndexOf("\n") + 1);
  const tail = lastLine.slice(lastLineEnd).replace(/\r$/, "");
  if (!/^\s*;?\s*(\/\/.*)?$/.test(tail)) {
    return {
      ok: false,
      reason: "console.log(...) is part of a larger expression or statement; not modifying it.",
    };
  }

  const before = lines.slice(idx, endLineIdx + 1);
  const after = before.map((l) => {
    const cr = l.endsWith("\r") ? "\r" : "";
    const body = cr ? l.slice(0, -1) : l;
    const indent = /^[ \t]*/.exec(body)?.[0] ?? "";
    return `${indent}// ${body.slice(indent.length)}${cr}`;
  });
  return { ok: true, content, edit: { startLine: idx, endLine: endLineIdx, before, after } };
}

export class ConsoleLogFixer implements AutoFixer {
  ruleId = "code_quality/console-log";
  description =
    "Comments out standalone console.log(...) statements with // (line numbers are preserved). Calls used inside expressions, arrow bodies, strings or braceless control statements are left untouched.";

  canFix(finding: Finding): boolean {
    if (finding.ruleId !== this.ruleId || !finding.file || !finding.line) return false;
    return (
      !path.isAbsolute(finding.file) &&
      !path.win32.isAbsolute(finding.file) &&
      !finding.file.split(/[\\/]/).includes("..")
    );
  }

  private async load(
    finding: Finding,
    rootPath: string,
  ): Promise<{ filePath: string; result: Analysis }> {
    const filePath = await resolveInsideRoot(rootPath, finding.file as string);
    const content = await fs.readFile(filePath, "utf-8");
    return { filePath, result: analyze(content, finding.line as number) };
  }

  async preview(finding: Finding, rootPath: string): Promise<FixPreview> {
    const none = (description: string): FixPreview => ({
      description,
      filesToModify: [],
      filesToCreate: [],
    });
    if (!finding.file || !finding.line) return none("Missing file or line number.");

    try {
      const { result } = await this.load(finding, rootPath);
      if (!result.ok) return none(result.reason);
      const { edit } = result;
      return {
        description: `Comments out console.log on line ${finding.line} in ${finding.file}`,
        filesToModify: [finding.file],
        filesToCreate: [],
        diff:
          edit.before.map((l) => `- ${l}`).join("\n") +
          "\n" +
          edit.after.map((l) => `+ ${l}`).join("\n"),
      };
    } catch (error) {
      return none(`Cannot read file: ${(error as Error).message}`);
    }
  }

  async apply(finding: Finding, rootPath: string): Promise<FixResult> {
    const fail = (message: string, error?: string): FixResult => ({
      success: false,
      filesModified: [],
      filesCreated: [],
      message,
      ...(error ? { error } : {}),
    });
    if (!finding.file || !finding.line) return fail("Missing location.");

    try {
      const { filePath, result } = await this.load(finding, rootPath);
      if (!result.ok) return fail(result.reason);

      const lines = result.content.split("\n");
      lines.splice(result.edit.startLine, result.edit.after.length, ...result.edit.after);
      const updated = lines.join("\n");
      if (updated === result.content) return fail("Nothing to change.");

      await fs.writeFile(filePath, updated, "utf-8");
      return {
        success: true,
        filesModified: [finding.file],
        filesCreated: [],
        message: `Commented out console.log on line ${finding.line}.`,
      };
    } catch (error) {
      return fail("Failed to apply fix.", (error as Error)?.message);
    }
  }
}
