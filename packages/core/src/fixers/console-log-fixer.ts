import type { AutoFixer, Finding, FixPreview, FixResult } from "@talaljaber/vibesafe-shared";
import fs from "node:fs/promises";
import path from "node:path";
import { findMatchingBrace, isJsxPath, maskCode } from "../detectors/utils/js-source.js";
import { resolveInsideRoot } from "./safe-path.js";

type Edit = { startLine: number; endLine: number; before: string[]; after: string[] };
type Analysis = { ok: true; content: string; edit: Edit } | { ok: false; reason: string };

/** Characters after which `console.log(` would be an operand or argument, not a statement. */
const EXPRESSION_PREV = new Set("(,=:?[+-*/%&|^!~<>.".split(""));

/**
 * Finds the standalone `console.log(...)` statement starting on `line` and the lines it
 * spans. The file is masked with the shared JS source model (comments, strings, template
 * text and regex literals blanked), so parentheses inside strings, template
 * substitutions or comments never confuse the call's end, and a `console.log(` inside a
 * string or comment is never touched.
 */
function analyze(content: string, line: number, file: string): Analysis {
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

  const code = maskCode(content, { jsx: isJsxPath(file) });
  const callStart = lineStart + (m[1] ?? "").length;
  if (code.slice(callStart, callStart + 11) !== "console.log") {
    return { ok: false, reason: `Line ${line} is inside a string or comment; not modifying it.` };
  }
  let p = callStart - 1;
  while (p >= 0 && /\s/.test(code[p]!)) p--;
  if (p >= 0 && EXPRESSION_PREV.has(code[p]!)) {
    return {
      ok: false,
      reason: "console.log(...) is part of a larger expression or statement; not modifying it.",
    };
  }

  // A braceless if/else/for/while body would change meaning if its statement were removed.
  for (let k = idx - 1; k >= 0; k--) {
    const prev = (lines[k] ?? "").trim();
    if (!prev || prev.startsWith("//")) continue;
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
  const close = findMatchingBrace(content, open, code);
  if (close < 0) {
    return { ok: false, reason: "Could not find the end of the console.log(...) call safely." };
  }
  const end = close + 1;

  const endLineIdx = content.slice(0, end).split("\n").length - 1;
  const lineEnd = content.indexOf("\n", end);
  // Comments after the call are masked to spaces, so only `;` and whitespace may remain.
  const tail = code.slice(end, lineEnd < 0 ? code.length : lineEnd).replace(/\r$/, "");
  let next = end;
  while (next < code.length && /\s/.test(code[next]!)) next++;
  // Without a `;`, a following line starting with `(`, `[`, `.`, a template or an operator
  // continues the same expression (ASI), so commenting the call out would change it.
  const continues = !tail.includes(";") && /[([`.+\-*/%,?:=<>&|]/.test(code[next] ?? "");
  if (!/^\s*;?\s*$/.test(tail) || continues) {
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
    return { filePath, result: analyze(content, finding.line as number, finding.file as string) };
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
