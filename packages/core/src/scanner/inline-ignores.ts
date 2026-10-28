import type { Finding } from "@vibesafe/shared";

/**
 * Inline ignore directives:
 *
 *   // vibesafe-disable-line [ruleId[, ruleId...]]
 *   // vibesafe-disable-next-line [ruleId[, ruleId...]]
 *   // vibesafe-disable-file [ruleId[, ruleId...]]
 *
 * No rule ids means "all rules". A trailing `*` in a rule id is a prefix
 * wildcard (e.g. `secret/*`). The directive must sit inside a comment
 * (`//`, `/* *\/`, `{/* *\/}` or `#`); the same text inside a string literal is
 * not a directive.
 */

/** null = no directive, "all" = every rule, otherwise the listed rule ids. */
type IgnoreSpec = null | "all" | string[];

interface FileDirectives {
  file: IgnoreSpec;
  line: Map<number, IgnoreSpec>; // 1-indexed line -> spec for that line
  nextLine: Map<number, IgnoreSpec>; // 1-indexed line the directive is ON
}

const DIRECTIVE_RE = /vibesafe-disable-(next-line|line|file)(?![\w-])([^\n]*)/g;
const RULE_ID_RE = /^[\w-]+\/[\w./*-]+$/;

function merge(a: IgnoreSpec, b: IgnoreSpec): IgnoreSpec {
  if (a === null) return b;
  if (b === null) return a;
  if (a === "all" || b === "all") return "all";
  return [...a, ...b];
}

function parseRuleIds(rest: string): IgnoreSpec {
  // Strip a closing block-comment / JSX terminator and anything after it.
  const cleaned = rest.replace(/\*\/.*$/, "");
  const ids: string[] = [];
  for (const token of cleaned.split(/[\s,]+/).filter(Boolean)) {
    if (!RULE_ID_RE.test(token)) break; // free-text explanation starts here
    ids.push(token);
  }
  return ids.length > 0 ? ids : "all";
}

/** Returns the comment text fragments of one line, tracking block-comment state across lines. */
function extractComments(line: string, state: { inBlock: boolean }): string[] {
  const out: string[] = [];
  let i = 0;

  if (state.inBlock) {
    const end = line.indexOf("*/");
    if (end === -1) return [line];
    out.push(line.slice(0, end + 2));
    state.inBlock = false;
    i = end + 2;
  }

  let quote: string | null = null;
  for (; i < line.length; i++) {
    const ch = line[i]!;
    if (quote) {
      if (ch === "\\") i++;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      quote = ch;
    } else if (ch === "/" && line[i + 1] === "/") {
      out.push(line.slice(i));
      return out;
    } else if (ch === "/" && line[i + 1] === "*") {
      const end = line.indexOf("*/", i + 2);
      if (end === -1) {
        out.push(line.slice(i));
        state.inBlock = true;
        return out;
      }
      out.push(line.slice(i, end + 2));
      i = end + 1;
    } else if (ch === "#" && (i === 0 || /\s/.test(line[i - 1]!))) {
      out.push(line.slice(i));
      return out;
    }
  }
  return out;
}

function parseDirectives(content: string): FileDirectives {
  const result: FileDirectives = { file: null, line: new Map(), nextLine: new Map() };
  if (!content.includes("vibesafe-disable-")) return result;

  const state = { inBlock: false };
  const lines = content.split("\n");
  for (let idx = 0; idx < lines.length; idx++) {
    const lineNo = idx + 1;
    for (const comment of extractComments(lines[idx]!, state)) {
      DIRECTIVE_RE.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = DIRECTIVE_RE.exec(comment)) !== null) {
        const spec = parseRuleIds(m[2] ?? "");
        if (m[1] === "file") result.file = merge(result.file, spec);
        else if (m[1] === "line") result.line.set(lineNo, merge(result.line.get(lineNo) ?? null, spec));
        else result.nextLine.set(lineNo, merge(result.nextLine.get(lineNo) ?? null, spec));
      }
    }
  }
  return result;
}

function matches(spec: IgnoreSpec, ruleId: string): boolean {
  if (spec === null) return false;
  if (spec === "all") return true;
  return spec.some((id) => (id.endsWith("*") ? ruleId.startsWith(id.slice(0, -1)) : id === ruleId));
}

/** Drops findings suppressed by inline directives in the files they point at. */
export async function applyInlineIgnores(
  findings: Finding[],
  readFile: (relativePath: string) => Promise<string>,
): Promise<Finding[]> {
  const cache = new Map<string, FileDirectives>();
  const kept: Finding[] = [];

  for (const finding of findings) {
    if (!finding.file) {
      kept.push(finding);
      continue;
    }

    let directives = cache.get(finding.file);
    if (!directives) {
      directives = parseDirectives(await readFile(finding.file));
      cache.set(finding.file, directives);
    }

    // vibesafe-disable-file applies to every finding in the file, with or without a line.
    if (matches(directives.file, finding.ruleId)) continue;

    if (finding.line) {
      const sameLine = directives.line.get(finding.line) ?? null;
      const prevLine = directives.nextLine.get(finding.line - 1) ?? null;
      if (matches(sameLine, finding.ruleId) || matches(prevLine, finding.ruleId)) continue;
    }

    kept.push(finding);
  }
  return kept;
}
