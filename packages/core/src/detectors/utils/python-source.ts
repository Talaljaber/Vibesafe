// ─────────────────────────────────────────────────────────────────────────────
// Line-based helpers for Python sources (no AST, by design).
//
// Tracks strings, comments, bracket depth and triple-quoted strings across
// lines so detectors can reason about logical statements instead of physical
// lines. Never throws.
// ─────────────────────────────────────────────────────────────────────────────

export interface PythonLine {
  /** Line without its trailing comment (and without a trailing "\r"). */
  code: string;
  /** Net bracket depth change, ignoring brackets inside strings. */
  delta: number;
  /** True when the line starts inside a triple-quoted string (docstring body). */
  startsInString: boolean;
  /** True when the line ends inside an open triple-quoted string. */
  endsInString: boolean;
  /** True when the line ends with a backslash line continuation. */
  backslash: boolean;
  /** Leading whitespace width (tabs count as one column). */
  indent: number;
}

/** Tokenises one line, tracking triple-quoted strings across lines. */
function scanLine(
  line: string,
  tripleState: string | null,
): { line: PythonLine; state: string | null } {
  const startsInString = tripleState !== null;
  let state = tripleState;
  let quote: string | null = null;
  let delta = 0;
  let end = line.length;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (state) {
      if (ch === "\\") i++;
      else if (line.startsWith(state, i)) {
        state = null;
        i += 2;
      }
    } else if (quote) {
      if (ch === "\\") i++;
      else if (ch === quote) quote = null;
    } else if (line.startsWith('"""', i) || line.startsWith("'''", i)) {
      state = line.slice(i, i + 3);
      i += 2;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === "#") {
      end = i;
      break;
    } else if (ch === "(" || ch === "[" || ch === "{") {
      delta++;
    } else if (ch === ")" || ch === "]" || ch === "}") {
      delta--;
    }
  }
  const code = line.slice(0, end);
  return {
    line: {
      code,
      delta,
      startsInString,
      endsInString: state !== null,
      backslash: state === null && code.endsWith("\\"),
      indent: startsInString ? 0 : (/^[ \t]*/.exec(line)?.[0].length ?? 0),
    },
    state,
  };
}

/** Splits Python source into scanned physical lines (CRLF tolerant). */
export function scanPythonLines(content: string): PythonLine[] {
  const lines: PythonLine[] = [];
  let state: string | null = null;
  for (const raw of content.split("\n")) {
    const r = scanLine(raw.replace(/\r$/, ""), state);
    lines.push(r.line);
    state = r.state;
  }
  return lines;
}

export const MAX_STATEMENT_LINES = 40;

/**
 * Joins the logical statement starting at line `start`: bracketed continuation,
 * backslash continuation and multi-line triple-quoted strings are followed (up
 * to MAX_STATEMENT_LINES physical lines). Returns the joined text and the index
 * of its last physical line.
 */
export function joinStatement(lines: PythonLine[], start: number): { stmt: string; end: number } {
  const first = lines[start];
  if (!first) return { stmt: "", end: start };
  let stmt = first.code;
  let depth = first.delta;
  let prev = first;
  let end = start;
  for (
    let j = start + 1;
    (depth > 0 || prev.endsInString || prev.backslash) &&
    j < lines.length &&
    j - start < MAX_STATEMENT_LINES;
    j++
  ) {
    const next = lines[j]!;
    if (prev.backslash) stmt = stmt.slice(0, -1);
    // Inside a triple-quoted string keep the text as is; otherwise join with one space.
    stmt += prev.endsInString ? "\n" + next.code : " " + next.code.trim();
    depth += next.delta;
    prev = next;
    end = j;
  }
  return { stmt, end };
}

/** A logical statement: its first physical line (0-based), last line and joined text. */
export interface PythonStatement {
  start: number;
  end: number;
  indent: number;
  /** First physical line of code (comment stripped). */
  head: string;
  stmt: string;
}

/** Every logical statement in the file, skipping blank lines and comment-only lines. */
export function pythonStatements(lines: PythonLine[]): PythonStatement[] {
  const out: PythonStatement[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (line.startsInString || !line.code.trim()) continue;
    const { stmt, end } = joinStatement(lines, i);
    out.push({ start: i, end, indent: line.indent, head: line.code, stmt });
    i = end;
  }
  return out;
}

/** `settings.py`, `settings_prod.py`, or any module inside a `settings/` package. */
export function isSettingsFile(filePath: string): boolean {
  const parts = filePath.replace(/\\/g, "/").split("/");
  const fileName = parts.pop() ?? "";
  if (!fileName.endsWith(".py")) return false;
  return /^settings([_.-].*)?\.py$/i.test(fileName) || parts.includes("settings");
}

/** Settings modules that are clearly for local development or testing only. */
export function isDevOnlySettings(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, "/").toLowerCase();
  const stem = (normalized.split("/").pop() ?? "").replace(/\.py$/, "");
  return /(^|[_.-])(dev|local|development|test|testing)($|[_.-])/.test(stem);
}
