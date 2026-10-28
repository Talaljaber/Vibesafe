export interface StripCommentsOptions {
  /** Also blank the contents of string, template and regex literals (quotes and `${}` code are kept). */
  blankStrings?: boolean;
}

interface ScanResult {
  out: string;
  end: number;
}

const REGEX_PRECEDERS = "(,=:[!&|?{};+-*%<>~^";
const REGEX_KEYWORD_RE = /\b(?:return|typeof|case|void|delete|in|of|yield|await)\s*$/;

/** Longest keyword (`typeof`/`return`/`delete`/`yield`/`await`) plus generous whitespace; keeps the test O(1). */
const KEYWORD_TAIL = 32;

function blank(ch: string, on: boolean): string {
  return on && ch !== "\n" ? " " : ch;
}

function scanCode(
  s: string,
  start: number,
  inTemplateExpr: boolean,
  blankStrings: boolean,
): ScanResult {
  const n = s.length;
  let out = "";
  let i = start;
  let depth = 0;
  let lastSig = "";
  // Bounded tail of recent plain-code output (never slice `out`: that flattens the string each time).
  let tail = "";

  while (i < n) {
    const c = s[i] as string;
    const next = s[i + 1];

    if (c === "/" && next === "/") {
      while (i < n && s[i] !== "\n") {
        out += " ";
        i++;
      }
    } else if (c === "/" && next === "*") {
      out += "  ";
      i += 2;
      while (i < n && !(s[i] === "*" && s[i + 1] === "/")) {
        out += s[i] === "\n" ? "\n" : " ";
        i++;
      }
      if (i < n) {
        out += "  ";
        i += 2;
      }
    } else if (c === '"' || c === "'") {
      // Single/double quoted strings cannot span lines: stop at an unescaped newline.
      out += c;
      i++;
      while (i < n && s[i] !== c && s[i] !== "\n") {
        if (s[i] === "\\" && i + 1 < n && s[i + 1] !== "\n") {
          out += blank(s[i] as string, blankStrings);
          i++;
        }
        out += blank(s[i] as string, blankStrings);
        i++;
      }
      if (i < n && s[i] === c) {
        out += c;
        i++;
      }
      lastSig = c;
    } else if (c === "`") {
      out += c;
      i++;
      while (i < n && s[i] !== "`") {
        if (s[i] === "\\" && i + 1 < n) {
          out += blank(s[i] as string, blankStrings) + blank(s[i + 1] as string, blankStrings);
          i += 2;
        } else if (s[i] === "$" && s[i + 1] === "{") {
          out += "${";
          const r = scanCode(s, i + 2, true, blankStrings);
          out += r.out;
          i = r.end;
        } else {
          out += blank(s[i] as string, blankStrings);
          i++;
        }
      }
      if (i < n) {
        out += "`";
        i++;
      }
      lastSig = "`";
      tail = "";
    } else if (
      c === "/" &&
      (lastSig === "" || REGEX_PRECEDERS.includes(lastSig) || REGEX_KEYWORD_RE.test(tail))
    ) {
      // Regex literal (heuristic: a slash where an expression is expected). Never spans lines.
      out += c;
      i++;
      let inClass = false;
      while (i < n && s[i] !== "\n") {
        const ch = s[i] as string;
        if (ch === "\\" && i + 1 < n && s[i + 1] !== "\n") {
          out += blank(ch, blankStrings) + blank(s[i + 1] as string, blankStrings);
          i += 2;
          continue;
        }
        if (ch === "[") inClass = true;
        else if (ch === "]") inClass = false;
        else if (ch === "/" && !inClass) break;
        out += blank(ch, blankStrings);
        i++;
      }
      if (i < n && s[i] === "/") {
        out += "/";
        i++;
      }
      lastSig = "/";
      tail = "";
    } else {
      if (c === "{") depth++;
      else if (c === "}") {
        if (inTemplateExpr && depth === 0) return { out: out + "}", end: i + 1 };
        depth--;
      }
      out += c;
      if (!/\s/.test(c)) lastSig = c;
      tail = (tail + c).slice(-KEYWORD_TAIL);
      i++;
    }
  }
  return { out, end: i };
}

/**
 * Replace comments with whitespace (newlines kept so line numbers stay valid). String, template
 * and regex literal contents are left untouched unless `blankStrings` is set.
 *
 * This is a lightweight scanner, not a parser: regex literals are recognised heuristically (a `/`
 * where an expression is expected) and JSX text containing quotes can pair with a later quote on the
 * same line. In TSX, a `/` after `<` (e.g. `</div> // note`) is read as a regex start, so a trailing
 * comment on such a line may not be stripped. Quoted strings end at a newline so a stray apostrophe never swallows later lines.
 */
export function stripComments(source: string, options: StripCommentsOptions = {}): string {
  return scanCode(source, 0, false, options.blankStrings === true).out;
}
