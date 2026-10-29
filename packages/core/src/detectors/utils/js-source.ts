import type { ScanContext } from "@talaljaber/vibesafe-shared";

/**
 * Shared JS/TS source model for regex-based detectors.
 *
 * A {@link JsSource} pairs the original `text` with `code`: the same string (same length,
 * same newline offsets) with comments, string/regex literal contents, template text and,
 * in JSX mode, JSX text children and attribute strings blanked to spaces. Detectors match
 * on `code` (so words in comments and strings never count as code) and read the matching
 * `text` at the same offsets for evidence.
 */

// ---------------------------------------------------------------------------
// Line index
// ---------------------------------------------------------------------------

/** Offset/line lookups over a text. Lines are 1-indexed. */
export interface LineIndex {
  /** Number of lines (a text without newlines has 1). */
  readonly lineCount: number;
  /** 1-indexed line of a character offset (clamped to the text). */
  lineAt(offset: number): number;
  /** Offset of the first character of a 1-indexed line (clamped). */
  lineStart(line: number): number;
  /** Offset of the line's terminating `\n` (or the text length for the last line). */
  lineEnd(line: number): number;
}

/** Builds a {@link LineIndex} for `text` (one pass, binary-search lookups). */
export function createLineIndex(text: string): LineIndex {
  let count = 1;
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) count++;
  const starts = new Int32Array(count);
  let k = 1;
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts[k++] = i + 1;
  const clampLine = (line: number): number => Math.min(Math.max(1, Math.floor(line)), count);
  return {
    lineCount: count,
    lineAt(offset: number): number {
      if (offset <= 0) return 1;
      let lo = 0;
      let hi = count - 1;
      while (lo < hi) {
        const mid = (lo + hi + 1) >> 1;
        if (starts[mid]! <= offset) lo = mid;
        else hi = mid - 1;
      }
      return lo + 1;
    },
    lineStart(line: number): number {
      return starts[clampLine(line) - 1]!;
    },
    lineEnd(line: number): number {
      const l = clampLine(line);
      return l < count ? starts[l]! - 1 : text.length;
    },
  };
}

// ---------------------------------------------------------------------------
// Masking
// ---------------------------------------------------------------------------

/** Options for {@link maskCode} and {@link createJsSource}. */
export interface JsSourceOptions {
  /**
   * Recognise JSX: in expression position a `<` followed by an identifier or `>` opens an
   * element; its text children and attribute strings are blanked, `{}` containers stay code.
   */
  jsx?: boolean | undefined;
}

const REGEX_PREV_KEYWORD_RE =
  /\b(?:return|typeof|case|in|of|delete|void|throw|else|do|yield|await)\s*$/;
const REGEX_PREV_CHARS = "(,=:[!&|?{};+-*%<>~^";
/** Keywords after which a `<` starts a JSX element. */
const JSX_PREV_KEYWORD_RE = /\b(?:return|case|in|of|void|throw|else|do|yield|await|default)\s*$/;
/** Characters after which a `<` starts a JSX element (`<` itself is excluded: `a <<b`). */
const JSX_PREV_CHARS = "(,=:[!&|?{};+-*%>~^";
/** `<T,>` / `<T extends U>` generic parameter lists in `.tsx` are not elements. */
const TSX_GENERIC_RE = /^<\s*(?:const\s+)?[A-Za-z_$][\w$]*\s*(?:,|extends\b)/;
const IDENT_START_RE = /[A-Za-z_$]/;
const MAX_JSX_RETRIES = 8;

type Frame =
  | { k: "tmpl"; braces: number }
  | { k: "attr"; braces: number; root: number }
  | { k: "child"; braces: number; root: number }
  | { k: "elem"; root: number };

interface MaskResult {
  out: string;
  /** Offset of the outermost JSX element that never closed, or -1. */
  failedRoot: number;
}

function maskOnce(src: string, jsx: boolean, banned: ReadonlySet<number>): MaskResult {
  const out = src.split("");
  const n = src.length;
  const mask = (from: number, to: number): void => {
    for (let k = from; k < to && k < n; k++) if (out[k] !== "\n") out[k] = " ";
  };
  const frames: Frame[] = [];
  let braces = 0;
  let prevSig = "";
  let mode: "code" | "tmpl" | "tag" | "children" = "code";
  let root = -1;
  const fail = (at: number): MaskResult => {
    const bottom = frames.find((f) => f.k !== "tmpl");
    return { out: out.join(""), failedRoot: bottom && "root" in bottom ? bottom.root : at };
  };
  const endElement = (): void => {
    const top = frames[frames.length - 1];
    if (top?.k === "elem") {
      mode = "children";
      root = top.root;
    } else {
      mode = "code";
      prevSig = ")";
    }
  };

  let i = 0;
  while (i < n) {
    const c = src[i]!;
    if (mode === "tmpl") {
      if (c === "\\") {
        mask(i, i + 2);
        i += 2;
      } else if (c === "`") {
        prevSig = "`";
        mode = "code";
        i++;
      } else if (c === "$" && src[i + 1] === "{") {
        frames.push({ k: "tmpl", braces });
        braces++;
        prevSig = "{";
        mode = "code";
        i += 2;
      } else {
        mask(i, i + 1);
        i++;
      }
      continue;
    }

    if (mode === "tag") {
      if (c === "/" && src[i + 1] === ">") {
        i += 2;
        endElement();
      } else if (c === ">") {
        frames.push({ k: "elem", root });
        mode = "children";
        i++;
      } else if (c === "{") {
        frames.push({ k: "attr", braces, root });
        braces++;
        prevSig = "{";
        mode = "code";
        i++;
      } else if (c === '"' || c === "'") {
        const j = src.indexOf(c, i + 1);
        if (j === -1) return fail(root);
        mask(i + 1, j);
        i = j + 1;
      } else {
        i++;
      }
      continue;
    }

    if (mode === "children") {
      if (c === "{") {
        frames.push({ k: "child", braces, root });
        braces++;
        prevSig = "{";
        mode = "code";
        i++;
      } else if (c === "<") {
        let j = i + 1;
        while (j < n && (src[j] === " " || src[j] === "\t" || src[j] === "\n" || src[j] === "\r"))
          j++;
        if (src[j] === "/") {
          const close = src.indexOf(">", j);
          if (close === -1) return fail(root);
          i = close + 1;
          frames.pop();
          endElement();
        } else if (src[j] === ">" || IDENT_START_RE.test(src[j] ?? "")) {
          mode = "tag";
          i++;
        } else {
          mask(i, i + 1);
          i++;
        }
      } else {
        mask(i, i + 1);
        i++;
      }
      continue;
    }

    // mode === "code"
    if (c === "/" && src[i + 1] === "/") {
      let e = src.indexOf("\n", i);
      if (e === -1) e = n;
      mask(i, e);
      i = e;
    } else if (c === "/" && src[i + 1] === "*") {
      const e = src.indexOf("*/", i + 2);
      const end = e === -1 ? n : e + 2;
      mask(i, end);
      i = end;
    } else if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < n && src[j] !== c && src[j] !== "\n") j += src[j] === "\\" ? 2 : 1;
      mask(i + 1, j);
      i = Math.min(j + 1, n);
      prevSig = c;
    } else if (c === "`") {
      mode = "tmpl";
      i++;
    } else if (c === "/") {
      const regexOk =
        prevSig === "" ||
        REGEX_PREV_CHARS.includes(prevSig) ||
        (/[\w$]/.test(prevSig) && REGEX_PREV_KEYWORD_RE.test(src.slice(Math.max(0, i - 12), i)));
      let j = i + 1;
      let ok = false;
      if (regexOk) {
        let inClass = false;
        for (; j < n && src[j] !== "\n"; j++) {
          const d = src[j]!;
          if (d === "\\") j++;
          else if (d === "[") inClass = true;
          else if (d === "]") inClass = false;
          else if (d === "/" && !inClass) {
            ok = true;
            break;
          }
        }
      }
      if (ok) {
        mask(i + 1, j);
        i = j + 1;
        while (i < n && /[a-z]/i.test(src[i]!)) i++; // flags
        prevSig = ")";
      } else {
        prevSig = "/";
        i++;
      }
    } else if (
      jsx &&
      c === "<" &&
      !banned.has(i) &&
      (src[i + 1] === ">" || IDENT_START_RE.test(src[i + 1] ?? "")) &&
      (prevSig === "" ||
        JSX_PREV_CHARS.includes(prevSig) ||
        (/[\w$]/.test(prevSig) && JSX_PREV_KEYWORD_RE.test(src.slice(Math.max(0, i - 12), i)))) &&
      !TSX_GENERIC_RE.test(src.slice(i, i + 80))
    ) {
      root = i;
      mode = "tag";
      i++;
    } else {
      if (c === "{") braces++;
      else if (c === "}") {
        braces--;
        const top = frames[frames.length - 1];
        if (top !== undefined && top.k !== "elem" && top.braces === braces) {
          frames.pop();
          i++;
          if (top.k === "tmpl") mode = "tmpl";
          else {
            root = top.root;
            mode = top.k === "attr" ? "tag" : "children";
          }
          continue;
        }
      }
      if (!/\s/.test(c)) prevSig = c;
      i++;
    }
  }
  if (mode === "tag" || mode === "children" || frames.some((f) => f.k !== "tmpl"))
    return fail(root);
  return { out: out.join(""), failedRoot: -1 };
}

/**
 * Returns `src` with comments, string literals, regex literals and template text
 * replaced by spaces (newlines and `${}` expressions are kept, so offsets and line
 * numbers are unchanged). Heuristic: regex-vs-division is decided from the previous token.
 *
 * With `{ jsx: true }`, JSX text children and attribute strings are blanked too (an
 * apostrophe or `//` in JSX text is not a string or comment), while `{}` containers stay
 * code. A `<` that cannot be closed as an element (e.g. a `.tsx` generic) is retried as an
 * operator; if JSX still cannot be balanced the non-JSX masking is returned.
 */
export function maskCode(src: string, options?: JsSourceOptions | undefined): string {
  if (options?.jsx !== true) return maskOnce(src, false, new Set()).out;
  const banned = new Set<number>();
  for (let attempt = 0; attempt <= MAX_JSX_RETRIES; attempt++) {
    const r = maskOnce(src, true, banned);
    if (r.failedRoot === -1) return r.out;
    if (banned.has(r.failedRoot) || r.failedRoot >= src.length) break;
    banned.add(r.failedRoot);
  }
  return maskOnce(src, false, new Set()).out;
}

// ---------------------------------------------------------------------------
// Brackets
// ---------------------------------------------------------------------------

const OPEN_OF: Readonly<Record<string, string>> = { ")": "(", "]": "[", "}": "{" };

/** Bracket partner map over masked code: partner offset, or -1 (not a bracket / unbalanced). */
function buildBracketMap(code: string): Int32Array {
  const map = new Int32Array(code.length).fill(-1);
  const stack: number[] = [];
  for (let i = 0; i < code.length; i++) {
    const c = code[i]!;
    if (c === "(" || c === "[" || c === "{") stack.push(i);
    else if (c === ")" || c === "]" || c === "}") {
      const top = stack[stack.length - 1];
      if (top !== undefined && code[top] === OPEN_OF[c]) {
        stack.pop();
        map[top] = i;
        map[i] = top;
      }
    }
  }
  return map;
}

/**
 * Offset of the bracket matching the `(`, `[` or `{` at `openIndex` (bracket kinds must
 * nest correctly), or -1 when `openIndex` is not an opening bracket in code or it never
 * closes. `text` is masked first unless the already-masked `code` is passed.
 */
export function findMatchingBrace(
  text: string,
  openIndex: number,
  code?: string | undefined,
): number {
  const masked = code ?? maskCode(text);
  const open = masked[openIndex];
  if (open !== "(" && open !== "[" && open !== "{") return -1;
  const stack: string[] = [];
  for (let i = openIndex; i < masked.length; i++) {
    const c = masked[i]!;
    if (c === "(" || c === "[" || c === "{") stack.push(c);
    else if (c === ")" || c === "]" || c === "}") {
      if (stack.pop() !== OPEN_OF[c]) return -1;
      if (stack.length === 0) return i;
    }
  }
  return -1;
}

// ---------------------------------------------------------------------------
// JsSource
// ---------------------------------------------------------------------------

/** A JS/TS file prepared for regex analysis (see the module comment). */
export interface JsSource {
  /** Relative path when built by {@link getJsSource}. */
  readonly file: string | undefined;
  /** Original text. */
  readonly text: string;
  /** Masked text: same length and newline offsets as `text`. */
  readonly code: string;
  /** Whether JSX was recognised while masking. */
  readonly jsx: boolean;
  /** Line lookups. */
  readonly lines: LineIndex;
  /** 1-indexed line of an offset. */
  lineAt(offset: number): number;
  /** Raw text of a 1-indexed line, without its line terminator. */
  lineText(line: number): string;
  /** Partner of the bracket at `offset` (either side), or -1 (not a bracket / unbalanced). */
  matchOf(offset: number): number;
}

/** True for paths whose code may contain JSX: `.jsx`, `.tsx` and plain JS (`.js .mjs .cjs`). */
export function isJsxPath(relativePath: string): boolean {
  return /\.(?:[jt]sx|[cm]?js)$/i.test(relativePath);
}

/**
 * Builds a {@link JsSource}. JSX is opt-in: pass `{ jsx: true }` for `.tsx`/`.jsx` (and
 * plain `.js`, where a `<` in expression position can only start JSX); `.ts` must not use
 * it because `<T>expr` is a type assertion there.
 */
export function createJsSource(
  text: string,
  options?: (JsSourceOptions & { file?: string | undefined }) | undefined,
): JsSource {
  const jsx = options?.jsx === true;
  const code = maskCode(text, { jsx });
  const lines = createLineIndex(text);
  let brackets: Int32Array | undefined;
  return {
    file: options?.file,
    text,
    code,
    jsx,
    lines,
    lineAt: (offset) => lines.lineAt(offset),
    lineText: (line) => text.slice(lines.lineStart(line), lines.lineEnd(line)).replace(/\r$/, ""),
    matchOf(offset: number): number {
      if (offset < 0 || offset >= code.length) return -1;
      brackets ??= buildBracketMap(code);
      return brackets[offset]!;
    },
  };
}

const SOURCE_CACHE = new WeakMap<ScanContext, Map<string, Promise<JsSource>>>();

/**
 * The {@link JsSource} of `file`, read via `context.readFile` and cached per scan context
 * (JSX mode follows {@link isJsxPath}). Never rejects: a failed read yields an empty source.
 */
export function getJsSource(context: ScanContext, file: string): Promise<JsSource> {
  let perContext = SOURCE_CACHE.get(context);
  if (perContext === undefined) {
    perContext = new Map();
    SOURCE_CACHE.set(context, perContext);
  }
  let cached = perContext.get(file);
  if (cached === undefined) {
    cached = context
      .readFile(file)
      .catch(() => "")
      .then((text) => createJsSource(text, { jsx: isJsxPath(file), file }));
    perContext.set(file, cached);
  }
  return cached;
}

/** 1-indexed line of `offset` in `src`. */
export function lineAt(src: JsSource, offset: number): number {
  return src.lineAt(offset);
}

/** Raw text of a 1-indexed line of `src`, without its terminator. */
export function lineText(src: JsSource, line: number): string {
  return src.lineText(line);
}

/** Partner of the bracket at `offset` in `src.code`, or -1. */
export function matchOf(src: JsSource, offset: number): number {
  return src.matchOf(offset);
}
