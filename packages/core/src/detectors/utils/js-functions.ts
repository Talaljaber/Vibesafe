import type { FileClassification, FileKind } from "./file-kind.js";
import type { JsSource } from "./js-source.js";
import { extractExpressRoutes, splitTopLevel } from "./route-analyzer.js";

/**
 * Function spans over a {@link JsSource}: every `function`, arrow function and
 * object/class method, with its parameters, body range, export name, wrapper calls
 * (`withAuth(async (req) => ...)`) and, given the file kind, its role (App Router
 * handler, Pages API handler, Express handler, server action, middleware, page).
 *
 * Regex/bracket based, no AST: spans come from `src.code` (comments and strings blanked)
 * and the lazy bracket map. A body whose braces never close is marked `truncated` and
 * runs to the end of the file; detectors cap confidence at `medium` on such spans.
 */

/** `module` is the synthetic whole-file span from {@link moduleSpan}. */
export type FunctionKind = "function" | "arrow" | "method" | "module";

/**
 * - `app-route-handler`: exported `GET`/`POST`/... in an App Router `route.*` file.
 * - `pages-api-handler`: default export of a `pages/api/**` file.
 * - `express-handler`: final handler of an `app|router.<method>("/path", ...)` route.
 * - `express-middleware`: inline function before the final handler of such a route.
 * - `server-action`: exported function of a `"use server"` file, or a function whose body
 *   starts with `"use server"`.
 * - `middleware`: exported `middleware`/`proxy`/default function of a Next middleware file.
 * - `page`: default export of an App Router page/layout (server component) or a Pages
 *   Router `getServerSideProps`.
 */
export type FunctionRole =
  | "app-route-handler"
  | "pages-api-handler"
  | "express-handler"
  | "express-middleware"
  | "server-action"
  | "middleware"
  | "page"
  | "other";

/** One declared parameter. */
export interface FunctionParam {
  /** Raw parameter text (annotation and default included), trimmed. */
  text: string;
  /** File offsets of `text`. */
  start: number;
  end: number;
  /** Binding pattern without annotation or default, from `code` (`req`, `{ params }`). */
  pattern: string;
  /** Names the parameter binds (`["req"]`, `["id", "body"]` for `{ id, body }`). */
  names: string[];
}

export interface FunctionSpan {
  /** Declared name, the binding/property it is assigned to, or undefined. */
  name: string | undefined;
  kind: FunctionKind;
  async: boolean;
  /** Offset of the first character (`async`, `function`, the method name or the arrow params). */
  start: number;
  /** Offset just past the body. */
  end: number;
  /** Offset of `(` (or of a bare arrow parameter) and just past `)` (or the parameter). */
  paramsStart: number;
  paramsEnd: number;
  params: FunctionParam[];
  /** Offset of the body `{` (or the first character of an expression body) and just past it. */
  bodyStart: number;
  bodyEnd: number;
  /** Arrow function whose body is an expression, not a block. */
  expressionBody: boolean;
  startLine: number;
  endLine: number;
  /** Exported via `export`, `export default`, `export { x }` or `module.exports`. */
  exported: boolean;
  /** `"default"` or the (first) exported name, when exported. */
  exportName: string | undefined;
  /** Every name the function is exported under (`export { handler as GET, handler as POST }`). */
  exportNames: string[];
  /** Calls wrapping the function in its binding, outermost first (`["withAuth"]`). */
  wrappers: string[];
  role: FunctionRole;
  /** Upper-cased HTTP method for App Router (`POST`) and Express (`POST`, `ALL`) handlers. */
  httpMethod: string | undefined;
  /** The body braces never close; the span runs to the end of the file. */
  truncated: boolean;
  /** Innermost enclosing function, if any. */
  parent: FunctionSpan | undefined;
}

const HTTP_METHODS = new Set(["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]);
const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const HANDLER_ROLES: ReadonlySet<FunctionRole> = new Set<FunctionRole>([
  "app-route-handler",
  "pages-api-handler",
  "express-handler",
  "server-action",
  "middleware",
  "page",
]);
const NOT_A_METHOD = new Set([
  "if",
  "for",
  "while",
  "switch",
  "catch",
  "function",
  "return",
  "typeof",
  "with",
  "do",
  "else",
  "new",
  "await",
  "yield",
  "void",
  "delete",
  "in",
  "of",
  "instanceof",
  "throw",
  "case",
  "import",
  "export",
  "super",
  "this",
]);
const MODIFIER_RE =
  /^(?:async|static|get|set|public|private|protected|readonly|override|abstract|declare)$/;
const TYPE_PREFIX_WORDS = new Set([
  "typeof",
  "keyof",
  "readonly",
  "infer",
  "unique",
  "new",
  "asserts",
  "abstract",
]);
const TYPE_CONTINUE_WORDS = new Set(["is", "extends", "as", "keyof"]);
const IDENT_CHAR_RE = /[\w$]/;
const WINDOW = 4000;

function isWs(c: string | undefined): boolean {
  return c === " " || c === "\t" || c === "\n" || c === "\r";
}

function nextNonWs(code: string, i: number): number {
  while (i < code.length && isWs(code[i])) i++;
  return i;
}

function prevNonWs(code: string, i: number): number {
  while (i >= 0 && isWs(code[i])) i--;
  return i;
}

/** Start offset of the identifier ending at `end` (inclusive), or `end + 1` when none. */
function identStartBack(code: string, end: number): number {
  let i = end;
  while (i >= 0 && IDENT_CHAR_RE.test(code[i]!)) i--;
  return i + 1;
}

function readIdent(code: string, i: number): string {
  const m = /^[A-Za-z_$][\w$]*/.exec(code.slice(i, i + 200));
  return m ? m[0] : "";
}

/** Skips a balanced `<...>` starting at `i` (`code[i] === "<"`); returns the offset after `>` or -1. */
function skipAngle(src: JsSource, i: number): number {
  const code = src.code;
  let depth = 0;
  const limit = Math.min(code.length, i + WINDOW);
  for (let j = i; j < limit; j++) {
    const c = code[j]!;
    if (c === "<") depth++;
    else if (c === ">" && code[j - 1] !== "=") {
      depth--;
      if (depth === 0) return j + 1;
    } else if (c === "(" || c === "[" || c === "{") {
      const m = src.matchOf(j);
      if (m < 0) return -1;
      j = m;
    } else if (c === ";" || c === ")" || c === "]" || c === "}") return -1;
  }
  return -1;
}

/** Skips back over a balanced `<...>` whose `>` is at `j`; returns the offset of `<` or -1. */
function skipAngleBack(code: string, j: number): number {
  let depth = 0;
  const limit = Math.max(0, j - WINDOW);
  for (let k = j; k >= limit; k--) {
    const c = code[k]!;
    if (c === ">" && code[k - 1] !== "=") depth++;
    else if (c === "<") {
      depth--;
      if (depth === 0) return k;
    } else if (c === ";" || c === "{" || c === "}") return -1;
  }
  return -1;
}

/**
 * Skips a TypeScript type starting at `i` (just after a `:`); returns the offset of the
 * first character after the type (where `{`, `=`, `,`, `)` or `;` is expected).
 */
export function skipTypeForward(src: JsSource, i: number): number {
  const code = src.code;
  let expect = true;
  let j = i;
  const limit = Math.min(code.length, i + WINDOW);
  while (j < limit) {
    const c = code[j]!;
    if (isWs(c)) {
      j++;
      continue;
    }
    if (expect) {
      if (c === "(" || c === "[" || c === "{") {
        const m = src.matchOf(j);
        if (m < 0) return j;
        j = m + 1;
        expect = false;
      } else if (c === "<") {
        const e = skipAngle(src, j);
        if (e < 0) return j;
        j = e;
      } else if (c === '"' || c === "'" || c === "`") {
        const e = code.indexOf(c, j + 1);
        if (e < 0) return j;
        j = e + 1;
        expect = false;
      } else if (/[\w$-]/.test(c)) {
        const word = /^-?[\w$]+/.exec(code.slice(j, j + 200))![0];
        j += word.length;
        if (!TYPE_PREFIX_WORDS.has(word)) expect = false;
      } else if (c === "|" || c === "&") {
        j++;
      } else return j;
      continue;
    }
    if (c === "." || c === "|" || c === "&" || c === "?" || c === ":") {
      j++;
      expect = true;
    } else if (c === "<") {
      const e = skipAngle(src, j);
      if (e < 0) return j;
      j = e;
    } else if (c === "[") {
      const m = src.matchOf(j);
      if (m < 0) return j;
      j = m + 1;
    } else if (c === "=" && code[j + 1] === ">") {
      j += 2;
      expect = true;
    } else if (/[A-Za-z_$]/.test(c)) {
      const word = readIdent(code, j);
      if (!TYPE_CONTINUE_WORDS.has(word)) return j;
      j += word.length;
      expect = true;
    } else return j;
  }
  return j;
}

function isTerminatorAfterNewline(code: string, prev: number, next: number): boolean {
  const p = code[prev];
  const n = code[next];
  if (p === undefined || n === undefined) return true;
  if ("=+-*/%&|^!?:<>,.([{~".includes(p)) return false;
  if (".?:+-*/%&|^=<>)]},;".includes(n)) return false;
  if (/^(?:as|satisfies|instanceof|in)\b/.test(code.slice(next, next + 12))) return false;
  return true;
}

/** Offset of the template literal's closing backtick (`code[i]` is the opening one), or -1. */
function skipTemplateLiteral(src: JsSource, i: number): number {
  const code = src.code;
  for (let j = i + 1; j < code.length; j++) {
    const c = code[j]!;
    if (c === "`") return j;
    if (c === "$" && code[j + 1] === "{") {
      const m = src.matchOf(j + 1);
      if (m < 0) return -1;
      j = m;
    }
  }
  return -1;
}

/**
 * End (exclusive, trailing whitespace trimmed) of the expression starting at `start`:
 * stops at a top-level `,` or `;`, an unmatched closing bracket, or a newline that ends
 * the statement (ASI heuristic: the line does not end with an operator and the next line
 * does not start with one). Never goes past `limit`.
 */
export function expressionEnd(src: JsSource, start: number, limit?: number | undefined): number {
  const code = src.code;
  const lim = Math.min(limit ?? code.length, code.length);
  let i = start;
  let lastSig = -1;
  let ternary = 0;
  while (i < lim) {
    const c = code[i]!;
    if (c === "?" && code[i + 1] !== "." && code[i + 1] !== "?" && code[i - 1] !== "?") ternary++;
    else if (c === ":") {
      if (ternary === 0) break;
      ternary--;
    }
    if (c === "(" || c === "[" || c === "{") {
      const m = src.matchOf(i);
      if (m < 0 || m >= lim) return lim;
      lastSig = m;
      i = m + 1;
      continue;
    }
    if (c === "`") {
      const e = skipTemplateLiteral(src, i);
      if (e < 0 || e >= lim) return lim;
      lastSig = e;
      i = e + 1;
      continue;
    }
    if (c === ")" || c === "]" || c === "}" || c === ";" || c === ",") break;
    if (c === "\n" && lastSig >= 0) {
      const next = nextNonWs(code, i);
      if (next >= lim) break;
      if (isTerminatorAfterNewline(code, lastSig, next)) break;
    }
    if (!isWs(c)) lastSig = i;
    i++;
  }
  return lastSig >= start ? lastSig + 1 : start;
}

/** Offset of the innermost unmatched opening bracket before `pos`, or -1 (bounded window). */
export function enclosingOpen(src: JsSource, pos: number): number {
  const code = src.code;
  const limit = Math.max(0, pos - WINDOW);
  for (let i = pos - 1; i >= limit; i--) {
    const c = code[i]!;
    if (c === ")" || c === "]" || c === "}") {
      const m = src.matchOf(i);
      if (m < 0) return -1;
      i = m;
    } else if (c === "(" || c === "[" || c === "{") return i;
  }
  return -1;
}

/** Index of `ch` at nesting depth 0 of masked `s`, ignoring `=>`, `==`, `<=`, `>=`, `!=`. */
function topLevelIndexOf(s: string, ch: string): number {
  let depth = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") depth--;
    else if (depth === 0 && c === ch) {
      if (ch === "=" && (s[i + 1] === ">" || s[i + 1] === "=" || "<>!=".includes(s[i - 1] ?? "")))
        continue;
      return i;
    }
  }
  return -1;
}

/** End (inclusive) of the group opened at `s[0]` in masked `s`, or -1. */
function groupEnd(s: string): number {
  let depth = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/**
 * Names bound by a destructuring pattern or identifier, from masked code:
 * `{ id, body: payload, ...rest }` gives `["id", "payload", "rest"]`; defaults are dropped.
 */
export function patternBindings(pattern: string): string[] {
  const p = pattern.trim();
  if (p.startsWith("...")) return patternBindings(p.slice(3));
  if (p.startsWith("{") || p.startsWith("[")) {
    const end = groupEnd(p);
    const inner = p.slice(1, end < 0 ? p.length : end);
    const out: string[] = [];
    for (const raw of splitTopLevel(inner)) {
      const el = raw.trim();
      if (el === "") continue;
      if (el.startsWith("...")) {
        out.push(...patternBindings(el.slice(3)));
        continue;
      }
      if (p.startsWith("{")) {
        const colon = topLevelIndexOf(el, ":");
        const eq = topLevelIndexOf(el, "=");
        if (colon >= 0 && (eq < 0 || colon < eq)) {
          out.push(...patternBindings(el.slice(colon + 1)));
          continue;
        }
        const name = readIdent(eq >= 0 ? el.slice(0, eq).trim() : el, 0);
        if (name) out.push(name);
      } else {
        const eq = topLevelIndexOf(el, "=");
        out.push(...patternBindings(eq >= 0 ? el.slice(0, eq) : el));
      }
    }
    return out;
  }
  const name = readIdent(p, 0);
  return name && name !== "this" ? [name] : [];
}

function parseParams(src: JsSource, open: number, close: number): FunctionParam[] {
  const inner = src.code.slice(open + 1, close);
  const params: FunctionParam[] = [];
  let offset = open + 1;
  for (const part of splitTopLevel(inner)) {
    const lead = part.length - part.trimStart().length;
    let body = part.trim();
    const start = offset + lead;
    offset += part.length + 1;
    if (body === "") continue;
    body = body.replace(/^(?:@[\w$.]+(?:\([^)]*\))?\s*)+/, "");
    body = body.replace(/^(?:(?:public|private|protected|readonly|override)\s+)+/, "");
    let pattern: string;
    if (body.startsWith("...")) body = body.slice(3).trimStart();
    if (body.startsWith("{") || body.startsWith("[")) {
      const end = groupEnd(body);
      pattern = end < 0 ? body : body.slice(0, end + 1);
    } else {
      pattern = readIdent(body, 0);
    }
    if (pattern === "" || pattern === "this") continue;
    const end = start + part.trim().length;
    params.push({
      text: src.text.slice(start, end),
      start,
      end,
      pattern,
      names: patternBindings(pattern),
    });
  }
  return params;
}

interface RawSpan {
  kind: FunctionKind;
  start: number;
  name: string | undefined;
  async: boolean;
  paramsStart: number;
  paramsEnd: number;
  params: FunctionParam[];
  bodyStart: number;
  bodyEnd: number;
  expressionBody: boolean;
  truncated: boolean;
}

/** Body after the `)` at `close`: optional return type, then `{`. Returns `[{, }]` or undefined. */
function blockBodyAfter(
  src: JsSource,
  close: number,
): { open: number; end: number; truncated: boolean } | undefined {
  const code = src.code;
  let j = nextNonWs(code, close + 1);
  if (code[j] === ":") j = nextNonWs(code, skipTypeForward(src, j + 1));
  if (code[j] !== "{") return undefined;
  const m = src.matchOf(j);
  return m < 0
    ? { open: j, end: code.length, truncated: true }
    : { open: j, end: m + 1, truncated: false };
}

function findFunctionKeywords(src: JsSource, out: RawSpan[]): void {
  const code = src.code;
  const re = /\bfunction\b/g;
  for (let m = re.exec(code); m !== null; m = re.exec(code)) {
    const at = m.index;
    const before = code[at - 1];
    if (before === "." || before === "$") continue;
    let j = nextNonWs(code, at + 8);
    if (code[j] === "*") j = nextNonWs(code, j + 1);
    const name = readIdent(code, j);
    if (name) j = nextNonWs(code, j + name.length);
    if (code[j] === "<") {
      const e = skipAngle(src, j);
      if (e < 0) continue;
      j = nextNonWs(code, e);
    }
    if (code[j] !== "(") continue;
    const close = src.matchOf(j);
    if (close < 0) continue;
    const body = blockBodyAfter(src, close);
    if (!body) continue;
    const asyncAt = asyncBefore(code, at);
    out.push({
      kind: "function",
      start: asyncAt ?? at,
      name: name || undefined,
      async: asyncAt !== undefined,
      paramsStart: j,
      paramsEnd: close + 1,
      params: parseParams(src, j, close),
      bodyStart: body.open,
      bodyEnd: body.end,
      expressionBody: false,
      truncated: body.truncated,
    });
  }
}

function asyncBefore(code: string, at: number): number | undefined {
  const p = prevNonWs(code, at - 1);
  if (p < 4) return undefined;
  const s = identStartBack(code, p);
  return code.slice(s, p + 1) === "async" && code[s - 1] !== "." ? s : undefined;
}

/** Back from `j` over a type expression; returns the offset of the first non-type char or -1. */
function skipTypeBack(src: JsSource, j: number): number {
  const code = src.code;
  const limit = Math.max(0, j - 400);
  while (j >= limit) {
    const c = code[j]!;
    if (isWs(c)) j--;
    else if (c === ")" || c === "]" || c === "}") {
      const o = src.matchOf(j);
      if (o < 0) return -1;
      j = o - 1;
    } else if (c === ">" && code[j - 1] !== "=") {
      const o = skipAngleBack(code, j);
      if (o < 0) return -1;
      j = o - 1;
    } else if (/[\w$.|&?"'`]/.test(c)) j--;
    else return j;
  }
  return -1;
}

/** `{` at `open` opens a type literal, interface or class body (not an object literal). */
function isTypeBrace(src: JsSource, open: number, depth: number): boolean {
  const code = src.code;
  const before = code.slice(Math.max(0, open - 300), open);
  if (/\binterface\s+[\w$]+(?:\s*<[^{}]*>)?(?:\s+extends\s+[^{};]+)?\s*$/.test(before)) return true;
  if (/\btype\s+[\w$]+(?:\s*<[^=;]*>)?\s*=\s*$/.test(before)) return true;
  if (/\bclass\b[^{};=]*$/.test(before)) return true;
  const p = prevNonWs(code, open - 1);
  const c = code[p];
  if (c === "<" || c === "|" || c === "&") return true;
  if (c === ":") return depth < 3 && isTypeColon(src, p, depth + 1);
  return false;
}

/** `:` at `colon` starts a type annotation (not an object property value or ternary branch). */
function isTypeColon(src: JsSource, colon: number, depth = 0): boolean {
  const code = src.code;
  const p = prevNonWs(code, colon - 1);
  if (p < 0) return false;
  if (code[p] === ")") return true; // return type annotation
  const encl = enclosingOpen(src, colon);
  if (encl < 0) {
    // statement level: `const f: T` (a ternary `a ? b : c` is not an annotation)
    return /\b(?:const|let|var|declare)\s+[A-Za-z_$][\w$]*\s*[!?]?\s*$/.test(
      code.slice(Math.max(0, colon - 200), colon),
    );
  }
  const kind = code[encl];
  if (kind === "(") {
    // parameter annotation, unless a ternary `?` sits between the opener and the colon
    const between = code.slice(encl + 1, colon);
    return !/\?(?![.:?])/.test(between.replace(/\?\s*:/g, ""));
  }
  if (kind === "{") return isTypeBrace(src, encl, depth);
  return false;
}

/** The `=>` at `arrow` belongs to a function type (`(x: number) => void`), not a function. */
function isTypeArrow(src: JsSource, paramsStart: number): boolean {
  const code = src.code;
  let p = prevNonWs(code, paramsStart - 1);
  if (p >= 0 && code[p] === ">" && code[p - 1] !== "=") {
    const o = skipAngleBack(code, p);
    if (o >= 0) p = prevNonWs(code, o - 1);
  }
  if (p < 0) return false;
  const c = code[p]!;
  if (c === "<" || c === "|" || c === "&") return true;
  if (c === ":") return isTypeColon(src, p);
  if (c === "=" && code[p - 1] !== "=" && code[p - 1] !== "!") {
    const before = code.slice(Math.max(0, p - 200), p);
    return /\btype\s+[\w$]+(?:\s*<[^=;]*>)?\s*$/.test(before);
  }
  return false;
}

function findArrows(src: JsSource, out: RawSpan[]): void {
  const code = src.code;
  const re = /=>/g;
  for (let m = re.exec(code); m !== null; m = re.exec(code)) {
    const k = m.index;
    const j = prevNonWs(code, k - 1);
    if (j < 0) continue;
    let pStart = -1;
    let pEnd = -1;
    let bare = false;
    const stop = skipTypeBack(src, j);
    const colonPrev = stop >= 0 && code[stop] === ":" ? prevNonWs(code, stop - 1) : -1;
    if (colonPrev >= 0 && code[colonPrev] === ")") {
      // `(params): ReturnType =>`
      const o = src.matchOf(colonPrev);
      if (o < 0) continue;
      pStart = o;
      pEnd = colonPrev + 1;
    } else if (code[j] === ")") {
      const o = src.matchOf(j);
      if (o < 0) continue;
      pStart = o;
      pEnd = j + 1;
    } else if (IDENT_CHAR_RE.test(code[j]!)) {
      pStart = identStartBack(code, j);
      pEnd = j + 1;
      bare = true;
      if (code[pStart - 1] === ".") continue;
    } else continue;

    // `foo(a) => x` is not valid JS; the group must not be a call's argument list.
    if (!bare) {
      const before = prevNonWs(code, pStart - 1);
      const s = identStartBack(code, before);
      if (s <= before && code[before] !== undefined && IDENT_CHAR_RE.test(code[before]!)) {
        const word = code.slice(s, before + 1);
        if (
          !/^(?:async|return|yield|await|case|in|of|typeof|void|delete|default|else|throw|do|extends)$/.test(
            word,
          )
        )
          continue;
      }
    }
    if (isTypeArrow(src, pStart)) continue;

    const asyncAt = asyncBefore(code, pStart);
    const bodyAt = nextNonWs(code, k + 2);
    let bodyEnd: number;
    let truncated = false;
    let expressionBody = false;
    if (code[bodyAt] === "{") {
      const close = src.matchOf(bodyAt);
      if (close < 0) {
        bodyEnd = code.length;
        truncated = true;
      } else bodyEnd = close + 1;
    } else {
      expressionBody = true;
      bodyEnd = expressionEnd(src, bodyAt);
    }
    const params = bare
      ? [
          {
            text: src.text.slice(pStart, pEnd),
            start: pStart,
            end: pEnd,
            pattern: code.slice(pStart, pEnd),
            names: [code.slice(pStart, pEnd)],
          },
        ]
      : parseParams(src, pStart, pEnd - 1);
    out.push({
      kind: "arrow",
      start: asyncAt ?? pStart,
      name: undefined,
      async: asyncAt !== undefined,
      paramsStart: pStart,
      paramsEnd: pEnd,
      params,
      bodyStart: bodyAt,
      bodyEnd,
      expressionBody,
      truncated,
    });
  }
}

function findMethods(src: JsSource, out: RawSpan[]): void {
  const code = src.code;
  const re =
    /(?:^|[{};,*])[ \t]*((?:(?:async|static|get|set|public|private|protected|readonly|override)[ \t]+)*)\*?[ \t]*([A-Za-z_$][\w$]*)[ \t]*(?:<[^<>\n]{0,120}>)?[ \t]*\(/gm;
  for (let m = re.exec(code); m !== null; m = re.exec(code)) {
    const name = m[2]!;
    const open = m.index + m[0].length - 1;
    re.lastIndex = open;
    if (NOT_A_METHOD.has(name) || MODIFIER_RE.test(name)) continue;
    const close = src.matchOf(open);
    if (close < 0) continue;
    const body = blockBodyAfter(src, close);
    if (!body) continue;
    const mods = m[1] ?? "";
    const modsAt = mods ? m[0].indexOf(mods) : 0;
    const nameAt = m.index + m[0].indexOf(name, modsAt + mods.length);
    out.push({
      kind: "method",
      start: mods ? m.index + modsAt : nameAt,
      name,
      async: /\basync\b/.test(mods),
      paramsStart: open,
      paramsEnd: close + 1,
      params: parseParams(src, open, close),
      bodyStart: body.open,
      bodyEnd: body.end,
      expressionBody: false,
      truncated: body.truncated,
    });
  }
}

interface Binding {
  name: string | undefined;
  exported: boolean;
  exportName: string | undefined;
  wrappers: string[];
}

/**
 * Callee text (`withAuth`, `auth.protect`) ending just before the `(` at `open`, with its
 * start offset; undefined for grouping parentheses and keywords such as `if (`.
 */
export function calleeBefore(
  code: string,
  open: number,
): { name: string; start: number } | undefined {
  const e = prevNonWs(code, open - 1);
  if (e < 0) return undefined;
  let s = e;
  while (s >= 0 && /[\w$.]/.test(code[s]!)) s--;
  const name = code.slice(s + 1, e + 1).replace(/^\.+/, "");
  if (!name || !/^[A-Za-z_$]/.test(name) || NOT_A_METHOD.has(name)) return undefined;
  return { name, start: s + 1 };
}

/** Name, export and wrappers of an anonymous function expression starting at `start`. */
function bindingOf(src: JsSource, start: number): Binding {
  const code = src.code;
  const wrappers: string[] = [];
  let pos = start;
  for (let guard = 0; guard < 6; guard++) {
    const p = prevNonWs(code, pos - 1);
    if (p < 0) break;
    let open = -1;
    if (code[p] === "(") open = p;
    else if (code[p] === ",") {
      const o = enclosingOpen(src, p);
      if (o >= 0 && code[o] === "(") open = o;
    }
    if (open < 0) break;
    const callee = calleeBefore(code, open);
    if (!callee) break;
    wrappers.unshift(callee.name);
    pos = callee.start;
  }
  const head = code.slice(Math.max(0, pos - 300), pos);
  let m = /\bexport\s+default\s+$/.exec(head);
  if (m) return { name: "default", exported: true, exportName: "default", wrappers };
  m = /(?:\bmodule\s*\.\s*)?\bexports\s*(?:\.\s*([A-Za-z_$][\w$]*)\s*)?=\s*$/.exec(head);
  if (m) {
    const name = m[1] ?? "default";
    return { name, exported: true, exportName: name, wrappers };
  }
  m = /(\bexport\s+)?(?:\b(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*(?::[^=;]{0,200})?=\s*$/.exec(
    head,
  );
  if (m) {
    const name = m[2]!;
    const exported = m[1] !== undefined;
    return { name, exported, exportName: exported ? name : undefined, wrappers };
  }
  m = /(?:^|[{,]\s*)([A-Za-z_$][\w$]*|"[^"\n]*"|'[^'\n]*')\s*:\s*$/.exec(head);
  if (m) return { name: m[1], exported: false, exportName: undefined, wrappers };
  return { name: undefined, exported: false, exportName: undefined, wrappers: [] };
}

interface ExportAlias {
  local: string;
  exportName: string;
  wrappers: string[];
}

function exportAliases(code: string): ExportAlias[] {
  const out: ExportAlias[] = [];
  for (const m of code.matchAll(/\bexport\s*\{([^}]*)\}/g)) {
    for (const spec of m[1]!.split(",")) {
      const parts = spec.trim().split(/\s+as\s+/);
      const local = (parts[0] ?? "").trim();
      const exported = (parts[1] ?? parts[0] ?? "").trim();
      if (/^[A-Za-z_$][\w$]*$/.test(local) && exported)
        out.push({ local, exportName: exported, wrappers: [] });
    }
  }
  const wrapped = (s: string): string[] =>
    [...s.matchAll(/([\w$.]+)\s*\(/g)].map((x) => x[1]!).filter((x) => !NOT_A_METHOD.has(x));
  for (const m of code.matchAll(
    /\bexport\s+default\s+((?:[\w$.]+\s*\(\s*){0,4})([A-Za-z_$][\w$]*)\s*(?=[),;\n]|$)/g,
  ))
    out.push({ local: m[2]!, exportName: "default", wrappers: wrapped(m[1]!) });
  for (const m of code.matchAll(
    /\bexport\s+(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;]{0,200})?=\s*((?:[\w$.]+\s*\(\s*){0,4})([A-Za-z_$][\w$]*)\s*(?=[),;\n]|$)/g,
  ))
    out.push({ local: m[3]!, exportName: m[1]!, wrappers: wrapped(m[2]!) });
  for (const m of code.matchAll(
    /\bmodule\s*\.\s*exports\s*(?:\.\s*([A-Za-z_$][\w$]*)\s*)?=\s*([A-Za-z_$][\w$]*)\s*(?=[;\n]|$)/g,
  ))
    out.push({ local: m[2]!, exportName: m[1] ?? "default", wrappers: [] });
  return out;
}

function startsWithUseServer(src: JsSource, span: FunctionSpan): boolean {
  if (span.expressionBody) return false;
  return /^\s*["']use server["']/.test(src.text.slice(span.bodyStart + 1, span.bodyStart + 64));
}

function assignRoles(src: JsSource, spans: FunctionSpan[], kind: FileKind | undefined): void {
  for (const s of spans) if (startsWithUseServer(src, s)) s.role = "server-action";
  if (kind === undefined) return;
  const top = spans.filter((s) => s.parent === undefined);
  for (const s of top) {
    if (!s.exported || s.exportName === undefined) continue;
    const e = s.exportName;
    const methods = s.exportNames.filter((x) => HTTP_METHODS.has(x));
    if (kind === "next-app-route" && methods.length > 0) {
      s.role = "app-route-handler";
      s.httpMethod = methods.find((x) => MUTATING_METHODS.has(x)) ?? methods[0];
    } else if (kind === "next-pages-api" && e === "default") s.role = "pages-api-handler";
    else if (kind === "next-server-action") s.role = "server-action";
    else if (kind === "next-middleware" && (e === "middleware" || e === "proxy" || e === "default"))
      s.role = "middleware";
    else if (kind === "next-server-component" && e === "default") s.role = "page";
    else if (kind === "next-pages-page" && e === "getServerSideProps") s.role = "page";
  }
  if (
    kind === "express-server" ||
    kind === "server-module" ||
    kind === "js-module" ||
    kind === "script"
  )
    assignExpressRoles(src, spans);
}

function assignExpressRoles(src: JsSource, spans: FunctionSpan[]): void {
  if (!/\.\s*(?:get|post|put|patch|delete|all)\s*\(/.test(src.code)) return;
  let routes;
  try {
    routes = extractExpressRoutes(src.text);
  } catch {
    return;
  }
  for (const route of routes) {
    if (route.handlerChain === "") continue;
    const chainStart = src.text.indexOf(route.handlerChain, route.index);
    if (chainStart < 0) continue;
    const chainEnd = chainStart + route.handlerChain.length;
    const parts = splitTopLevel(route.chainCode);
    let offset = chainStart;
    parts.forEach((part, idx) => {
      const partStart = offset;
      offset += part.length + 1;
      const last = idx === parts.length - 1;
      const first = nextNonWs(src.code, partStart);
      const inline = spans.find((s) => s.start === first);
      if (inline) {
        if (inline.role === "other") {
          inline.role = last ? "express-handler" : "express-middleware";
          if (last) inline.httpMethod = route.method;
        }
        return;
      }
      if (!last) return;
      const ident = part.trim();
      if (!/^[A-Za-z_$][\w$]*$/.test(ident)) return;
      const named = spans.find(
        (s) =>
          s.parent === undefined &&
          s.name === ident &&
          (s.end <= chainStart || s.start >= chainEnd),
      );
      if (named && named.role === "other") {
        named.role = "express-handler";
        named.httpMethod = route.method;
      }
    });
  }
}

const SPAN_CACHE = new WeakMap<JsSource, Map<string, FunctionSpan[]>>();

/**
 * Every function in `src`, sorted by start offset, with `parent` links. With a
 * classification, roles and HTTP methods are assigned for the file kind (see
 * {@link FunctionRole}); without one only body-level `"use server"` is recognised.
 * Results are cached per source and kind; treat them as read-only.
 */
export function extractFunctions(
  src: JsSource,
  classification?: Pick<FileClassification, "kind"> | undefined,
): FunctionSpan[] {
  const key = classification?.kind ?? "";
  let perSource = SPAN_CACHE.get(src);
  if (perSource === undefined) {
    perSource = new Map();
    SPAN_CACHE.set(src, perSource);
  }
  const cached = perSource.get(key);
  if (cached) return cached;
  let spans: FunctionSpan[];
  try {
    spans = buildSpans(src, classification?.kind);
  } catch {
    spans = [];
  }
  perSource.set(key, spans);
  return spans;
}

function buildSpans(src: JsSource, kind: FileKind | undefined): FunctionSpan[] {
  const raw: RawSpan[] = [];
  findFunctionKeywords(src, raw);
  findArrows(src, raw);
  findMethods(src, raw);
  const byStart = new Map<number, RawSpan>();
  for (const r of raw) if (!byStart.has(r.paramsStart)) byStart.set(r.paramsStart, r);
  const spans: FunctionSpan[] = [...byStart.values()].map((r) => {
    const end = r.bodyEnd;
    let b: Binding = { name: r.name, exported: false, exportName: undefined, wrappers: [] };
    if (r.kind === "function" && r.name !== undefined) {
      const head = src.code.slice(Math.max(0, r.start - 40), r.start);
      const em = /\bexport\s+(default\s+)?$/.exec(head);
      if (em) b = { ...b, exported: true, exportName: em[1] ? "default" : r.name };
    } else if (r.kind !== "method") {
      const found = bindingOf(src, r.start);
      b = { ...found, name: r.name ?? found.name };
    }
    return {
      name: b.name,
      kind: r.kind,
      async: r.async,
      start: r.start,
      end,
      paramsStart: r.paramsStart,
      paramsEnd: r.paramsEnd,
      params: r.params,
      bodyStart: r.bodyStart,
      bodyEnd: r.bodyEnd,
      expressionBody: r.expressionBody,
      startLine: src.lineAt(r.start),
      endLine: src.lineAt(Math.max(r.start, end - 1)),
      exported: b.exported,
      exportName: b.exportName,
      exportNames: b.exportName === undefined ? [] : [b.exportName],
      wrappers: b.wrappers,
      role: "other" as FunctionRole,
      httpMethod: undefined,
      truncated: r.truncated,
      parent: undefined,
    };
  });
  spans.sort((a, b) => a.start - b.start || b.end - a.end);
  const stack: FunctionSpan[] = [];
  for (const s of spans) {
    while (stack.length > 0 && stack[stack.length - 1]!.end <= s.start) stack.pop();
    s.parent = stack[stack.length - 1];
    stack.push(s);
  }
  const aliases = exportAliases(src.code);
  for (const a of aliases) {
    const s = spans.find((x) => x.parent === undefined && x.name === a.local);
    if (s === undefined) continue;
    s.exported = true;
    s.exportName ??= a.exportName;
    if (!s.exportNames.includes(a.exportName)) s.exportNames.push(a.exportName);
    if (s.wrappers.length === 0) s.wrappers = a.wrappers;
  }
  assignRoles(src, spans, kind);
  return spans;
}

/**
 * Synthetic span covering the whole file (kind `module`, no params, role `other`), for
 * analysing top-level code such as scripts. Functions in the file are its descendants.
 */
export function moduleSpan(src: JsSource): FunctionSpan {
  const end = src.text.length;
  return {
    name: undefined,
    kind: "module",
    async: false,
    start: 0,
    end,
    paramsStart: 0,
    paramsEnd: 0,
    params: [],
    bodyStart: 0,
    bodyEnd: end,
    expressionBody: false,
    startLine: 1,
    endLine: src.lineAt(Math.max(0, end - 1)),
    exported: false,
    exportName: undefined,
    exportNames: [],
    wrappers: [],
    role: "other",
    httpMethod: undefined,
    truncated: false,
    parent: undefined,
  };
}

/** Innermost span containing `offset` (`start <= offset < end`), or undefined. */
export function enclosingFunction(
  spans: readonly FunctionSpan[],
  offset: number,
): FunctionSpan | undefined {
  let best: FunctionSpan | undefined;
  for (const s of spans) {
    if (s.start > offset) break;
    if (offset < s.end && (best === undefined || s.start >= best.start)) best = s;
  }
  return best;
}

/**
 * Request entry points of a file: spans whose role is `app-route-handler`,
 * `pages-api-handler`, `express-handler`, `server-action`, `middleware` or `page`.
 */
export function handlerSpans(
  src: JsSource,
  classification: Pick<FileClassification, "kind">,
): FunctionSpan[] {
  return extractFunctions(src, classification).filter((s) => HANDLER_ROLES.has(s.role));
}
