import type { ScanContext } from "@talaljaber/vibesafe-shared";
import {
  classifyFile,
  isGenerated,
  isJsLike,
  isServerScope,
  isTestOrFixturePath,
  type FileClassification,
} from "./file-kind.js";
import { enclosingOpen, expressionEnd, skipTypeForward } from "./js-functions.js";
import { getJsSource, type JsSource } from "./js-source.js";

/**
 * Small helpers shared by the tooling stream's server-side validation detectors
 * (client-trusted prices, check-then-act races). They build on the frozen JS
 * primitives (js-source, js-functions, taint) and never reimplement them.
 */

export interface ServerSource {
  file: string;
  src: JsSource;
  classification: FileClassification;
}

function isWs(c: string | undefined): boolean {
  return c === " " || c === "\t" || c === "\n" || c === "\r";
}

/** First non-whitespace offset at or after `i`. */
export function nextNonWs(code: string, i: number): number {
  while (i < code.length && isWs(code[i])) i++;
  return i;
}

/** Last non-whitespace offset at or before `i` (-1 when none). */
export function prevNonWs(code: string, i: number): number {
  while (i >= 0 && isWs(code[i])) i--;
  return i;
}

/**
 * Server-side JS sources of the scan whose code may contain `needle` (a cheap
 * `includes` prefilter on the raw text): request-serving runtimes only (not
 * client, build or script files), never generated files, and test/fixture paths
 * only with `includeTests`.
 */
export async function serverSources(context: ScanContext, needle: RegExp): Promise<ServerSource[]> {
  const out: ServerSource[] = [];
  const includeTests = context.config?.includeTests === true;
  for (const file of context.files) {
    if (!isJsLike(file) || isGenerated(file)) continue;
    if (!includeTests && isTestOrFixturePath(file)) continue;
    const src = await getJsSource(context, file);
    if (src.text === "" || !needle.test(src.text)) continue;
    const classification = classifyFile(file, src.text, context.projectContext);
    if (classification.generated || !isServerScope(classification)) continue;
    if (classification.runtime === "script" || classification.runtime === "build") continue;
    out.push({ file, src, classification });
  }
  return out;
}

/**
 * Callee text ending just before the `(` at `open`, whitespace removed across member
 * dots (`stripe.checkout\n  .sessions.create`), e.g. `stripe.checkout.sessions.create`.
 * Empty when the parenthesis does not follow an identifier.
 */
export function calleeText(code: string, open: number): string {
  const parts: string[] = [];
  let i = prevNonWs(code, open - 1);
  for (let guard = 0; guard < 16 && i >= 0; guard++) {
    let s = i;
    while (s >= 0 && /[\w$]/.test(code[s]!)) s--;
    if (s === i) break;
    parts.unshift(code.slice(s + 1, i + 1));
    const p = prevNonWs(code, s);
    if (code[p] !== ".") break;
    i = prevNonWs(code, code[p - 1] === "?" ? p - 2 : p - 1);
  }
  return parts.join(".");
}

/**
 * Range of the value bound by the declaration/assignment whose pattern starts at
 * `offset` (`const x = <init>`, `const { a } = <init>`, `for (const x of <init>)`,
 * `x = <init>`), or undefined (parameters, compound assignments, mutations).
 */
export function declarationInit(
  src: JsSource,
  offset: number,
  limit: number,
): { start: number; end: number } | undefined {
  const code = src.code;
  let i = offset;
  if (code[i] === "{" || code[i] === "[") {
    const close = src.matchOf(i);
    if (close < 0) return undefined;
    i = close + 1;
  } else {
    const id = /^[A-Za-z_$][\w$]*/.exec(code.slice(i, i + 200));
    if (id === null) return undefined;
    i += id[0].length;
  }
  let j = nextNonWs(code, i);
  if (code[j] === "!") j = nextNonWs(code, j + 1);
  if (code[j] === ":") j = nextNonWs(code, skipTypeForward(src, j + 1));
  if (/^(?:of|in)(?![\w$])/.test(code.slice(j, j + 3))) {
    const open = enclosingOpen(src, offset);
    const close = open >= 0 && code[open] === "(" ? src.matchOf(open) : -1;
    return close > j ? { start: nextNonWs(code, j + 2), end: close } : undefined;
  }
  if (code[j] === "=" && code[j + 1] !== "=" && code[j + 1] !== ">") {
    const start = nextNonWs(code, j + 1);
    return { start, end: expressionEnd(src, start, limit) };
  }
  return undefined;
}

/**
 * True when `pos` sits inside a computed member access (`table[<pos>]`,
 * `PRICES[plan]`) at or after `floor`: the value at `pos` selects a server-side
 * entry instead of being used itself.
 */
export function inIndexBracket(src: JsSource, pos: number, floor: number): boolean {
  const code = src.code;
  let open = enclosingOpen(src, pos);
  for (let guard = 0; guard < 32 && open >= floor && open >= 0; guard++) {
    if (code[open] === "[") {
      const p = prevNonWs(code, open - 1);
      if (p >= 0 && /[\w$)\]]/.test(code[p]!)) return true;
    }
    open = enclosingOpen(src, open);
  }
  return false;
}

/** Escapes a string for use inside a RegExp. */
export function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
