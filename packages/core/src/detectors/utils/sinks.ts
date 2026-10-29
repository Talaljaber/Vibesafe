import type { Confidence, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import {
  SINK_SANITIZERS,
  WEBHOOK_VERIFY_RE,
  isKnownSinkModule,
  normalizeModuleName,
  type SinkKind,
  type SinkPattern,
} from "../patterns/sink-patterns.js";
import {
  PASS_THROUGH_CALLS,
  TAINT_CLEANERS,
  type TaintRuntime,
  type TaintSource,
} from "../patterns/taint-sources.js";
import { isStripeWebhookRoute } from "../stripe-webhook-detector.js";
import { classifyFile, isServerScope, type FileClassification } from "./file-kind.js";
import {
  enclosingFunction,
  enclosingOpen,
  expressionEnd,
  extractFunctions,
  moduleSpan,
  skipTypeForward,
  type FunctionSpan,
} from "./js-functions.js";
import { makeFinding } from "./finding.js";
import { getJsSource, type JsSource } from "./js-source.js";
import { analyzeTaint, taintConfidence, type TaintHit, type TaintState } from "./taint.js";

/**
 * Sink discovery and sink-specific taint resolution for the server-side injection
 * detectors (SQL, shell, code eval, SSRF, path traversal, open redirect).
 *
 * - {@link resolveCallAliases} maps local names to canonical callees from the file's
 *   imports of well-known modules: `import { exec as sh } from "child_process"`,
 *   `const { exec } = require("child_process")`, `import * as cp from "node:child_process"`,
 *   `const run = promisify(exec)`.
 * - {@link findSinkCalls} finds calls whose canonical callee matches a {@link SinkPattern}.
 * - {@link SinkAnalyzer} answers "does attacker data reach this argument?" on top of
 *   `analyzeTaint`, adding what only a sink can decide: allowlist lookups (`MAP.get(x)`,
 *   `OBJ[x]`), sink-specific guards and sanitizers, verified webhook payloads, `req`
 *   names that are not requests, callback and same-file call-site seeding, and where a
 *   tainted part sits in a URL ({@link taintPosition}).
 *
 * All matching runs on masked code (comments and string contents blanked); literal text
 * (module names, regex sources, SQL text) is read from `text` at the same offsets.
 */

/** A half-open file range `[start, end)`. */
export interface Range {
  start: number;
  end: number;
}

// ---------------------------------------------------------------------------
// Scanning helpers
// ---------------------------------------------------------------------------

function isWs(c: string | undefined): boolean {
  return c === " " || c === "\t" || c === "\n" || c === "\r";
}

export function nextNonWs(code: string, i: number): number {
  while (i < code.length && isWs(code[i])) i++;
  return i;
}

export function prevNonWs(code: string, i: number): number {
  while (i >= 0 && isWs(code[i])) i--;
  return i;
}

/** `r` with surrounding whitespace removed. */
export function trimRange(src: JsSource, r: Range): Range {
  let s = r.start;
  let e = r.end;
  while (s < e && isWs(src.code[s])) s++;
  while (e > s && isWs(src.code[e - 1])) e--;
  return { start: s, end: e };
}

/** Offset of the template literal's closing backtick (`code[i]` is the opening one), or -1. */
export function templateEnd(src: JsSource, i: number): number {
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

/** Offset just past the string literal starting at `i` (`'` or `"`), or -1. */
export function stringEnd(src: JsSource, i: number): number {
  const q = src.code[i];
  if (q !== '"' && q !== "'") return -1;
  const e = src.code.indexOf(q, i + 1);
  return e < 0 ? -1 : e + 1;
}

/** Skips a bracket, string or template starting at `i`; returns the last offset of it or -1. */
function skipGroup(src: JsSource, i: number, end: number): number {
  const c = src.code[i];
  if (c === "(" || c === "[" || c === "{") {
    const m = src.matchOf(i);
    return m < 0 || m >= end ? -1 : m;
  }
  if (c === "`") {
    const e = templateEnd(src, i);
    return e < 0 || e >= end ? -1 : e;
  }
  if (c === '"' || c === "'") {
    const e = stringEnd(src, i);
    return e < 0 || e > end ? -1 : e - 1;
  }
  return i;
}

/**
 * Splits `r` at top-level `sep` (`,` or a binary `+`), skipping brackets, strings and
 * template literals. Ranges are trimmed and empty ones dropped.
 */
export function splitTopLevel(src: JsSource, r: Range, sep: "," | "+"): Range[] {
  const code = src.code;
  const out: Range[] = [];
  let from = r.start;
  for (let i = r.start; i < r.end; i++) {
    const c = code[i]!;
    if (c === "(" || c === "[" || c === "{" || c === "`" || c === '"' || c === "'") {
      const e = skipGroup(src, i, r.end);
      if (e < 0) break;
      i = e;
      continue;
    }
    if (c !== sep) continue;
    if (sep === "+") {
      if (code[i + 1] === "+" || code[i - 1] === "+" || code[i + 1] === "=") continue;
      const p = prevNonWs(code, i - 1);
      if (p < r.start || "=(,?:+-*/%&|!<>".includes(code[p]!)) continue; // unary plus
    }
    out.push(trimRange(src, { start: from, end: i }));
    from = i + 1;
  }
  out.push(trimRange(src, { start: from, end: r.end }));
  return out.filter((x) => x.end > x.start);
}

/** Splits `r` at a top-level two-character operator (`??`, `||`). */
export function splitTopLevelOp(src: JsSource, r: Range, op: "??" | "||"): Range[] {
  const code = src.code;
  const out: Range[] = [];
  let from = r.start;
  for (let i = r.start; i < r.end; i++) {
    const c = code[i]!;
    if (c === "(" || c === "[" || c === "{" || c === "`" || c === '"' || c === "'") {
      const e = skipGroup(src, i, r.end);
      if (e < 0) break;
      i = e;
      continue;
    }
    if (c === op[0] && code[i + 1] === op[1] && code[i + 2] !== "=" && code[i - 1] !== op[0]) {
      out.push(trimRange(src, { start: from, end: i }));
      from = i + 2;
      i++;
    }
  }
  out.push(trimRange(src, { start: from, end: r.end }));
  return out.filter((x) => x.end > x.start);
}

/** Top-level `cond ? a : b` in `r`, or undefined. */
export function topLevelTernary(
  src: JsSource,
  r: Range,
): { cond: Range; whenTrue: Range; whenFalse: Range } | undefined {
  const code = src.code;
  let q = -1;
  let nested = 0;
  for (let i = r.start; i < r.end; i++) {
    const c = code[i]!;
    if (c === "(" || c === "[" || c === "{" || c === "`" || c === '"' || c === "'") {
      const e = skipGroup(src, i, r.end);
      if (e < 0) return undefined;
      i = e;
      continue;
    }
    if (c === "?" && code[i + 1] !== "." && code[i + 1] !== "?" && code[i - 1] !== "?") {
      if (q < 0) q = i;
      else nested++;
    } else if (c === ":" && q >= 0) {
      if (nested > 0) {
        nested--;
        continue;
      }
      return {
        cond: trimRange(src, { start: r.start, end: q }),
        whenTrue: trimRange(src, { start: q + 1, end: i }),
        whenFalse: trimRange(src, { start: i + 1, end: r.end }),
      };
    }
  }
  return undefined;
}

/** Top-level argument ranges of the call whose parentheses are at `open`/`close`. */
export function splitArgs(src: JsSource, open: number, close: number): Range[] {
  return splitTopLevel(src, { start: open + 1, end: close }, ",");
}

/**
 * Static text of the string and template literals inside `r` (template `${}` parts become
 * ` X `), joined with spaces. Bounded to 4000 characters.
 */
export function staticText(src: JsSource, r: Range): string {
  const code = src.code;
  const parts: string[] = [];
  let total = 0;
  for (let i = r.start; i < r.end && total < 4000; i++) {
    const c = code[i]!;
    if (c === '"' || c === "'") {
      const e = stringEnd(src, i);
      if (e < 0) break;
      const s = src.text.slice(i + 1, e - 1);
      parts.push(s);
      total += s.length;
      i = e - 1;
    } else if (c === "`") {
      const e = templateEnd(src, i);
      if (e < 0) break;
      let buf = "";
      for (let j = i + 1; j < e; j++) {
        if (code[j] === "$" && code[j + 1] === "{") {
          const m = src.matchOf(j + 1);
          if (m < 0) break;
          buf += " X ";
          j = m;
        } else buf += src.text[j];
      }
      parts.push(buf);
      total += buf.length;
      i = e;
    }
  }
  return parts.join(" ");
}

/** Parts of a template literal spanning exactly `r`, or undefined. */
function templateParts(
  src: JsSource,
  r: Range,
): { kind: "static" | "expr"; range: Range }[] | undefined {
  const code = src.code;
  if (code[r.start] !== "`" || templateEnd(src, r.start) !== r.end - 1) return undefined;
  const out: { kind: "static" | "expr"; range: Range }[] = [];
  let from = r.start + 1;
  for (let j = r.start + 1; j < r.end - 1; j++) {
    if (code[j] === "$" && code[j + 1] === "{") {
      const m = src.matchOf(j + 1);
      if (m < 0) return undefined;
      if (j > from) out.push({ kind: "static", range: { start: from, end: j } });
      out.push({ kind: "expr", range: trimRange(src, { start: j + 2, end: m }) });
      j = m;
      from = m + 1;
    }
  }
  if (r.end - 1 > from) out.push({ kind: "static", range: { start: from, end: r.end - 1 } });
  return out;
}

// ---------------------------------------------------------------------------
// URL positions
// ---------------------------------------------------------------------------

/**
 * Where a tainted value sits in a string built from parts (URL-oriented):
 * - `whole`: the value is the string, or its start (`fetch(url)`, `` `${url}/x` ``).
 * - `url-origin`: after a fixed prefix but before any path separator, so it can still
 *   change the host (`` `https://${host}/x` ``, `` `${origin}${next}` ``, `"/" + next`).
 * - `url-path`: after a fixed origin and a `/` (`` `https://api.x.com/u/${id}` ``).
 * - `inner`: in the query string or fragment, or after arbitrary non-URL text.
 */
export type TaintPosition = "whole" | "url-origin" | "url-path" | "inner";

const POSITION_RANK: Readonly<Record<TaintPosition, number>> = {
  whole: 0,
  "url-origin": 1,
  "url-path": 2,
  inner: 3,
};

/** The less constrained (more dangerous) of two positions. */
export function strongerPosition(a: TaintPosition, b: TaintPosition): TaintPosition {
  return POSITION_RANK[a] <= POSITION_RANK[b] ? a : b;
}

/**
 * Position of a tainted part that follows `prefix` (the static text before it, with each
 * untainted dynamic part written as `X`), given the part's own position `inner`.
 */
export function taintPosition(prefix: string, inner: TaintPosition = "whole"): TaintPosition {
  if (prefix === "") return inner;
  let p: TaintPosition;
  if (/[?#]/.test(prefix)) p = "inner";
  else if (prefix === "/")
    p = "url-origin"; // "/" + "/evil.com" is protocol-relative
  else {
    const scheme = /^[a-z][\w+.-]*:\/\//i.exec(prefix);
    const rest = scheme ? prefix.slice(scheme[0].length) : prefix;
    if (rest.includes("/")) p = "url-path";
    else if (scheme || /^[X\w.:@-]*$/.test(rest)) p = "url-origin";
    else p = "inner";
  }
  return POSITION_RANK[p] >= POSITION_RANK[inner] ? p : inner;
}

// ---------------------------------------------------------------------------
// Aliases
// ---------------------------------------------------------------------------

function moduleAt(src: JsSource, quoteAt: number): { name: string; end: number } | undefined {
  const q = src.code[quoteAt];
  if (q !== '"' && q !== "'") return undefined;
  const e = src.code.indexOf(q, quoteAt + 1);
  if (e < 0) return undefined;
  return { name: normalizeModuleName(src.text.slice(quoteAt + 1, e)), end: e + 1 };
}

function memberName(mod: string, name: string): string {
  return name === "default" ? mod : `${mod}.${name}`;
}

function addSpecifiers(map: Map<string, string>, base: string, specs: string): void {
  for (const raw of specs.split(",")) {
    const spec = raw.trim();
    if (spec === "" || /^type\s/.test(spec)) continue;
    const m = /^([A-Za-z_$][\w$]*)(?:\s*(?:as|:)\s*([A-Za-z_$][\w$]*))?/.exec(spec);
    if (!m) continue;
    map.set(m[2] ?? m[1]!, memberName(base, m[1]!));
  }
}

const PROMISIFY_RE =
  /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:util\s*\.\s*)?promisify\s*\(\s*([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\)/g;
const PROMISIFY_REQUIRE_RE =
  /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:util\s*\.\s*)?promisify\s*\(\s*require\s*\(\s*(?=["'])/g;
const ALIAS_RE =
  /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)+)\s*(?=[;\n])/g;
const IMPORT_RE = /\bimport\s+(?!type\b)([^;]*?)\s*from\s*(?=["'])/g;
const REQUIRE_RE =
  /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*|\{[^}]*\})\s*=\s*(?:await\s+)?(?:require|import)\s*\(\s*(?=["'])/g;

/**
 * Local name -> canonical callee for the file's imports and requires of well-known
 * modules (see the module comment). Project modules are never resolved. Never throws.
 */
export function resolveCallAliases(src: JsSource): Map<string, string> {
  const map = new Map<string, string>();
  const code = src.code;
  try {
    for (const m of code.matchAll(IMPORT_RE)) {
      const mod = moduleAt(src, m.index + m[0].length);
      if (!mod || !isKnownSinkModule(mod.name)) continue;
      const clause = m[1]!.trim();
      const ns = /^\*\s*as\s+([A-Za-z_$][\w$]*)$/.exec(clause);
      if (ns) {
        map.set(ns[1]!, mod.name);
        continue;
      }
      const def = /^([A-Za-z_$][\w$]*)\s*(?:,|$)/.exec(clause);
      if (def) map.set(def[1]!, mod.name);
      const nsAfter = /,\s*\*\s*as\s+([A-Za-z_$][\w$]*)/.exec(clause);
      if (nsAfter) map.set(nsAfter[1]!, mod.name);
      const braces = /\{([^}]*)\}/.exec(clause);
      if (braces) addSpecifiers(map, mod.name, braces[1]!);
    }
    for (const m of code.matchAll(REQUIRE_RE)) {
      const mod = moduleAt(src, m.index + m[0].length);
      if (!mod || !isKnownSinkModule(mod.name)) continue;
      const after = /^\s*\)\s*(?:\.\s*([A-Za-z_$][\w$]*))?/.exec(code.slice(mod.end, mod.end + 80));
      const member = after?.[1];
      const target = m[1]!;
      const base = member ? `${mod.name}.${member}` : mod.name;
      if (target.startsWith("{")) addSpecifiers(map, base, target.slice(1, -1));
      else map.set(target, base);
    }
    for (const m of code.matchAll(PROMISIFY_RE)) {
      map.set(m[1]!, canonicalCallee(m[2]!.replace(/\s+/g, ""), map));
    }
    for (const m of code.matchAll(PROMISIFY_REQUIRE_RE)) {
      const mod = moduleAt(src, m.index + m[0].length);
      if (!mod || !isKnownSinkModule(mod.name)) continue;
      const after = /^\s*\)\s*\.\s*([A-Za-z_$][\w$]*)/.exec(code.slice(mod.end, mod.end + 80));
      if (after) map.set(m[1]!, `${mod.name}.${after[1]!}`);
    }
    for (const m of code.matchAll(ALIAS_RE)) {
      if (map.has(m[1]!)) continue;
      const inner = m[2]!.replace(/\s+/g, "");
      if (map.has(inner.split(".")[0]!)) map.set(m[1]!, canonicalCallee(inner, map));
    }
  } catch {
    // best effort
  }
  return map;
}

/** Resolves the first segment of `raw` through `aliases` and folds `fs.promises.x` to `fs.x`. */
export function canonicalCallee(raw: string, aliases: ReadonlyMap<string, string>): string {
  const dot = raw.indexOf(".");
  const head = dot < 0 ? raw : raw.slice(0, dot);
  const rest = dot < 0 ? "" : raw.slice(dot);
  const mapped = aliases.get(head);
  const out = mapped === undefined ? raw : mapped + rest;
  return out.replace(/^fs\.promises\./, "fs.");
}

// ---------------------------------------------------------------------------
// Calls
// ---------------------------------------------------------------------------

export interface SinkCall {
  pattern: SinkPattern;
  /** Canonical callee (aliases resolved), e.g. `child_process.exec`. */
  callee: string;
  /** Callee as written, e.g. `sh` or `cp.exec`. */
  raw: string;
  /** Offset of the callee's first character. */
  start: number;
  /** Offsets of `(` and `)`. */
  open: number;
  close: number;
  /** Top-level argument ranges, trimmed. */
  args: Range[];
  isNew: boolean;
  /** 1-indexed line of the callee. */
  line: number;
}

const CALL_RE = /(?<![\w$])([A-Za-z_$][\w$]*(?:\s*\??\.\s*[A-Za-z_$][\w$]*)*)\s*\(/g;
const NOT_CALLEE = new Set([
  "if",
  "for",
  "while",
  "switch",
  "catch",
  "function",
  "return",
  "typeof",
  "await",
  "yield",
  "void",
  "delete",
  "in",
  "of",
  "case",
  "throw",
  "else",
  "do",
  "with",
  "super",
  "import",
]);
const METHOD_MODIFIER_RE = /^(?:async|static|get|set|public|private|protected|override)$/;

/**
 * Calls in `src` whose canonical callee matches one of `patterns` (first match wins, so
 * list specific patterns first). Declarations (`function exec(`, method definitions) are
 * skipped. `require("child_process").exec(...)` resolves through the inline require; a
 * call on a call or index result reads `.method` (`(await db()).query` -> `.query`).
 */
export function findSinkCalls(
  src: JsSource,
  patterns: readonly SinkPattern[],
  aliases: ReadonlyMap<string, string>,
): SinkCall[] {
  const out: SinkCall[] = [];
  if (patterns.length === 0) return out;
  const code = src.code;
  const re = new RegExp(CALL_RE.source, "g");
  for (let m = re.exec(code); m !== null; m = re.exec(code)) {
    const raw = m[1]!.replace(/\s+/g, "").replace(/\?\./g, ".");
    const head = raw.split(".")[0]!;
    if (NOT_CALLEE.has(head)) continue;
    const open = m.index + m[0].length - 1;
    const close = src.matchOf(open);
    if (close < 0) continue;
    const before = prevNonWs(code, m.index - 1);
    const word = /([A-Za-z_$][\w$]*)\s*$/.exec(code.slice(Math.max(0, m.index - 24), m.index));
    const wordBefore = word?.[1];
    if (wordBefore === "function" || wordBefore === "class") continue;
    const afterClose = nextNonWs(code, close + 1);
    if (
      code[afterClose] === "{" &&
      (before < 0 ||
        "{};,".includes(code[before]!) ||
        (wordBefore !== undefined && METHOD_MODIFIER_RE.test(wordBefore)))
    )
      continue; // method definition
    let callee: string;
    if (code[before] === "." && !(code[before - 1] === "." && code[before - 2] === ".")) {
      let prefix = "";
      const recvEnd = prevNonWs(code, before - 1);
      if (code[recvEnd] === ")") {
        const ro = src.matchOf(recvEnd);
        if (ro >= 0 && /\brequire\s*$/.test(code.slice(Math.max(0, ro - 12), ro))) {
          const mod = moduleAt(src, nextNonWs(code, ro + 1));
          if (mod && isKnownSinkModule(mod.name)) prefix = `${mod.name}.`;
        }
      }
      callee = prefix === "" ? `.${raw}` : (prefix + raw).replace(/^fs\.promises\./, "fs.");
    } else callee = canonicalCallee(raw, aliases);
    const isNew = wordBefore === "new";
    for (const p of patterns) {
      if (p.constructorOnly === true && !isNew) continue;
      if (p.callOnly === true && isNew) continue;
      if (!p.callee.test(callee)) continue;
      out.push({
        pattern: p,
        callee,
        raw,
        start: m.index,
        open,
        close,
        args: splitArgs(src, open, close),
        isNew,
        line: src.lineAt(m.index),
      });
      break;
    }
  }
  return out;
}

/** Argument ranges of `call` that carry the pattern's dangerous value. */
export function sinkArgs(call: SinkCall): Range[] {
  const spec = call.pattern.args;
  if (spec === "all") return call.args;
  if (spec === "last") return call.args.length > 0 ? [call.args[call.args.length - 1]!] : [];
  return spec.map((i) => call.args[i]).filter((r): r is Range => r !== undefined);
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

/** A server-side JS file prepared for sink analysis. */
export interface SinkFile {
  file: string;
  src: JsSource;
  classification: FileClassification;
  runtime: TaintRuntime;
  spans: FunctionSpan[];
  aliases: ReadonlyMap<string, string>;
}

const CLASSIFICATION_CACHE = new WeakMap<ScanContext, Map<string, FileClassification>>();
const SINK_FILE_CACHE = new WeakMap<JsSource, SinkFile>();

/**
 * Loads `file` for the injection detectors, or undefined when it is out of scope: not a
 * server-side JS file (`runtime === "client"`, `.py`, `.sql`, ...), generated, a test or
 * fixture (unless `includeTests`), a signature-verified Stripe webhook route, or a file
 * that contains none of `needles` (cheap prefilter before any parsing). Never throws.
 */
export async function loadSinkFile(
  context: ScanContext,
  file: string,
  needles: readonly string[],
): Promise<SinkFile | undefined> {
  try {
    if (!/\.(?:[cm]?[jt]s|[jt]sx)$/i.test(file)) return undefined;
    const text = await context.readFile(file);
    if (text === "" || !needles.some((n) => text.includes(n))) return undefined;
    let perContext = CLASSIFICATION_CACHE.get(context);
    if (perContext === undefined) {
      perContext = new Map();
      CLASSIFICATION_CACHE.set(context, perContext);
    }
    let classification = perContext.get(file);
    if (classification === undefined) {
      classification = classifyFile(file, text, context.projectContext);
      perContext.set(file, classification);
    }
    if (!isServerScope(classification) || classification.generated) return undefined;
    if (classification.testOrFixture && context.config?.includeTests !== true) return undefined;
    if (isStripeWebhookRoute(file, text)) return undefined;
    const src = await getJsSource(context, file);
    const cached = SINK_FILE_CACHE.get(src);
    if (cached !== undefined) return cached;
    const sinkFile: SinkFile = {
      file,
      src,
      classification,
      runtime: classification.runtime === "script" ? "script" : "server",
      spans: extractFunctions(src, classification),
      aliases: resolveCallAliases(src),
    };
    SINK_FILE_CACHE.set(src, sinkFile);
    return sinkFile;
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

const HANDLER_ROLES = new Set([
  "app-route-handler",
  "pages-api-handler",
  "express-handler",
  "express-middleware",
  "server-action",
  "middleware",
  "page",
]);
const REQUEST_NAME_SOURCES = new Set([
  "request-body",
  "request-payload",
  "request-query",
  "request-params",
  "request-url",
  "request-headers",
]);
const CALLBACK_METHODS = new Set([
  "map",
  "forEach",
  "filter",
  "flatMap",
  "find",
  "findLast",
  "some",
  "every",
  "reduce",
  "reduceRight",
  "then",
]);
const BOOLEAN_METHOD_RE =
  /(?:^|\.)(?:includes|has|test|startsWith|endsWith|some|every|indexOf|lastIndexOf|findIndex|localeCompare|isArray|isInteger|isSafeInteger|isFinite|isNaN)$/;
const KEYWORD_RE =
  /^(?:if|for|while|switch|catch|return|typeof|function|await|yield|void|delete|in|of|new|case|throw|else|do)$/;
const MAX_ANALYSES = 50;
const MAX_DEPTH = 5;

/** A tainted value reaching a sink argument, after sink-specific filtering. */
export interface EffectiveHit {
  hit: TaintHit;
  /**
   * The taint is real but weaker evidence: the value went through schema validation
   * (`schema.parse`), or the source is a `req`-named parameter outside a known handler.
   */
  weak: boolean;
}

/** What reaches a sink argument. */
export interface ArgTaint {
  /** Strongest hit (by confidence, then trust). */
  hit: TaintHit;
  hits: EffectiveHit[];
  confidence: Confidence;
  /** The analysis the hits come from (use it for {@link SinkAnalyzer.position}). */
  state: TaintState;
  /** Found by seeding a callback or a same-file function's parameters. */
  seeded: boolean;
}

interface IfStatement {
  offset: number;
  cond: Range;
  /** The consequent returns/throws/redirects (early exit). */
  exits: boolean;
  /** Block range of the consequent when it is a `{}` block. */
  block: Range | undefined;
}

type Position = TaintPosition | "self" | undefined;

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Regex source (text) of a regex literal `/.../flags` at the start of `s`, or undefined. */
function regexLiteralSource(s: string): string | undefined {
  const m = /^\/((?:[^/\\\n[]|\\.|\[(?:[^\]\\\n]|\\.)*\])+)\/[a-z]*/.exec(s);
  return m?.[1];
}

/** Anchored both ends, no wildcard `.`, no negated class: a whitelist-style regex. */
function isStrictRegex(source: string): boolean {
  if (!source.startsWith("^") || !source.endsWith("$")) return false;
  const plain = source.replace(/\\./g, "E");
  return !plain.includes(".") && !plain.includes("[^");
}

/** The regex pins a host (contains an escaped-dot domain), not just a scheme. */
function isHostRegex(source: string): boolean {
  return /[a-z0-9-]\\\.[a-z]/i.test(source);
}

/** The regex only accepts a same-site path: `^/` not followed by another `/` or `\`. */
function isRelativePathRegex(source: string): boolean {
  const m = /^\^\\?\/(.*)$/.exec(source);
  if (!m) return false;
  const rest = m[1]!;
  return rest.startsWith("(?!") || /^\[(?!\^)[^\]/\\]*\]/.test(rest) || /^[\w-]/.test(rest);
}

/**
 * Per-file, per-sink-kind analysis driver. Holds caches and the analysis budget
 * (≤ 50 taint analyses per file). Never throws: failures read as "no taint".
 */
export class SinkAnalyzer {
  private analyses = 0;
  private module: TaintState | undefined;
  private moduleTainted: Map<string, TaintHit> | undefined;
  private readonly tops = new Map<number, TaintState>();
  private readonly ifs = new Map<string, IfStatement[]>();
  private readonly literalCollections = new Map<string, boolean>();

  constructor(
    readonly f: SinkFile,
    readonly kind: SinkKind,
  ) {}

  // ---- states ----

  private moduleState(): TaintState {
    this.module ??= analyzeTaint(this.f.src, moduleSpan(this.f.src), { runtime: this.f.runtime });
    return this.module;
  }

  /** Tainted module-scope names (latest binding per name). */
  private moduleTaint(): Map<string, TaintHit> {
    if (this.moduleTainted !== undefined) return this.moduleTainted;
    const out = new Map<string, TaintHit>();
    const len = this.f.src.text.length;
    const latest = new Map<string, number>();
    for (const b of this.moduleState().bindings) {
      if (b.scopeStart !== 0 || b.scopeEnd !== len) continue;
      if ((latest.get(b.name) ?? -1) > b.offset) continue;
      latest.set(b.name, b.offset);
      if (b.hit === undefined) out.delete(b.name);
      else out.set(b.name, b.hit);
    }
    this.moduleTainted = out;
    return out;
  }

  private budget(): boolean {
    if (this.analyses >= MAX_ANALYSES) return false;
    this.analyses++;
    return true;
  }

  private topOf(offset: number): FunctionSpan | undefined {
    let s = enclosingFunction(this.f.spans, offset);
    while (s?.parent !== undefined) s = s.parent;
    return s;
  }

  /** The analysis covering `offset`: its top-level function (module taint inherited) or the module. */
  stateAt(offset: number): TaintState {
    const top = this.topOf(offset);
    if (top === undefined) return this.moduleState();
    const cached = this.tops.get(top.start);
    if (cached !== undefined) return cached;
    const inherited = this.moduleTaint();
    let st: TaintState;
    if (inherited.size === 0) st = analyzeTaint(this.f.src, top, { runtime: this.f.runtime });
    else {
      this.analyses++;
      st = analyzeTaint(this.f.src, top, { runtime: this.f.runtime, inherited });
    }
    this.tops.set(top.start, st);
    return st;
  }

  // ---- public API ----

  /**
   * Taint reaching `range` (a sink argument) for a sink at `at`, or undefined. Tries the
   * covering analysis first, then a tainted callback receiver (`list.map((x) => sink(x))`),
   * then same-file callers of the enclosing function (depth ≤ 2).
   */
  argTaint(range: Range, at: number): ArgTaint | undefined {
    try {
      const st = this.stateAt(at);
      const direct = this.effective(st, range, at, 0);
      if (direct.length > 0) return this.result(st, direct, false, at);
      const cb = this.callbackState(st, at);
      if (cb !== undefined) {
        const hits = this.effective(cb, range, at, 0);
        if (hits.length > 0) return this.result(cb, hits, true, at);
      }
      const seeded = this.callerSeeded(range, at, 0);
      if (seeded !== undefined) return this.result(seeded.state, seeded.hits, true, at);
    } catch {
      // never throw from a detector
    }
    return undefined;
  }

  /**
   * Where taint sits in the URL built by `range` in `state`: `whole`, `url-origin`,
   * `url-path`, `inner`, or undefined when no attacker data reaches it (the request's own
   * origin, `new URL("/x", req.url)`, counts as fixed).
   */
  position(state: TaintState, range: Range, at: number): TaintPosition | undefined {
    try {
      const p = this.pos(state, trimRange(this.f.src, range), at, 0);
      return p === "self" ? undefined : p;
    } catch {
      return undefined;
    }
  }

  /** The analysed span of `state` is truncated, or so is the innermost span at `at`. */
  truncatedAt(state: TaintState, at: number): boolean {
    return state.span.truncated || enclosingFunction(this.f.spans, at)?.truncated === true;
  }

  /** The innermost request-handler span containing `offset`, if any. */
  handlerAt(offset: number): FunctionSpan | undefined {
    for (let s = enclosingFunction(this.f.spans, offset); s !== undefined; s = s.parent)
      if (HANDLER_ROLES.has(s.role)) return s;
    return undefined;
  }

  /**
   * Analysis of `span` with the parameters at `indexes` seeded as `source` (for rules
   * about values a function receives from its callers). Undefined when over budget.
   */
  seededState(span: FunctionSpan, indexes: number[], source: TaintSource): TaintState | undefined {
    if (indexes.length === 0 || !this.budget()) return undefined;
    const inherited = this.moduleTaint();
    return analyzeTaint(this.f.src, span, {
      runtime: this.f.runtime,
      seedParams: indexes,
      seedSource: source,
      ...(inherited.size > 0 ? { inherited } : {}),
    });
  }

  /** Effective hits of `range` in an explicit state (see {@link argTaint}). */
  hitsIn(state: TaintState, range: Range, at: number): EffectiveHit[] {
    try {
      return this.effective(state, range, at, 0);
    } catch {
      return [];
    }
  }

  // ---- result ----

  private result(st: TaintState, hits: EffectiveHit[], seeded: boolean, at: number): ArgTaint {
    const score = (e: EffectiveHit): number =>
      (e.weak ? 0 : 4) +
      (taintConfidence(e.hit) === "high" ? 2 : 0) +
      (e.hit.trust === "remote" ? 1 : 0);
    const best = [...hits].sort((a, b) => score(b) - score(a))[0]!;
    let confidence = taintConfidence(best.hit);
    if (best.weak || seeded || this.truncatedAt(st, at)) confidence = "medium";
    return { hit: best.hit, hits, confidence, state: st, seeded };
  }

  // ---- effective hits ----

  private effective(st: TaintState, range: Range, at: number, depth: number): EffectiveHit[] {
    const out: EffectiveHit[] = [];
    for (const h of this.rangeHits(st, range, at)) {
      const e = this.filterHit(st, h, range.start, at, depth);
      if (e !== undefined) out.push(e);
    }
    return out;
  }

  /** Raw hits of `range`; a ternary whose condition guards a name drops that name's hits in the true branch. */
  private rangeHits(st: TaintState, range: Range, at: number): TaintHit[] {
    const src = this.f.src;
    const r = trimRange(src, range);
    if (r.end <= r.start) return [];
    const tpl = templateParts(src, r);
    if (tpl !== undefined)
      return tpl.flatMap((p) => (p.kind === "expr" ? this.rangeHits(st, p.range, at) : []));
    const plus = splitTopLevel(src, r, "+");
    if (plus.length > 1) return plus.flatMap((p) => this.rangeHits(st, p, at));
    if (this.isBooleanOrNumeric(r)) return [];
    if (this.safeMapExpr(st, r, at)) return [];
    const t = topLevelTernary(src, r);
    if (t === undefined) return st.exprTaints(r.start, r.end);
    const cond = this.resolveCond(st, t.cond);
    const a = this.rangeHits(st, t.whenTrue, at).filter(
      (h) => !this.condGuards(cond, this.hitName(h), "enter", st),
    );
    return [...a, ...this.rangeHits(st, t.whenFalse, at)];
  }

  /** A ternary condition that is a lone boolean binding (`safe ? v : "/"`) stands for its initializer. */
  private resolveCond(st: TaintState, cond: Range): Range {
    const r = trimRange(this.f.src, cond);
    if (!/^[A-Za-z_$][\w$]*$/.test(this.f.src.code.slice(r.start, r.end))) return cond;
    const name = this.f.src.code.slice(r.start, r.end);
    const b = this.visibleBinding(st, name, r.start);
    const init = b === undefined ? undefined : this.bindingInit(st, b);
    return init !== undefined && init.exact ? init.range : cond;
  }

  /**
   * The expression yields a boolean or a number (`a === b`, `!x`, `typeof x`, `x.length`,
   * `page * size`), so it cannot carry attacker-chosen text.
   */
  private isBooleanOrNumeric(r: Range): boolean {
    const src = this.f.src;
    const code = src.code;
    const seg = code.slice(r.start, r.end);
    if (/^!(?!=)/.test(seg) || /^typeof\b/.test(seg)) return true;
    if (/\.\s*(?:length|size)\s*$/.test(seg)) return true;
    if (topLevelTernary(src, r) !== undefined) return false;
    for (let i = r.start; i < r.end; i++) {
      const c = code[i]!;
      if (c === "(" || c === "[" || c === "{" || c === "`" || c === '"' || c === "'") {
        const e = skipGroup(src, i, r.end);
        if (e < 0) return false;
        i = e;
        continue;
      }
      if ((c === "=" || c === "!") && code[i + 1] === "=") return true;
      if ((c === "<" || c === ">") && code[i - 1] !== "=" && code[i + 1] !== ">") return true;
      if ((c === "*" || c === "/" || c === "%") && code[i + 1] !== "=") return true;
      if (
        c === "-" &&
        code[i + 1] !== "-" &&
        code[i - 1] !== "-" &&
        prevNonWs(code, i - 1) >= r.start
      )
        return true;
    }
    return false;
  }

  /** Name used to look for guards: the binding name, or the source member chain (`req.query.x`). */
  private hitName(h: TaintHit): string | undefined {
    if (h.via !== undefined) return h.via;
    const m = /^[A-Za-z_$][\w$]*(?:\s*\??\.\s*[A-Za-z_$][\w$]*)*/.exec(
      this.f.src.code.slice(h.offset, h.offset + 200),
    );
    return m?.[0].replace(/\s+/g, "");
  }

  private filterHit(
    st: TaintState,
    h: TaintHit,
    rangeStart: number,
    at: number,
    depth: number,
  ): EffectiveHit | undefined {
    const src = this.f.src;
    // cleaners recorded by the taint analysis
    if (this.cleanedForKind(h)) return undefined;
    // calls between the range start and the hit: sanitizers, webhook verification, unknown calls
    if (this.callBoundary(rangeStart, h.offset)) return undefined;
    const schemaWeak = this.kind !== "eval" && h.cleanedBy.includes("schema");
    const name = this.hitName(h);
    if (name !== undefined && this.guarded(st, name, at)) return undefined;
    if (h.via === undefined) {
      // a direct source in the range: `req.body` must be a request parameter
      const req = REQUEST_NAME_SOURCES.has(h.source.id)
        ? /^(req|request)\b/.exec(src.code.slice(h.offset, h.offset + 8))?.[1]
        : undefined;
      if (req !== undefined) {
        const owner = this.paramOwner(req, h.offset);
        if (owner === undefined) return undefined;
        return { hit: h, weak: schemaWeak || !HANDLER_ROLES.has(owner.role) };
      }
      return { hit: h, weak: schemaWeak };
    }
    let b = this.visibleBinding(st, h.via, h.offset);
    if (b === undefined) return { hit: h, weak: schemaWeak };
    // Walk the appends (`+=`, `push`) back to the assignment that starts the value: the hit
    // stays only when one of them carries taint, so `params.push(q); sql += ` AND a = $${params.length}``
    // and `where.push(`a = $${n}`)` are clean.
    const subs: EffectiveHit[] = [];
    for (let guard = 0; guard < 24; guard++) {
      const init = this.bindingInit(st, b);
      if (init === undefined) return { hit: h, weak: schemaWeak }; // parameter, inherited, unknown shape
      if (!this.isSafeInit(st, init, at)) {
        if (depth >= MAX_DEPTH) return { hit: h, weak: schemaWeak };
        subs.push(...this.effective(st, init.range, at, depth + 1));
      }
      if (init.exact) break;
      const prev = this.visibleBinding(st, h.via, b.offset);
      if (prev === undefined) break;
      b = prev;
    }
    if (subs.length === 0) return undefined;
    return { hit: h, weak: schemaWeak || subs.every((s) => s.weak) };
  }

  private cleanedForKind(h: TaintHit): boolean {
    const c = h.cleanedBy;
    switch (this.kind) {
      case "sql":
        return c.includes("sql");
      case "postgrest":
        return c.includes("url-encode") || c.includes("sql");
      case "command":
        return c.includes("shell") || c.includes("url-encode");
      case "eval":
        return false;
      case "ssrf":
      case "redirect":
        return c.includes("url-encode");
      case "path":
        return c.includes("path") || c.includes("url-encode");
    }
  }

  /**
   * True when a call encloses `at` inside `[start, at)` that ends the taint for this sink:
   * a sink sanitizer, a webhook verification, or an unknown non-awaited call (its result
   * is not the input; awaited calls are already dropped by the taint analysis).
   */
  private callBoundary(start: number, at: number): boolean {
    const src = this.f.src;
    const code = src.code;
    for (let i = enclosingOpen(src, at); i >= start && i >= 0; i = enclosingOpen(src, i)) {
      if (code[i] !== "(") continue;
      const callee = this.calleeAt(i);
      if (callee === undefined || KEYWORD_RE.test(callee)) continue;
      if (WEBHOOK_VERIFY_RE.test(`${callee}(`) || /(?:^|\.)verify$/.test(callee)) return true;
      const san = SINK_SANITIZERS[this.kind];
      if (san !== undefined && san.test(callee)) return true;
      if (TAINT_CLEANERS.some((c) => c.callee.test(callee))) continue;
      if (BOOLEAN_METHOD_RE.test(callee)) continue;
      if (PASS_THROUGH_CALLS.some((re) => re.test(callee))) continue;
      return true;
    }
    return false;
  }

  /** Callee text before the `(` at `open` (leading dots and whitespace in chains removed). */
  private calleeAt(open: number): string | undefined {
    const code = this.f.src.code;
    let i = prevNonWs(code, open - 1);
    if (i < 0 || !/[\w$]/.test(code[i]!)) return undefined;
    const parts: string[] = [];
    for (let guard = 0; guard < 12; guard++) {
      let s = i;
      while (s >= 0 && /[\w$]/.test(code[s]!)) s--;
      parts.unshift(code.slice(s + 1, i + 1));
      let p = prevNonWs(code, s);
      if (code[p] !== ".") break;
      p = prevNonWs(code, p - 1);
      if (code[p] === "?") p = prevNonWs(code, p - 1);
      if (p < 0 || !/[\w$]/.test(code[p]!)) break; // receiver is a call or index result
      i = p;
    }
    const name = parts.join(".");
    return /^[A-Za-z_$]/.test(name) ? name : undefined;
  }

  private paramOwner(name: string, offset: number): FunctionSpan | undefined {
    for (let s = enclosingFunction(this.f.spans, offset); s !== undefined; s = s.parent)
      if (s.params.some((p) => p.names.includes(name))) return s;
    return undefined;
  }

  private visibleBinding(st: TaintState, name: string, at: number) {
    let best: TaintState["bindings"][number] | undefined;
    for (const b of st.bindings) {
      if (b.name !== name || b.offset >= at || at < b.scopeStart || at >= b.scopeEnd) continue;
      if (best === undefined || b.offset >= best.offset) best = b;
    }
    return best;
  }

  /**
   * Initializer of a binding: `{ range, exact }` where `exact` means the range is the
   * whole value (declaration/assignment), or undefined for parameters, inherited names and
   * shapes that cannot be read back.
   */
  private bindingInit(
    st: TaintState,
    b: TaintState["bindings"][number],
  ): { range: Range; exact: boolean; destructured: boolean } | undefined {
    const src = this.f.src;
    const code = src.code;
    if (b.offset === st.span.start && st.span.kind !== "module") return undefined;
    for (let s = enclosingFunction(this.f.spans, b.offset); s !== undefined; s = s.parent)
      if (s.params.some((p) => p.start === b.offset)) return undefined;
    let i = b.offset;
    let destructured = false;
    if (code[i] === "{" || code[i] === "[") {
      const c = src.matchOf(i);
      if (c < 0) return undefined;
      i = c + 1;
      destructured = true;
    } else {
      const id = /^[A-Za-z_$][\w$]*/.exec(code.slice(i, i + 200));
      if (id === null) return undefined;
      i += id[0].length;
    }
    let member = false;
    for (let guard = 0; guard < 16; guard++) {
      const j = nextNonWs(code, i);
      if (code[j] === "." && /[A-Za-z_$]/.test(code[nextNonWs(code, j + 1)] ?? "")) {
        const k = nextNonWs(code, j + 1);
        const id = /^[A-Za-z_$][\w$]*/.exec(code.slice(k, k + 200))!;
        i = k + id[0].length;
        member = true;
      } else if (code[j] === "[" && !destructured) {
        member = true;
        const c = src.matchOf(j);
        if (c < 0) return undefined;
        i = c + 1;
      } else break;
    }
    let j = nextNonWs(code, i);
    if (code[j] === "(") {
      // mutation: `list.push(x)`
      const c = src.matchOf(j);
      return c < 0 ? undefined : { range: { start: j + 1, end: c }, exact: false, destructured };
    }
    if (code[j] === "!") j = nextNonWs(code, j + 1);
    if (code[j] === ":") j = nextNonWs(code, skipTypeForward(src, j + 1));
    if (/^(?:of|in)\b/.test(code.slice(j, j + 3))) {
      const open = enclosingOpen(src, b.offset);
      const close = open >= 0 && code[open] === "(" ? src.matchOf(open) : -1;
      return close > j
        ? { range: { start: j + 2, end: close }, exact: false, destructured }
        : undefined;
    }
    const op = /^(?:\+=|\|\|=|\?\?=|=(?![=>]))/.exec(code.slice(j, j + 3));
    if (op === null) return undefined;
    const start = nextNonWs(code, j + op[0].length);
    const end = expressionEnd(src, start, st.span.bodyEnd);
    if (end <= start) return undefined;
    return { range: { start, end }, exact: op[0] === "=" && !member, destructured };
  }

  /** Allowlist lookups and verified payloads: the binding's value is not attacker-chosen. */
  private isSafeInit(st: TaintState, init: { range: Range; exact: boolean }, at: number): boolean {
    const src = this.f.src;
    const code = src.code;
    let r = trimRange(src, init.range);
    if (/^await\b/.test(code.slice(r.start, r.end)))
      r = trimRange(src, { start: r.start + 5, end: r.end });
    const seg = code.slice(r.start, r.end);
    if (WEBHOOK_VERIFY_RE.test(seg)) return true;
    // `LOOKUP.get(x) ?? "default"`, `LOOKUP[x] || "default"`
    const head = splitTopLevelOp(src, r, "??")[0] ?? r;
    const first = splitTopLevelOp(src, head, "||")[0] ?? head;
    const fseg = code.slice(first.start, first.end);
    const lookup = /^([A-Za-z_$][\w$]*)\s*(?:\.\s*(?:get|find)\s*\(|\[)/.exec(fseg);
    if (lookup !== null && this.isLiteralCollection(lookup[1]!)) {
      const open = first.start + lookup[0].length - 1;
      if (src.matchOf(open) === first.end - 1) return true;
    }
    return first.end === r.end && this.safeMapExpr(st, first, at);
  }

  /**
   * `items.map((x, i) => `$${i + 1}`)` with an optional literal `.join(",")`: the callback's
   * result does not carry the element, so the expression is placeholders only.
   */
  private safeMapExpr(st: TaintState, first: Range, at: number): boolean {
    const src = this.f.src;
    const code = src.code;
    const fseg = code.slice(first.start, first.end);
    const arrayFrom = /^Array\s*\.\s*from\s*\(/.exec(fseg);
    const map = arrayFrom ?? /^[A-Za-z_$][\w$.]*\s*\.\s*map\s*\(/.exec(fseg);
    if (map === null) return false;
    const open = first.start + map[0].length - 1;
    const close = src.matchOf(open);
    if (close < 0) return false;
    const tail = code.slice(close + 1, first.end);
    const joined = /^\s*\.\s*join\s*\(\s*(?:"[^"\\]*"|'[^'\\]*'|`[^`$\\]*`)?\s*\)\s*$/.test(tail);
    if (close !== first.end - 1 && !joined) return false;
    // `Array.from(items, cb)` / `Array.from({ length: n }, cb)`: the callback is the second argument
    const cbRaw = arrayFrom === null ? open + 1 : (splitArgs(src, open, close)[1]?.start ?? -1);
    const cbStart = cbRaw < 0 ? -1 : nextNonWs(code, cbRaw);
    const cb = this.f.spans.find((s) => s.start === cbStart);
    if (cb === undefined || !this.budget()) return false;
    const returns = this.returnRanges(cb);
    if (returns.length === 0) return false;
    if (cb.params.length > 0) {
      const seeded = analyzeTaint(src, cb, { runtime: this.f.runtime, seedParams: [0] });
      if (!returns.every((x) => this.effective(seeded, x, at, MAX_DEPTH).length === 0))
        return false;
    }
    return !this.closureTaintIn(st, returns, at);
  }
  /** Whether any of `ranges` uses a tainted binding of the enclosing analysis. */
  private closureTaintIn(st: TaintState, ranges: Range[], at: number): boolean {
    return ranges.some((r) => this.effective(st, r, at, MAX_DEPTH).length > 0);
  }

  /** Ranges of the values a function returns (expression body or `return x` statements). */
  private returnRanges(span: FunctionSpan): Range[] {
    const src = this.f.src;
    if (span.expressionBody) return [{ start: span.bodyStart, end: span.bodyEnd }];
    const out: Range[] = [];
    const inner = this.f.spans.filter(
      (s) => s.start > span.start && s.end <= span.end && s.parent === span,
    );
    const re = /\breturn\b/g;
    re.lastIndex = span.bodyStart;
    for (let m = re.exec(src.code); m !== null && m.index < span.bodyEnd; m = re.exec(src.code)) {
      if (inner.some((s) => m!.index >= s.start && m!.index < s.end)) continue;
      const start = nextNonWs(src.code, m.index + 6);
      out.push({ start, end: expressionEnd(src, start, span.bodyEnd) });
    }
    return out;
  }

  /**
   * True when `name` is a module-level `const` holding only literals: a `new Map([...])`
   * of literal pairs, an object literal with literal values, or an array of literals.
   */
  private isLiteralCollection(name: string): boolean {
    const cached = this.literalCollections.get(name);
    if (cached !== undefined) return cached;
    const src = this.f.src;
    const code = src.code;
    let ok = false;
    const re = new RegExp(String.raw`\bconst\s+${escapeRe(name)}\s*(?::[^=;]{0,200})?=\s*`, "g");
    for (let m = re.exec(code); m !== null; m = re.exec(code)) {
      if (enclosingFunction(this.f.spans, m.index) !== undefined) continue;
      let i = m.index + m[0].length;
      const call = /^(?:Object\s*\.\s*freeze\s*\(|new\s+Map\s*(?:<[^>()]*>)?\s*\()/.exec(
        code.slice(i, i + 80),
      );
      if (call !== null) i = nextNonWs(code, i + call[0].length);
      if (code[i] !== "{" && code[i] !== "[") break;
      const close = src.matchOf(i);
      if (close < 0) break;
      const body = code
        .slice(i, close + 1)
        .replace(/(["'`])[^"'`\n]*\1/g, "S")
        .replace(/\bas\s+const\b/g, "");
      ok =
        !/[(`$]/.test(body) &&
        /^[\s{}[\]:,S\w.-]*$/.test(body) &&
        !/\b[a-z_$][\w$]*\s*\./.test(body);
      // values must be literals or constant-like identifiers, never lower-case expressions
      if (ok && code[i] === "{")
        ok = !/:\s*[a-z_$][\w$]*\s*[,}]/.test(body.replace(/:\s*(?:true|false|null)\b/g, ":S"));
      break;
    }
    this.literalCollections.set(name, ok);
    return ok;
  }

  // ---- guards ----

  private ifStatements(st: TaintState): IfStatement[] {
    const key = `${st.span.start}:${st.span.end}`;
    const cached = this.ifs.get(key);
    if (cached !== undefined) return cached;
    const src = this.f.src;
    const code = src.code;
    const out: IfStatement[] = [];
    const re = /\bif\s*\(/g;
    re.lastIndex = st.span.bodyStart;
    for (let m = re.exec(code); m !== null && m.index < st.span.bodyEnd; m = re.exec(code)) {
      const open = m.index + m[0].length - 1;
      const close = src.matchOf(open);
      if (close < 0) continue;
      const body = nextNonWs(code, close + 1);
      let block: Range | undefined;
      let exits: boolean;
      if (code[body] === "{") {
        const end = src.matchOf(body);
        block = end > body ? { start: body, end } : undefined;
        exits =
          block !== undefined &&
          /\b(?:return|throw|notFound\s*\(|redirect\s*\(|continue|process\s*\.\s*exit)\b/.test(
            code.slice(body, block.end),
          );
      } else {
        exits =
          /^(?:return\b|throw\b|notFound\s*\(|redirect\s*\(|continue\b|process\s*\.\s*exit\s*\()/.test(
            code.slice(body, body + 16),
          );
      }
      out.push({ offset: m.index, cond: { start: open + 1, end: close }, exits, block });
    }
    this.ifs.set(key, out);
    return out;
  }

  /** An `if` before `at` exits early unless `name` passes a check that fits this sink, or `at` sits in a guarded block. */
  private guarded(st: TaintState, name: string, at: number): boolean {
    for (const s of this.ifStatements(st)) {
      if (s.offset >= at) break;
      if (s.cond.end <= at && s.exits && this.condGuards(s.cond, name, "exit", st)) return true;
      if (
        s.block !== undefined &&
        s.block.start < at &&
        at < s.block.end &&
        this.condGuards(s.cond, name, "enter", st)
      )
        return true;
    }
    return false;
  }

  /**
   * Whether the condition at `cond` checks `name` in a way that makes it safe for this
   * sink kind. `exit`: the code after `if (cond) return` runs only when the check passed
   * (`!ALLOWED.includes(x)`); `enter`: the guarded block runs only when it passed.
   * Scheme-only regexes never guard SSRF; `startsWith("http")` never guards a redirect.
   */
  condGuards(
    cond: Range,
    name: string | undefined,
    mode: "exit" | "enter",
    st?: TaintState,
  ): boolean {
    if (name === undefined) return false;
    const src = this.f.src;
    const code = src.code.slice(cond.start, cond.end);
    const text = src.text.slice(cond.start, cond.end);
    const n = name
      .split(".")
      .map((p) => escapeRe(p))
      .join(String.raw`\s*\??\.\s*`);
    const N = String.raw`(?<![.\w$])${n}(?![\w$])`;
    if (!new RegExp(N).test(code)) return false;
    const neg = mode === "exit" ? String.raw`!\s*` : String.raw`(?<!!\s*)`;
    const kind = this.kind;

    // allowlist membership: `!ALLOWED.includes(x)`, `!allowed.has(x)`
    if (new RegExp(String.raw`${neg}[\w$.]+\s*\.\s*(?:includes|has)\s*\(\s*${N}\s*[,)]`).test(code))
      return true;
    // equality with a literal: `x !== "a"` (exit) / `x === "a"` (enter)
    const eq = mode === "exit" ? "!==?" : "===?";
    if (new RegExp(String.raw`(?<!typeof\s+)${N}\s*${eq}\s*["'\x60]`).test(code)) return true;
    // regex test: `!/^[a-z]+$/.test(x)` or `!SAFE_RE.test(x)`
    const reTest = new RegExp(
      String.raw`${neg}(\/(?:[^/\\\n[]|\\.|\[(?:[^\]\\\n]|\\.)*\])+\/[a-z]*|[\w$.]+)\s*\.\s*test\s*\(\s*${N}`,
    ).exec(text);
    if (reTest !== null && new RegExp(N).test(code)) {
      const lit = reTest[1]!;
      const source = lit.startsWith("/") ? regexLiteralSource(lit) : this.namedRegexSource(lit);
      if (source === undefined) {
        if (kind !== "ssrf" && kind !== "redirect") return true;
      } else if (kind === "ssrf") {
        if (isHostRegex(source)) return true;
      } else if (kind === "redirect") {
        if (isRelativePathRegex(source)) return true;
      } else if (isStrictRegex(source)) return true;
    }
    // validator calls: `!isAllowedHost(x)`, `!isSafeRedirect(x)`
    const validator = new RegExp(
      String.raw`${neg}(?:await\s+)?[\w$.]*?\b((?:is|valid|check|safe|allowed|assert|verify)\w*)\s*\(([^()]|\([^()]*\))*?${N}`,
      "i",
    ).exec(code);
    if (validator !== null) {
      const fn = validator[1]!;
      if (kind === "ssrf") {
        if (
          /allow|safe|trust|internal|private|public|permit|whitelist|block|external|host/i.test(fn)
        )
          return true;
      } else if (kind === "redirect") {
        if (/safe|allow|relative|same|local|internal|trust|redirect|path/i.test(fn)) return true;
      } else if (!/^is(?:NaN|Array|String|Object)$/i.test(fn)) return true;
    }
    if (kind === "path") {
      if (/\.\.|\bisAbsolute\s*\(|\brelative\s*\(/.test(text)) return true;
      // a literal-prefix check passes `uploads/../x`; only a normalized value counts
      if (/\bstartsWith\s*\(\s*(?!["'`])/.test(text)) return true;
      if (st !== undefined && this.startsWithOnResolved(st, code, text, name, cond.start))
        return true;
    }
    if (kind === "redirect") {
      const rootOnly = /startsWith\s*\(\s*(["'`])\/\1\s*\)/.test(text);
      const noDouble = /(["'`])(?:\/\/|\/\\\\|\\\\)\1/.test(text);
      if (rootOnly && noDouble) return true;
      if (
        /\.\s*(?:origin|host|hostname)\b[^&|]*(?:===?|!==?)|(?:===?|!==?)[^&|]*\.\s*(?:origin|host|hostname)\b/.test(
          code,
        )
      )
        return true;
    }
    if (kind === "ssrf") {
      if (
        /\b(?:hostname|host|origin)\b/.test(code) &&
        /\b(?:includes|has|endsWith)\s*\(|===?|!==?/.test(code)
      )
        return true;
    }
    return false;
  }

  /** `<name>.startsWith(<literal>)` where `name` is bound to path.resolve/normalize/realpath. */
  private startsWithOnResolved(
    st: TaintState,
    code: string,
    text: string,
    name: string,
    at: number,
  ): boolean {
    const recv = new RegExp(String.raw`(?<![.\w$])${escapeRe(name)}\s*\.\s*startsWith\s*\(`);
    // inline: `path.resolve(root, name).startsWith("/srv/uploads/")`
    if (
      /\b(?:resolve|normalize|realpath(?:Sync)?)\s*\([^()]*\)\s*\.\s*startsWith\s*\(\s*["'`]/.test(
        text,
      )
    )
      return true;
    if (!recv.test(code)) return false;
    const b = this.visibleBinding(st, name, at);
    const init = b === undefined ? undefined : this.bindingInit(st, b);
    if (init === undefined || !init.exact) return false;
    const seg = this.f.src.code.slice(init.range.start, init.range.end);
    return /^(?:await\s+)?(?:[\w$]+\s*\.\s*)*(?:resolve|normalize|realpath(?:Sync)?)\s*\(/.test(
      seg,
    );
  }

  private namedRegexSource(name: string): string | undefined {
    if (!/^[A-Za-z_$][\w$]*$/.test(name)) return undefined;
    const m = new RegExp(
      String.raw`\b${escapeRe(name)}\s*=\s*(\/(?:[^/\\\n[]|\\.|\[(?:[^\]\\\n]|\\.)*\])+\/[a-z]*)`,
    ).exec(this.f.src.text);
    return m ? regexLiteralSource(m[1]!) : undefined;
  }

  // ---- seeding ----

  /** Analysis of the callback at `at` with its element parameter seeded from a tainted receiver. */
  private callbackState(st: TaintState, at: number): TaintState | undefined {
    const src = this.f.src;
    const code = src.code;
    for (
      let s = enclosingFunction(this.f.spans, at);
      s !== undefined && s.start > st.span.start;
      s = s.parent
    ) {
      const p = prevNonWs(code, s.start - 1);
      const open = code[p] === "(" ? p : code[p] === "," ? enclosingOpen(src, p) : -1;
      if (open < 0 || code[open] !== "(") continue;
      const nameEnd = prevNonWs(code, open - 1);
      let k = nameEnd;
      while (k >= 0 && /[\w$]/.test(code[k]!)) k--;
      const method = code.slice(k + 1, nameEnd + 1);
      if (!CALLBACK_METHODS.has(method)) continue;
      const dot = prevNonWs(code, k);
      if (code[dot] !== ".") continue;
      const recvStart = this.receiverStart(dot);
      if (recvStart >= dot) continue;
      const recv = this.effective(st, { start: recvStart, end: dot }, at, 0);
      if (recv.length === 0) continue;
      if (!this.budget()) return undefined;
      const idx = method === "reduce" || method === "reduceRight" ? 1 : 0;
      const inherited = new Map(this.moduleTaint());
      for (const b of st.bindings) {
        if (b.hit === undefined || b.offset >= s.start) continue;
        if (s.start < b.scopeStart || s.start >= b.scopeEnd) continue;
        inherited.set(b.name, b.hit);
      }
      return analyzeTaint(src, s, {
        runtime: this.f.runtime,
        seedParams: [idx],
        seedSource: recv[0]!.hit.source,
        ...(inherited.size > 0 ? { inherited } : {}),
      });
    }
    return undefined;
  }

  /** Start of the member/call chain ending just before `dot` (`Object.entries(x)\n.filter(...)`). */
  private receiverStart(dot: number): number {
    const src = this.f.src;
    const code = src.code;
    let i = dot - 1;
    for (let guard = 0; guard < 64 && i >= 0; guard++) {
      i = prevNonWs(code, i);
      const c = code[i];
      if (c === ")" || c === "]") {
        const o = src.matchOf(i);
        if (o < 0) break;
        i = o - 1;
        continue;
      }
      if (c !== undefined && /[\w$]/.test(c)) {
        while (i >= 0 && /[\w$]/.test(code[i]!)) i--;
        const q = prevNonWs(code, i);
        if (code[q] === ".") {
          i = code[q - 1] === "?" ? q - 2 : q - 1;
          continue;
        }
        return i + 1;
      }
      break;
    }
    return dot;
  }

  /**
   * Seeds the parameters of the named function enclosing `at` from same-file call sites
   * whose arguments are tainted (depth ≤ 2: a caller's own parameters may be seeded once more).
   */
  private callerSeeded(
    range: Range,
    at: number,
    depth: number,
  ): { state: TaintState; hits: EffectiveHit[] } | undefined {
    if (depth >= 2) return undefined;
    const src = this.f.src;
    const code = src.code;
    let fn = enclosingFunction(this.f.spans, at);
    while (fn !== undefined && (fn.name === undefined || fn.params.length === 0)) fn = fn.parent;
    if (fn === undefined || fn.name === undefined || fn.name === "default") return undefined;
    const re = new RegExp(String.raw`(?<![\w$.])${escapeRe(fn.name)}\s*\(`, "g");
    for (let m = re.exec(code); m !== null; m = re.exec(code)) {
      const open = m.index + m[0].length - 1;
      if (open === fn.paramsStart) continue;
      if (m.index >= fn.start && m.index < fn.end) continue; // recursion
      const word = /([A-Za-z_$][\w$]*)\s*$/.exec(code.slice(Math.max(0, m.index - 12), m.index));
      if (word?.[1] === "function") continue;
      const close = src.matchOf(open);
      if (close < 0) continue;
      const args = splitArgs(src, open, close);
      for (let idx = 0; idx < Math.min(args.length, fn.params.length); idx++) {
        const arg = args[idx]!;
        let found = this.effective(this.stateAt(m.index), arg, m.index, 0);
        if (found.length === 0 && depth + 1 < 2) {
          const up = this.callerSeeded(arg, m.index, depth + 1);
          found = up?.hits ?? [];
        }
        if (found.length === 0) continue;
        const state = this.seededState(fn, [idx], found[0]!.hit.source);
        if (state === undefined) return undefined;
        const hits = this.effective(state, range, at, 0);
        if (hits.length > 0) return { state, hits };
      }
    }
    return undefined;
  }

  // ---- positions ----

  private pos(st: TaintState, r0: Range, at: number, depth: number): Position {
    const src = this.f.src;
    const code = src.code;
    let r = trimRange(src, r0);
    for (let g = 0; g < 4; g++) {
      if (/^await\b/.test(code.slice(r.start, r.start + 6)))
        r = trimRange(src, { start: r.start + 5, end: r.end });
      else if (code[r.start] === "(" && src.matchOf(r.start) === r.end - 1)
        r = trimRange(src, { start: r.start + 1, end: r.end - 1 });
      else break;
    }
    const asType = /\s+as\s+[\w$.<>[\]| ]+$/.exec(code.slice(r.start, r.end));
    if (asType !== null) r = trimRange(src, { start: r.start, end: r.end - asType[0].length });
    if (r.end <= r.start) return undefined;
    const seg = code.slice(r.start, r.end);
    if (this.isSelfOrigin(seg)) return "self";
    if (depth > 6) return this.effective(st, r, at, 0).length > 0 ? "whole" : undefined;

    const t = topLevelTernary(src, r);
    if (t !== undefined) {
      const a = this.condGuards(
        this.resolveCond(st, t.cond),
        this.firstName(t.whenTrue),
        "enter",
        st,
      )
        ? undefined
        : this.pos(st, t.whenTrue, at, depth + 1);
      return this.strongest(a, this.pos(st, t.whenFalse, at, depth + 1));
    }
    for (const op of ["??", "||"] as const) {
      const parts = splitTopLevelOp(src, r, op);
      if (parts.length > 1) {
        let best: Position;
        for (const p of parts) best = this.strongest(best, this.pos(st, p, at, depth + 1));
        return best;
      }
    }
    const plus = splitTopLevel(src, r, "+");
    if (plus.length > 1)
      return this.compose(
        st,
        plus.map((p) =>
          code[p.start] === '"' || code[p.start] === "'"
            ? { kind: "static" as const, range: { start: p.start + 1, end: p.end - 1 } }
            : { kind: "expr" as const, range: p },
        ),
        at,
        depth,
      );
    const tpl = templateParts(src, r);
    if (tpl !== undefined) return this.compose(st, tpl, at, depth);
    if (code[r.start] === '"' || code[r.start] === "'") return undefined;

    const url = /^new\s+URL\s*\(/.exec(seg);
    if (url !== null) {
      const open = r.start + url[0].length - 1;
      const close = src.matchOf(open);
      if (close === r.end - 1) {
        const args = splitArgs(src, open, close);
        const a = args[0] ? this.pos(st, args[0], at, depth + 1) : undefined;
        if (a !== undefined && a !== "self") return a;
        const b = args[1] ? this.pos(st, args[1], at, depth + 1) : undefined;
        return b === undefined ? a : b;
      }
    }
    const wrap = /^(?:String|encodeURI|decodeURIComponent|decodeURI)\s*\(/.exec(seg);
    if (wrap !== null) {
      const open = r.start + wrap[0].length - 1;
      if (src.matchOf(open) === r.end - 1)
        return this.pos(st, { start: open + 1, end: r.end - 1 }, at, depth + 1);
    }
    const toStr = /\.\s*(?:toString|href)\s*(?:\(\s*\))?$/.exec(seg);
    if (toStr !== null && toStr.index > 0)
      return this.pos(st, { start: r.start, end: r.start + toStr.index }, at, depth + 1);
    // request path members always start with `/` or `?`, so they cannot change the host
    if (
      /^(?:(?:req|request)\s*\.\s*(?:nextUrl\s*\.\s*)?(?:pathname|path|url|originalUrl|search)|[A-Za-z_$][\w$]*\s*\.\s*nextUrl\s*\.\s*(?:pathname|search))$/.test(
        seg,
      )
    )
      return "url-path";
    const originMember = /^([A-Za-z_$][\w$]*)\s*\.\s*(?:origin|host|hostname|protocol)$/.exec(seg);
    if (originMember !== null) {
      const p = this.pos(
        st,
        { start: r.start, end: r.start + originMember[1]!.length },
        at,
        depth + 1,
      );
      if (p === "self" || p === undefined) return p;
      return "whole";
    }

    const hits = this.effective(st, r, at, 0);
    if (hits.length === 0) return undefined;
    if (/^[A-Za-z_$][\w$]*$/.test(seg)) {
      const b = this.visibleBinding(st, seg, r.start);
      const init = b === undefined ? undefined : this.bindingInit(st, b);
      if (init === undefined || !init.exact) return "whole";
      const p = this.pos(st, init.range, at, depth + 1);
      if (init.destructured && p === "self")
        return /^(?:origin|host|hostname|protocol)$/.test(seg) ? "self" : "whole";
      return p ?? "whole";
    }
    return "whole";
  }

  private firstName(r: Range): string | undefined {
    const m = /^[A-Za-z_$][\w$]*/.exec(this.f.src.code.slice(r.start, r.end));
    return m?.[0];
  }

  private compose(
    st: TaintState,
    parts: { kind: "static" | "expr"; range: Range }[],
    at: number,
    depth: number,
  ): Position {
    const src = this.f.src;
    let prefix = "";
    let best: Position;
    let selfFirst = false;
    parts.forEach((part, i) => {
      if (part.kind === "static") {
        prefix += src.text.slice(part.range.start, part.range.end);
        return;
      }
      const p = this.pos(st, part.range, at, depth + 1);
      if (p === undefined) prefix += "X";
      else if (p === "self") {
        if (i === 0) selfFirst = true;
        prefix += prefix === "" ? "https://self" : "X";
      } else {
        best = this.strongest(best, taintPosition(prefix, p));
        prefix += "X";
      }
    });
    if (best === undefined && selfFirst) return "self";
    return best;
  }

  private strongest(a: Position, b: Position): Position {
    if (a === undefined || a === "self") return b === undefined ? a : b;
    if (b === undefined || b === "self") return a;
    return strongerPosition(a, b);
  }

  /** The request's own URL or origin (`req.nextUrl`, `request.url`, `new URL(req.url).origin`). */
  private isSelfOrigin(seg: string): boolean {
    const s = seg.replace(/\s+/g, "");
    return /^(?:req|request)\.(?:nextUrl|url)(?:\.(?:origin|href))?$|^newURL\((?:req|request)\.(?:url|nextUrl)\)(?:\.origin)?$|^(?:req|request)\.nextUrl\.(?:host|hostname|protocol)$/.test(
      s,
    );
  }
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

/** Max findings of one rule in one file before they are summarised. */
export const MAX_FINDINGS_PER_RULE_PER_FILE = 25;

/** One medium-confidence finding standing for `rest` (same rule, same file). */
export function summaryOf(ruleId: string, rest: Finding[]): Finding {
  const first = rest[0]!;
  return makeFinding({
    category: first.category,
    ruleId,
    title: `${first.title} (${rest.length} more in this file)`,
    severity: first.severity === "critical" ? "high" : first.severity,
    confidence: "medium",
    file: first.file,
    discriminator: "summary",
    plainEnglishProblem: `${rest.length} more places in this file have the same problem. ${first.plainEnglishProblem}`,
    whyItMatters: first.whyItMatters,
    fixSteps: first.fixSteps,
    aiFixPrompt: first.aiFixPrompt ?? "",
    learnMoreUrl: first.learnMoreUrl,
  });
}

/**
 * Keeps at most {@link MAX_FINDINGS_PER_RULE_PER_FILE} findings per rule for one file and
 * replaces the rest with one summary built by `summarize(rest)` (medium confidence).
 */
export function capPerRule(
  findings: Finding[],
  summarize: (ruleId: string, rest: Finding[]) => Finding = summaryOf,
): Finding[] {
  const byRule = new Map<string, Finding[]>();
  for (const f of findings) {
    const list = byRule.get(f.ruleId) ?? [];
    list.push(f);
    byRule.set(f.ruleId, list);
  }
  const out: Finding[] = [];
  for (const [ruleId, list] of byRule) {
    if (list.length <= MAX_FINDINGS_PER_RULE_PER_FILE) {
      out.push(...list);
      continue;
    }
    out.push(...list.slice(0, MAX_FINDINGS_PER_RULE_PER_FILE));
    out.push(summarize(ruleId, list.slice(MAX_FINDINGS_PER_RULE_PER_FILE)));
  }
  return out;
}

/** Stable finding discriminator: column within the line plus callee, so edits elsewhere in the file keep the id. */
export function callKey(src: JsSource, offset: number, callee: string): string {
  const lineStart = src.code.lastIndexOf("\n", offset - 1) + 1;
  return `${offset - lineStart}:${callee}`;
}

/** Evidence line and anchor for a sink: the line of the first tainted offset inside the call, else the call line. */
export function sinkAnchor(
  src: JsSource,
  call: SinkCall,
  offset: number | undefined,
): { line: number; endLine: number | undefined; evidence: string } {
  const line =
    offset !== undefined && offset >= call.start && offset <= call.close
      ? src.lineAt(offset)
      : call.line;
  const last = src.lineAt(call.close);
  return {
    line,
    endLine: last > line ? last : undefined,
    evidence: src.lineText(line).trim(),
  };
}
