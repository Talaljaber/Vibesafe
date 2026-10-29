import path from "node:path";
import type { Finding, ProjectContext, ScanContext } from "@talaljaber/vibesafe-shared";
import { classifyFile, isClientScope, isJsLike, type FileClassification } from "./file-kind.js";
import {
  enclosingFunction,
  expressionEnd,
  extractFunctions,
  moduleSpan,
  type FunctionSpan,
} from "./js-functions.js";
import { getJsSource, type JsSource } from "./js-source.js";
import { analyzeTaint, type TaintHit } from "./taint.js";

/**
 * Shared helpers for the client-runtime detectors (`groups/client.ts`): loading client
 * files, taint queries with same-file parameter seeding, same-project import resolution,
 * declaration backtracking and small expression helpers over masked code.
 *
 * Client detectors run on files whose {@link classifyFile} runtime is `client`; the
 * server-side detectors (injection) run on every other JS file, so a sink is never
 * reported by both.
 */

/** A client file prepared for analysis. */
export interface ClientFile {
  file: string;
  src: JsSource;
  classification: FileClassification;
  spans: FunctionSpan[];
}

export interface LoadClientFileOptions {
  /** Cheap text prefilter: the file is skipped (never masked) when it returns false. */
  prefilter?: ((text: string) => boolean) | undefined;
  /**
   * Also accept App Router server components (`next-server-component`). Only for JSX
   * attribute sinks, which render into the browser whatever runtime built them.
   */
  allowServerComponents?: boolean | undefined;
}

/**
 * Loads `file` when it is client-runtime JS (see the module comment); undefined for
 * server/script/unknown files, generated files and, unless `includeTests`, tests and
 * fixtures. Never throws.
 */
export async function loadClientFile(
  context: ScanContext,
  file: string,
  options: LoadClientFileOptions = {},
): Promise<ClientFile | undefined> {
  try {
    if (!isJsLike(file)) return undefined;
    const text = await context.readFile(file);
    if (text === "" || (options.prefilter !== undefined && !options.prefilter(text))) {
      return undefined;
    }
    const classification = classifyFile(file, text, context.projectContext);
    if (classification.generated) return undefined;
    if (classification.testOrFixture && context.config?.includeTests !== true) return undefined;
    const accepted =
      isClientScope(classification) ||
      (options.allowServerComponents === true && classification.kind === "next-server-component");
    if (!accepted) return undefined;
    const src = await getJsSource(context, file);
    const spans = extractFunctions(src, classification);
    return { file, src, classification, spans };
  } catch {
    return undefined;
  }
}

/** Pages Router data functions run on the server even inside a client-runtime page file. */
const SERVER_ONLY_FUNCTION_RE = /^(?:getServerSideProps|getStaticProps|getStaticPaths)$/;

/** Outermost function containing `offset`, or the whole-file span for top-level code. */
export function outermostSpan(cf: ClientFile, offset: number): FunctionSpan {
  let s = enclosingFunction(cf.spans, offset);
  while (s?.parent !== undefined) s = s.parent;
  return s ?? moduleSpan(cf.src);
}

/** True when `offset` sits in a Pages Router server-side data function. */
export function inServerOnlyFunction(cf: ClientFile, offset: number): boolean {
  for (let s = enclosingFunction(cf.spans, offset); s !== undefined; s = s.parent) {
    if (s.name !== undefined && SERVER_ONLY_FUNCTION_RE.test(s.name)) return true;
  }
  return false;
}

/** Taint runtime for a loaded file: client sources in client files, server sources otherwise. */
function runtimeOf(cf: ClientFile): "client" | "server" {
  return cf.classification.runtime === "client" ? "client" : "server";
}

const MAX_SEED_PARAMS = 4;
const MAX_CALL_SITES = 10;
const MAX_SEED_DEPTH = 2;
const SEED_BUDGET = new WeakMap<JsSource, { left: number }>();

function seedBudget(src: JsSource): { left: number } {
  let b = SEED_BUDGET.get(src);
  if (b === undefined) {
    b = { left: 50 };
    SEED_BUDGET.set(src, b);
  }
  return b;
}

/**
 * Strongest taint reaching `[start, end)`: first from the outermost function containing
 * the range (closures inside components see the component's bindings), then, when the
 * range reads a parameter of a named function, from that function's call sites in the
 * same file (depth <= 2, result path `indirect`). Never throws.
 */
export function clientTaint(
  cf: ClientFile,
  start: number,
  end: number,
  depth = 0,
): TaintHit | undefined {
  try {
    const runtime = runtimeOf(cf);
    const outer = outermostSpan(cf, start);
    const hit = analyzeTaint(cf.src, outer, { runtime }).exprTaint(start, end);
    if (hit !== undefined) return hit;
    if (outer.kind !== "module") {
      // Module-level bindings read inside a function (`const code = location.hash` at the top).
      const top = analyzeTaint(cf.src, moduleSpan(cf.src), { runtime }).exprTaint(start, end);
      if (top !== undefined) return top;
    }
    if (depth >= MAX_SEED_DEPTH) return undefined;
    const budget = seedBudget(cf.src);
    for (let fn = enclosingFunction(cf.spans, start); fn !== undefined; fn = fn.parent) {
      if (fn.name === undefined || fn.params.length === 0) continue;
      for (let idx = 0; idx < Math.min(fn.params.length, MAX_SEED_PARAMS); idx++) {
        if (budget.left <= 0) return undefined;
        budget.left--;
        const seeded = analyzeTaint(cf.src, fn, { runtime, seedParams: [idx] }).exprTaint(
          start,
          end,
        );
        if (seeded === undefined) continue;
        for (const call of callSites(cf.src, fn.name, fn).slice(0, MAX_CALL_SITES)) {
          const arg = call.args[idx];
          if (arg === undefined) continue;
          const caller = clientTaint(cf, arg.start, arg.end, depth + 1);
          if (caller !== undefined) {
            return { ...caller, path: "indirect", offset: seeded.offset, via: seeded.via };
          }
        }
      }
    }
    return undefined;
  } catch {
    return undefined;
  }
}

export interface ArgRange {
  start: number;
  end: number;
}

/** Top-level argument ranges of the call whose `(` is at `open` (trimmed), or [] if unbalanced. */
export function callArgs(src: JsSource, open: number): ArgRange[] {
  const close = src.matchOf(open);
  if (close < 0) return [];
  const code = src.code;
  const out: ArgRange[] = [];
  let s = open + 1;
  for (let i = open + 1; i <= close; i++) {
    const c = code[i]!;
    if ((c === "(" || c === "[" || c === "{") && i < close) {
      const m = src.matchOf(i);
      if (m < 0 || m > close) return [];
      i = m;
      continue;
    }
    if (c === "," || i === close) {
      const r = trimRange(code, s, i);
      if (r.end > r.start) out.push(r);
      s = i + 1;
    }
  }
  return out;
}

function trimRange(code: string, start: number, end: number): ArgRange {
  let s = start;
  let e = end;
  while (s < e && /\s/.test(code[s]!)) s++;
  while (e > s && /\s/.test(code[e - 1]!)) e--;
  return { start: s, end: e };
}

/** Calls of `name(...)` in the file other than its own declaration. */
export function callSites(
  src: JsSource,
  name: string,
  declared?: FunctionSpan | undefined,
): { open: number; args: ArgRange[] }[] {
  const esc = name.replace(/\$/g, "\\$");
  const re = new RegExp(String.raw`(?<![\w$.])${esc}\s*\(`, "g");
  const out: { open: number; args: ArgRange[] }[] = [];
  for (let m = re.exec(src.code); m !== null; m = re.exec(src.code)) {
    const open = m.index + m[0].length - 1;
    if (declared !== undefined && open === declared.paramsStart) continue;
    if (/\bfunction\s*\*?\s*$/.test(src.code.slice(Math.max(0, m.index - 12), m.index))) continue;
    out.push({ open, args: callArgs(src, open) });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Expression helpers (all on masked code: string contents are blank, quotes kept)
// ---------------------------------------------------------------------------

/** True when masked code at `i` starts a string or template literal with literal text first. */
export function startsWithLiteral(code: string, i: number): boolean {
  const c = code[i];
  if (c === '"' || c === "'") return true;
  if (c === "`") return !(code[i + 1] === "$" && code[i + 2] === "{");
  return false;
}

/**
 * Ranges that decide the start (scheme/host) of the value in `[start, end)`: the first
 * operand of a `+` chain, the left side of `||`/`??` fallbacks, both branches of a
 * top-level ternary, or the first `${}` of a template that starts with one. A value that
 * starts with literal text yields no range.
 */
export function leadingOperands(src: JsSource, start: number, end: number, depth = 0): ArgRange[] {
  const code = src.code;
  const r = trimRange(code, start, end);
  if (r.end <= r.start || depth > 4) return [];
  let s = r.start;
  // Unwrap `(...)` around the whole value.
  if (code[s] === "(" && src.matchOf(s) === r.end - 1) {
    return leadingOperands(src, s + 1, r.end - 1, depth + 1);
  }
  // Top-level ternary: either branch may be the value.
  let q = -1;
  for (let i = s; i < r.end; i++) {
    const c = code[i]!;
    if (c === "(" || c === "[" || c === "{") {
      const m = src.matchOf(i);
      if (m < 0 || m >= r.end) break;
      i = m;
      continue;
    }
    if (c === "`") {
      const e = templateEnd(src, i, r.end);
      if (e < 0) break;
      i = e;
      continue;
    }
    if (c === "?" && code[i + 1] !== "." && code[i + 1] !== "?" && code[i - 1] !== "?") {
      q = i;
      break;
    }
  }
  if (q >= 0) {
    const colon = topLevelColon(src, q + 1, r.end);
    if (colon >= 0) {
      return [
        ...leadingOperands(src, q + 1, colon, depth + 1),
        ...leadingOperands(src, colon + 1, r.end, depth + 1),
      ];
    }
  }
  if (code[s] === "`") {
    if (code[s + 1] === "$" && code[s + 2] === "{") {
      const close = src.matchOf(s + 2);
      return close > s + 2 ? leadingOperands(src, s + 3, close, depth + 1) : [];
    }
    return [];
  }
  if (startsWithLiteral(code, s)) return [];
  // First operand up to a top-level `+`, `||`, `??` or `&&`.
  for (let i = s; i < r.end; i++) {
    const c = code[i]!;
    if (c === "(" || c === "[" || c === "{") {
      const m = src.matchOf(i);
      if (m < 0 || m >= r.end) return [{ start: s, end: r.end }];
      i = m;
      continue;
    }
    if (c === "`") {
      const e = templateEnd(src, i, r.end);
      if (e < 0) return [{ start: s, end: r.end }];
      i = e;
      continue;
    }
    const two = code.slice(i, i + 2);
    if ((c === "+" && code[i + 1] !== "+" && code[i + 1] !== "=") || two === "||" || two === "??") {
      return [trimRange(code, s, i)];
    }
    if (two === "&&") s = i + 2; // `ok && value`: the value is the right side
  }
  const t = trimRange(code, s, r.end);
  return t.end > t.start ? [t] : [];
}

function topLevelColon(src: JsSource, start: number, end: number): number {
  const code = src.code;
  let nested = 0;
  for (let i = start; i < end; i++) {
    const c = code[i]!;
    if (c === "(" || c === "[" || c === "{") {
      const m = src.matchOf(i);
      if (m < 0 || m >= end) return -1;
      i = m;
    } else if (c === "?" && code[i + 1] !== "." && code[i + 1] !== "?" && code[i - 1] !== "?") {
      nested++;
    } else if (c === ":") {
      if (nested === 0) return i;
      nested--;
    }
  }
  return -1;
}

function templateEnd(src: JsSource, open: number, limit: number): number {
  const code = src.code;
  for (let j = open + 1; j < limit; j++) {
    if (code[j] === "$" && code[j + 1] === "{") {
      const m = src.matchOf(j + 1);
      if (m < 0) return -1;
      j = m;
    } else if (code[j] === "`") return j;
  }
  return -1;
}

/** A plain member chain (`a.b?.c`, `a["b"]` excluded) or identifier, as segments; else undefined. */
export function memberChain(code: string, start: number, end: number): string[] | undefined {
  const text = code.slice(start, end).replace(/!+\s*$/, ""); // non-null assertions
  const m = /^\s*([A-Za-z_$][\w$]*)((?:\s*\??\.\s*[A-Za-z_$][\w$]*)*)\s*$/.exec(text);
  if (m === null) return undefined;
  const rest = (m[2] ?? "").split(/\s*\??\.\s*/).filter((p) => p !== "");
  return [m[1]!, ...rest];
}

/** Raw text of the string literal whose opening quote is at `quote` (undefined if not one). */
export function literalText(src: JsSource, quote: number): string | undefined {
  const q = src.code[quote];
  if (q !== '"' && q !== "'" && q !== "`") return undefined;
  for (let j = quote + 1; j < src.code.length; j++) {
    const c = src.code[j];
    if (c === q) return src.text.slice(quote + 1, j);
    if (q === "`" && c === "$" && src.code[j + 1] === "{") return undefined;
    if (c === "\n" && q !== "`") return undefined;
  }
  return undefined;
}

/** The single string literal that makes up `[start, end)`, or undefined. */
export function wholeLiteral(src: JsSource, start: number, end: number): string | undefined {
  const r = trimRange(src.code, start, end);
  const t = literalText(src, r.start);
  if (t === undefined) return undefined;
  return r.end - r.start === t.length + 2 ? t : undefined;
}

// ---------------------------------------------------------------------------
// Declarations
// ---------------------------------------------------------------------------

export interface Declaration {
  /** Offset of the declared name. */
  offset: number;
  /** Initializer range (empty when there is none). */
  initStart: number;
  initEnd: number;
  /** Declared through a destructuring pattern (`const { a } = obj`). */
  destructured: boolean;
}

/**
 * Nearest `const|let|var` declaration of `name` before `before` (plain or destructuring),
 * within `scope` when given. The declaration backtrace used to tell local literals and
 * config objects from data. Undefined when the name is a parameter or not declared.
 */
export function findDeclaration(
  src: JsSource,
  name: string,
  before: number,
  scope?: { start: number; end: number } | undefined,
): Declaration | undefined {
  const code = src.code;
  const esc = name.replace(/\$/g, "\\$");
  const from = scope?.start ?? 0;
  const plain = new RegExp(
    String.raw`\b(?:const|let|var)\s+(${esc})\s*(?::[^=;\n]{0,120})?=(?![=>])`,
    "g",
  );
  const destr = new RegExp(String.raw`\b(?:const|let|var)\s*([{[])`, "g");
  let best: Declaration | undefined;
  plain.lastIndex = from;
  for (let m = plain.exec(code); m !== null && m.index < before; m = plain.exec(code)) {
    const initStart = skipWs(code, m.index + m[0].length);
    best = {
      offset: m.index + /^(?:const|let|var)\s+/.exec(m[0])![0].length,
      initStart,
      initEnd: expressionEnd(src, initStart),
      destructured: false,
    };
  }
  destr.lastIndex = from;
  for (let m = destr.exec(code); m !== null && m.index < before; m = destr.exec(code)) {
    const open = m.index + m[0].length - 1;
    const close = src.matchOf(open);
    if (close < 0 || close >= before) continue;
    const pattern = code.slice(open, close + 1);
    if (!new RegExp(String.raw`(?<![\w$.])${esc}(?![\w$]|\s*:)`).test(pattern)) continue;
    const eq = /^\s*(?::[^=;\n]{0,120})?=(?![=>])/.exec(code.slice(close + 1, close + 140));
    if (eq === null) continue;
    if (best !== undefined && best.offset > m.index) continue;
    const initStart = skipWs(code, close + 1 + eq[0].length);
    best = { offset: open, initStart, initEnd: expressionEnd(src, initStart), destructured: true };
  }
  return best;
}

function skipWs(code: string, i: number): number {
  while (i < code.length && /\s/.test(code[i]!)) i++;
  return i;
}

/** `const [value, setValue] = useState(...)` pairs: setter name -> state name. */
export function useStatePairs(src: JsSource): Map<string, string> {
  const out = new Map<string, string>();
  const re =
    /\[\s*([A-Za-z_$][\w$]*)\s*,\s*([A-Za-z_$][\w$]*)\s*\]\s*=\s*(?:React\s*\.\s*)?use(?:State|LocalStorage|SessionStorage)\b/g;
  for (let m = re.exec(src.code); m !== null; m = re.exec(src.code)) out.set(m[2]!, m[1]!);
  return out;
}

/** Names bound to the result of one of `hooks` (`const router = useRouter()`). */
export function namesFromHooks(src: JsSource, hooks: RegExp): Set<string> {
  const out = new Set<string>();
  const re = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;\n]{0,80})?=\s*([\w$.]+)\s*\(/g;
  for (let m = re.exec(src.code); m !== null; m = re.exec(src.code)) {
    if (hooks.test(m[2]!)) out.add(m[1]!);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

export interface ImportBinding {
  /** Module specifier as written. */
  spec: string;
  /** Local name -> imported name (`default` for default imports, `*` for namespaces). */
  names: Map<string, string>;
  /** 1-indexed line of the import. */
  line: number;
}

/**
 * Value imports of a file. `import type ...` statements and `type` specifiers are skipped:
 * they are erased at compile time and never bring code into the client bundle.
 */
export function parseImports(src: JsSource): ImportBinding[] {
  const out: ImportBinding[] = [];
  const re = /\bimport\s+(?!type\b)([\w$*{},\s]+?)\s+from\s*(["'])/g;
  for (let m = re.exec(src.code); m !== null; m = re.exec(src.code)) {
    const quote = m.index + m[0].length - 1;
    const spec = literalText(src, quote);
    if (spec === undefined || spec === "") continue;
    const names = new Map<string, string>();
    const clause = m[1]!;
    const def = /^\s*([A-Za-z_$][\w$]*)\s*(?:,|$)/.exec(clause);
    if (def !== null) names.set(def[1]!, "default");
    const ns = /\*\s*as\s+([A-Za-z_$][\w$]*)/.exec(clause);
    if (ns !== null) names.set(ns[1]!, "*");
    const braces = /\{([^}]*)\}/.exec(clause);
    if (braces !== null) {
      for (const part of braces[1]!.split(",")) {
        const p = part.trim();
        if (p === "" || /^type\s/.test(p)) continue;
        const as = /^([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?$/.exec(p);
        if (as !== null) names.set(as[2] ?? as[1]!, as[1]!);
      }
    }
    if (names.size > 0) out.push({ spec, names, line: src.lineAt(m.index) });
  }
  return out;
}

const RESOLVE_EXTENSIONS = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"];

/**
 * Resolves a project-relative import (`./x`, `../x`, `@/x` -> project root or `src/x`) to
 * a file that `context.readFile` can read. Package imports resolve to undefined. Does not
 * rely on `context.files` (a `targetFiles` scan lists only the targets).
 */
export async function resolveImport(
  context: ScanContext,
  fromFile: string,
  spec: string,
): Promise<string | undefined> {
  const bases: string[] = [];
  const from = fromFile.replace(/\\/g, "/");
  if (spec.startsWith("./") || spec.startsWith("../")) {
    bases.push(path.posix.normalize(path.posix.join(path.posix.dirname(from), spec)));
  } else if (spec.startsWith("@/")) {
    bases.push(spec.slice(2), `src/${spec.slice(2)}`);
  } else {
    return undefined;
  }
  for (const base of bases) {
    if (base.startsWith("../")) continue;
    const candidates = /\.[cm]?[jt]sx?$/.test(base)
      ? [base]
      : [
          ...RESOLVE_EXTENSIONS.map((e) => base + e),
          ...RESOLVE_EXTENSIONS.map((e) => `${base}/index${e}`),
        ];
    for (const c of candidates) {
      try {
        if ((await context.readFile(c)) !== "") return c;
      } catch {
        // unreadable candidate
      }
    }
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

/** Major version of `react` from the project's dependencies, or undefined when unknown. */
export function reactMajor(
  projectContext: Pick<ProjectContext, "dependencies" | "devDependencies"> | undefined,
): number | undefined {
  const v = projectContext?.dependencies?.react ?? projectContext?.devDependencies?.react;
  if (typeof v !== "string") return undefined;
  const m = /(\d+)/.exec(v.replace(/^npm:[^@]*@/, ""));
  return m === null ? undefined : Number(m[1]);
}

/** Per-file cap for one rule: keeps the first `limit` findings and adds one summary. */
export function capPerFile(
  findings: Finding[],
  limit: number,
  summary: (dropped: number, first: Finding) => Finding,
): Finding[] {
  if (findings.length <= limit) return findings;
  const kept = findings.slice(0, limit);
  kept.push(summary(findings.length - limit, findings[limit]!));
  return kept;
}

/** Text of the raw source line containing `offset`, for evidence. */
export function lineOf(src: JsSource, offset: number): { line: number; text: string } {
  const line = src.lineAt(offset);
  return { line, text: src.lineText(line) };
}
