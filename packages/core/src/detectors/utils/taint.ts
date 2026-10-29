import type { Confidence, Severity } from "@talaljaber/vibesafe-shared";
import {
  PAGE_PROPS_SOURCE,
  PARAMETER_SOURCE,
  PASS_THROUGH_CALLS,
  ROUTE_PARAMS_SOURCE,
  SERVER_ACTION_SOURCE,
  TAINT_CLEANERS,
  requestMemberSource,
  sourcesForRuntime,
  type CleanerKind,
  type TaintRuntime,
  type TaintSource,
  type TaintTrust,
} from "../patterns/taint-sources.js";
import {
  calleeBefore,
  enclosingOpen,
  expressionEnd,
  extractFunctions,
  patternBindings,
  skipTypeForward,
  type FunctionSpan,
} from "./js-functions.js";
import type { JsSource } from "./js-source.js";

/**
 * Intra-function taint tracking over a {@link JsSource}, regex/bracket based.
 *
 * {@link analyzeTaint} walks one function span in source order, recording which local
 * bindings hold attacker-controlled data (request data on the server, the URL on the
 * client, argv in scripts), then answers "is this expression tainted?" for sink detectors.
 *
 * Paths (binding for confidence, see {@link taintConfidence}):
 * - `direct`: the source expression sits inside the queried range (the sink statement).
 * - `binding`: reached through `const`/`let`/destructuring/alias bindings or a
 *   pass-through call (`String(x)`, `path.join(...)`, template literals) in the same span.
 * - `indirect`: through a callback parameter, a closure, a seeded or inherited parameter,
 *   or the argument of an unknown (non-awaited) call.
 *
 * Numeric coercions (`Number(x)`, `parseInt`) and boolean expressions (comparisons,
 * `.includes(...)`, `.length`) clean taint. Other cleaners (`path.basename`,
 * `encodeURIComponent`, sanitizers, schema `.parse`) are recorded in `cleanedBy` so each
 * sink decides. The result of an awaited unknown call (`await db.find(id)`) is not tainted.
 */

export type TaintPath = "direct" | "binding" | "indirect";

export interface TaintHit {
  source: TaintSource;
  trust: TaintTrust;
  path: TaintPath;
  /** File offset of the tainted token in the queried range (source match or identifier). */
  offset: number;
  /** Local binding the taint came through, when not direct. */
  via: string | undefined;
  /** Non-numeric cleaners the value went through (empty when uncleaned). */
  cleanedBy: readonly CleanerKind[];
}

/** One (re)declaration of a local name: tainted (`hit`) or clean (`hit === undefined`). */
export interface TaintBinding {
  name: string;
  /** Offset of the declaration/assignment. */
  offset: number;
  /** Range of the function the binding lives in. */
  scopeStart: number;
  scopeEnd: number;
  hit: TaintHit | undefined;
}

/** A check on a name that returns/throws early, found before an offset. */
export interface TaintGuard {
  /**
   * - `allowlist`: `if (!ALLOWED.includes(x)) return`, `if (x !== "a") return`
   * - `regex`: `if (!/^[a-z]+$/.test(x)) throw ...`
   * - `validator`: `if (!isValidUrl(x)) return`
   * - `contains-check`: `if (x.includes("..")) return`
   * - `type-check`: `if (typeof x !== "string") return`
   */
  kind: "allowlist" | "regex" | "validator" | "contains-check" | "type-check";
  /** Offset of the `if`. */
  offset: number;
}

export interface TaintOptions {
  /** Default `server`. Selects the default sources. */
  runtime?: TaintRuntime | undefined;
  /** Replaces the runtime's default sources (disables memoization). */
  sources?: readonly TaintSource[] | undefined;
  /** Indexes of the span's parameters to treat as tainted (`indirect`; disables memoization). */
  seedParams?: readonly number[] | undefined;
  /** Source reported for seeded parameters (default: a label-only "function parameter"). */
  seedSource?: TaintSource | undefined;
  /** Names tainted in an enclosing scope (closure), e.g. from an outer analysis (`indirect`). */
  inherited?: ReadonlyMap<string, TaintHit> | undefined;
}

export interface TaintState {
  readonly span: FunctionSpan;
  readonly runtime: TaintRuntime;
  /** Every recorded (re)declaration in source order, tainted and clean. */
  readonly bindings: readonly TaintBinding[];
  /**
   * Strongest taint in the file range `[start, end)`, or undefined. Pass a sink's argument
   * range (not the whole call): calls inside the range are classified as cleaners,
   * pass-through or unknown. Order: `direct` > `binding` > `indirect`, then `remote` over
   * `local`, then uncleaned first.
   */
  exprTaint(start: number, end: number): TaintHit | undefined;
  /** Every taint hit in `[start, end)` (one per source match / tainted identifier). */
  exprTaints(start: number, end: number): TaintHit[];
  /** The tainted binding of `name` visible at `offset`, or undefined (unknown or clean). */
  bindingAt(name: string, offset: number): TaintBinding | undefined;
  /** An early-exit guard on `name` between the span body start and `offset`. */
  guardBefore(name: string, offset: number): TaintGuard | undefined;
}

/** Confidence for a taint path: `direct`/`binding` give `high`, `indirect` gives `medium`. */
export function taintConfidence(hit: Pick<TaintHit, "path">): Confidence {
  return hit.path === "indirect" ? "medium" : "high";
}

/** Caps `severity` at `high` for `local` trust (argv/stdin); `remote` is unchanged. */
export function capSeverityForTrust(severity: Severity, trust: TaintTrust): Severity {
  return trust === "local" && severity === "critical" ? "high" : severity;
}

const PATH_RANK: Readonly<Record<TaintPath, number>> = { direct: 0, binding: 1, indirect: 2 };
const CALLBACK_METHOD_RE =
  /\.(?:map|forEach|filter|flatMap|find|findLast|findIndex|some|every|reduce|reduceRight|sort|then)$/;
const BOOLEAN_METHOD_RE =
  /(?:^|\.)(?:includes|has|test|startsWith|endsWith|some|every|indexOf|lastIndexOf|findIndex|localeCompare|isArray|isInteger|isSafeInteger|isFinite|isNaN|is[A-Z]\w*)$/;
const NOT_CALL_RE =
  /^(?:if|for|while|switch|catch|return|typeof|function|await|yield|void|delete|in|of|new|case|throw|else|do)$/;
const MAX_HITS_PER_QUERY = 200;
const MEMO = new WeakMap<JsSource, Map<string, TaintState>>();

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
function wordBefore(code: string, i: number): string {
  const e = prevNonWs(code, i - 1);
  let s = e;
  while (s >= 0 && /[\w$]/.test(code[s]!)) s--;
  return code.slice(s + 1, e + 1);
}

function stronger(a: TaintHit | undefined, b: TaintHit): TaintHit {
  if (a === undefined) return b;
  const d = PATH_RANK[a.path] - PATH_RANK[b.path];
  if (d !== 0) return d < 0 ? a : b;
  if (a.trust !== b.trust) return a.trust === "remote" ? a : b;
  if ((a.cleanedBy.length === 0) !== (b.cleanedBy.length === 0))
    return a.cleanedBy.length === 0 ? a : b;
  return a.offset <= b.offset ? a : b;
}

interface CallContext {
  drop: boolean;
  boundary: boolean;
  cleaned: CleanerKind[];
}

function globalCopy(re: RegExp): RegExp {
  return new RegExp(re.source, re.flags.replace(/[gy]/g, "") + "g");
}

class Analysis {
  private readonly code: string;
  private readonly sources: { source: TaintSource; re: RegExp }[];
  private readonly entries = new Map<string, TaintBinding[]>();
  private readonly ordered: TaintBinding[] = [];
  private readonly inner: FunctionSpan[];

  constructor(
    private readonly src: JsSource,
    private readonly span: FunctionSpan,
    private readonly runtime: TaintRuntime,
    private readonly opts: TaintOptions,
  ) {
    this.code = src.code;
    const base = opts.sources ?? sourcesForRuntime(runtime);
    this.sources = [...base, ...this.roleSources()].map((source) => ({
      source,
      re: globalCopy(source.pattern),
    }));
    this.inner = extractFunctions(src).filter(
      (s) =>
        s.start >= span.start &&
        s.end <= span.end &&
        !(s.start === span.start && s.end === span.end),
    );
  }

  private roleSources(): TaintSource[] {
    if (this.opts.sources !== undefined || this.runtime !== "server") return [];
    const p0 = this.span.params[0];
    if (p0 === undefined || !/^[A-Za-z_$][\w$]*$/.test(p0.pattern)) return [];
    const name = p0.pattern;
    switch (this.span.role) {
      case "app-route-handler":
      case "pages-api-handler":
      case "express-handler":
      case "express-middleware":
      case "middleware":
        return name === "req" || name === "request" ? [] : [requestMemberSource(name)];
      case "page":
        return [
          {
            ...PAGE_PROPS_SOURCE,
            pattern: new RegExp(
              String.raw`(?<![.\w$])${name.replace(/\$/g, "\\$")}\s*\.\s*(?:params|searchParams|query)\b`,
            ),
          },
        ];
      default:
        return [];
    }
  }

  // ---- scopes and bindings ----

  private scopeOf(offset: number): { start: number; end: number } {
    let best: FunctionSpan | undefined;
    for (const s of this.inner) {
      if (s.start > offset) break;
      if (offset < s.end && (best === undefined || s.start >= best.start)) best = s;
    }
    return best ?? this.span;
  }

  private record(name: string, offset: number, hit: TaintHit | undefined, scope?: FunctionSpan) {
    const sc = scope ?? this.scopeOf(offset);
    const b: TaintBinding = { name, offset, scopeStart: sc.start, scopeEnd: sc.end, hit };
    let list = this.entries.get(name);
    if (list === undefined) {
      list = [];
      this.entries.set(name, list);
    }
    list.push(b);
    this.ordered.push(b);
  }

  visible(name: string, at: number): TaintBinding | undefined {
    const list = this.entries.get(name);
    if (list === undefined) return undefined;
    let best: TaintBinding | undefined;
    for (const b of list) {
      if (b.offset >= at || at < b.scopeStart || at >= b.scopeEnd) continue;
      if (best === undefined || b.offset >= best.offset) best = b;
    }
    return best;
  }

  private isClosure(b: TaintBinding, at: number): boolean {
    const sc = this.scopeOf(at);
    return sc.start !== b.scopeStart || sc.end !== b.scopeEnd;
  }

  // ---- expression taint ----

  private callContext(start: number, at: number): CallContext {
    const ctx: CallContext = { drop: false, boundary: false, cleaned: [] };
    const code = this.code;
    const stack: number[] = [];
    for (let i = Math.max(start, at - 8000); i < at; i++) {
      const c = code[i];
      if (c === "(" || c === "[" || c === "{") stack.push(i);
      else if (c === ")" || c === "]" || c === "}") stack.pop();
    }
    for (const open of stack) {
      if (code[open] !== "(") continue;
      const callee = calleeBefore(code, open);
      if (callee === undefined || NOT_CALL_RE.test(callee.name)) continue;
      const name = callee.name;
      const cleaner = TAINT_CLEANERS.find((c) => c.callee.test(name));
      if (cleaner !== undefined) {
        if (cleaner.kind === "numeric") ctx.drop = true;
        else if (!ctx.cleaned.includes(cleaner.kind)) ctx.cleaned.push(cleaner.kind);
        continue;
      }
      if (BOOLEAN_METHOD_RE.test(name) && name.includes(".")) {
        ctx.drop = true; // `allowed.includes(x)` yields a boolean
        continue;
      }
      if (PASS_THROUGH_CALLS.some((re) => re.test(name))) continue;
      if (wordBefore(code, callee.start) === "await") ctx.drop = true;
      else ctx.boundary = true;
    }
    return ctx;
  }

  exprTaints(start: number, end: number): TaintHit[] {
    const out: TaintHit[] = [];
    if (end <= start) return out;
    const code = this.code;
    const seg = code.slice(start, end);
    for (const { source, re } of this.sources) {
      re.lastIndex = 0;
      for (let m = re.exec(seg); m !== null; m = re.exec(seg)) {
        if (m[0] === "") re.lastIndex++;
        if (out.length >= MAX_HITS_PER_QUERY) return out;
        const at = start + m.index;
        const ctx = this.callContext(start, at);
        if (ctx.drop) continue;
        out.push({
          source,
          trust: source.trust,
          path: ctx.boundary ? "indirect" : "direct",
          offset: at,
          via: undefined,
          cleanedBy: ctx.cleaned,
        });
      }
    }
    if (this.entries.size === 0) return out;
    const idRe = /[A-Za-z_$][\w$]*/g;
    for (let m = idRe.exec(seg); m !== null; m = idRe.exec(seg)) {
      const name = m[0];
      if (!this.entries.has(name)) continue;
      if (out.length >= MAX_HITS_PER_QUERY) break;
      const at = start + m.index;
      const p = prevNonWs(code, at - 1);
      if (code[p] === "." && !(code[p - 1] === "." && code[p - 2] === ".")) continue;
      const nx = nextNonWs(code, at + name.length);
      if (code[nx] === ":" && code[nx + 1] !== ":" && (code[p] === "{" || code[p] === ","))
        continue; // object key
      if (wordBefore(code, at) === "typeof") continue;
      const b = this.visible(name, at);
      if (b?.hit === undefined) continue;
      const ctx = this.callContext(start, at);
      if (ctx.drop) continue;
      let path = b.hit.path;
      if (ctx.boundary || (path !== "indirect" && this.isClosure(b, at))) path = "indirect";
      const cleanedBy = [...b.hit.cleanedBy];
      for (const k of ctx.cleaned) if (!cleanedBy.includes(k)) cleanedBy.push(k);
      out.push({ ...b.hit, path, offset: at, via: name, cleanedBy });
    }
    return out;
  }

  exprTaint(start: number, end: number): TaintHit | undefined {
    let best: TaintHit | undefined;
    for (const h of this.exprTaints(start, end)) best = stronger(best, h);
    return best;
  }

  /** Taint carried by an initializer/assigned value into a binding. */
  private valueTaint(start: number, end: number, depth = 0): TaintHit | undefined {
    const code = this.code;
    const s = nextNonWs(code, start);
    if (s >= end) return undefined;
    const tern = depth < 4 ? this.topLevelTernary(s, end) : undefined;
    if (tern !== undefined) {
      const a = this.valueTaint(tern.q + 1, tern.colon, depth + 1);
      const b = this.valueTaint(tern.colon + 1, end, depth + 1);
      return a === undefined ? b : b === undefined ? a : stronger(a, b);
    }
    if (this.isBooleanOrNumeric(s, end)) return undefined;
    if (this.inner.some((f) => f.start === s)) return undefined; // a function value, not data
    const hit = this.exprTaint(s, end);
    if (hit === undefined) return undefined;
    return { ...hit, path: hit.path === "indirect" ? "indirect" : "binding" };
  }

  private topLevelTernary(start: number, end: number): { q: number; colon: number } | undefined {
    const code = this.code;
    let q = -1;
    let nested = 0;
    for (let i = start; i < end; i++) {
      const c = code[i]!;
      if (c === "(" || c === "[" || c === "{") {
        const m = this.src.matchOf(i);
        if (m < 0 || m >= end) return undefined;
        i = m;
      } else if (c === "?" && code[i + 1] !== "." && code[i + 1] !== "?" && code[i - 1] !== "?") {
        if (q < 0) q = i;
        else nested++;
      } else if (c === ":" && q >= 0) {
        if (nested === 0) return { q, colon: i };
        nested--;
      }
    }
    return undefined;
  }

  private isBooleanOrNumeric(start: number, end: number): boolean {
    const code = this.code;
    if (code[start] === "!") return true;
    if (/^typeof\b/.test(code.slice(start, start + 7))) return true;
    for (let i = start; i < end; i++) {
      const c = code[i]!;
      if (c === "(" || c === "[" || c === "{") {
        const m = this.src.matchOf(i);
        if (m < 0 || m >= end) return false;
        i = m;
        continue;
      }
      if (c === "`") {
        let j = i + 1;
        while (j < end && code[j] !== "`") {
          if (code[j] === "$" && code[j + 1] === "{") {
            const m = this.src.matchOf(j + 1);
            if (m < 0) return false;
            j = m;
          }
          j++;
        }
        i = j;
        continue;
      }
      if (c === "=" && code[i + 1] === "=") return true;
      if (c === "!" && code[i + 1] === "=") return true;
      if ((c === "<" || c === ">") && code[i - 1] !== "=" && code[i + 1] !== ">") {
        const generic = c === "<" ? /^<[\w$.,\s[\]|&<>]*>\s*\(/.exec(code.slice(i, i + 200)) : null;
        if (generic !== null) {
          i += generic[0].lastIndexOf(">");
          continue;
        }
        return true;
      }
      if (/[\w$]/.test(c) && !/[\w$]/.test(code[i - 1] ?? "")) {
        const w = /^[\w$]+/.exec(code.slice(i, i + 20))![0];
        if (w === "instanceof" || w === "in") return true;
        if (w === "as" || w === "satisfies") break; // the rest is a type
        i += w.length - 1;
      }
    }
    const last = prevNonWs(code, end - 1);
    if (code[last] === ")") {
      const open = this.src.matchOf(last);
      const callee = open >= 0 ? calleeBefore(code, open) : undefined;
      if (callee !== undefined && BOOLEAN_METHOD_RE.test(callee.name))
        return (
          callee.name.includes(".") || code[callee.start] === "." || /^is[A-Z]/.test(callee.name)
        );
    }
    return /\.\s*(?:length|size)\s*$/.test(code.slice(Math.max(start, last - 20), last + 1));
  }

  // ---- events ----

  run(): void {
    const { span, code, opts } = this;
    for (const [name, hit] of opts.inherited ?? new Map<string, TaintHit>())
      this.record(name, span.start, { ...hit, path: "indirect" }, span);
    const seeded = new Set(opts.seedParams ?? []);
    const roleSeed = this.roleSeed();
    span.params.forEach((p, idx) => {
      for (const n of p.names) {
        let hit: TaintHit | undefined;
        if (seeded.has(idx))
          hit = this.seedHit(opts.seedSource ?? PARAMETER_SOURCE, p.start, "indirect");
        else if (roleSeed !== undefined && roleSeed.match(idx, n))
          hit = this.seedHit(roleSeed.source, p.start, "binding");
        this.record(n, p.start, hit, span);
      }
    });

    const events: { at: number; run: () => void }[] = [];
    const from = span.bodyStart;
    const to = Math.min(span.bodyEnd, code.length);
    const add = (re: RegExp, fn: (m: RegExpExecArray) => void): void => {
      re.lastIndex = from;
      for (let m = re.exec(code); m !== null && m.index < to; m = re.exec(code)) {
        const mm = m;
        events.push({ at: mm.index, run: () => fn(mm) });
      }
    };
    add(/\b(?:const|let|var)\s+/g, (m) => this.onDeclaration(m.index, m[0].length));
    add(/(?<![\w$.])([A-Za-z_$][\w$]*)\s*(\+=|\|\|=|\?\?=|=)(?![=>])/g, (m) =>
      this.onAssignment(m),
    );
    add(
      /(?<![\w$.])([A-Za-z_$][\w$]*)(?:\s*\.\s*[A-Za-z_$][\w$]*|\s*\[[^\]\n]{0,80}\])+\s*(?:\+=|=)(?![=>])/g,
      (m) => this.onMemberAssignment(m),
    );
    add(
      /(?<![\w$.])([A-Za-z_$][\w$]*)\s*\.\s*(?:push|unshift|splice|set|append|add|concat)\s*\(/g,
      (m) => this.onMutation(m),
    );
    for (const s of this.inner) {
      if (s.start >= from && s.start < to)
        events.push({ at: s.start, run: () => this.onFunction(s) });
    }
    events.sort((a, b) => a.at - b.at);
    for (const e of events) e.run();
  }

  private seedHit(source: TaintSource, offset: number, path: TaintPath): TaintHit {
    return { source, trust: source.trust, path, offset, via: undefined, cleanedBy: [] };
  }

  private roleSeed():
    { source: TaintSource; match: (idx: number, name: string) => boolean } | undefined {
    if (this.opts.sources !== undefined || this.runtime !== "server") return undefined;
    switch (this.span.role) {
      case "app-route-handler":
        return { source: ROUTE_PARAMS_SOURCE, match: (idx) => idx === 1 };
      case "server-action":
        return { source: SERVER_ACTION_SOURCE, match: () => true };
      case "page":
        return {
          source: PAGE_PROPS_SOURCE,
          match: (idx, name) => idx === 0 && /^(?:params|searchParams|query)$/.test(name),
        };
      default:
        return undefined;
    }
  }

  private onDeclaration(at: number, kwLen: number): void {
    const { code, src } = this;
    let i = nextNonWs(code, at + kwLen);
    for (let guard = 0; guard < 50; guard++) {
      const patStart = i;
      let patEnd: number;
      if (code[i] === "{" || code[i] === "[") {
        const close = src.matchOf(i);
        if (close < 0) return;
        patEnd = close + 1;
      } else {
        const id = /^[A-Za-z_$][\w$]*/.exec(code.slice(i, i + 200));
        if (id === null) return;
        patEnd = i + id[0].length;
      }
      const names = patternBindings(code.slice(patStart, patEnd));
      let j = nextNonWs(code, patEnd);
      if (code[j] === "!") j = nextNonWs(code, j + 1);
      if (code[j] === ":") j = nextNonWs(code, skipTypeForward(src, j + 1));
      const kw = /^(?:of|in)\b/.exec(code.slice(j, j + 3));
      if (kw !== null) {
        const open = enclosingOpen(src, at);
        const close = open >= 0 && code[open] === "(" ? src.matchOf(open) : -1;
        const hit = close > j ? this.valueTaint(j + 2, close) : undefined;
        for (const n of names) this.record(n, patStart, hit);
        return;
      }
      if (code[j] === "=" && code[j + 1] !== "=") {
        const initStart = nextNonWs(code, j + 1);
        const initEnd = expressionEnd(src, initStart, this.span.bodyEnd);
        const hit = this.valueTaint(initStart, initEnd);
        for (const n of names) this.record(n, patStart, hit);
        const after = nextNonWs(code, initEnd);
        if (code[after] !== ",") return;
        i = nextNonWs(code, after + 1);
        continue;
      }
      for (const n of names) this.record(n, patStart, undefined);
      if (code[j] !== ",") return;
      i = nextNonWs(code, j + 1);
    }
  }

  private onAssignment(m: RegExpExecArray): void {
    const name = m[1]!;
    const before = wordBefore(this.code, m.index);
    if (before === "const" || before === "let" || before === "var" || before === "type") return;
    const op = m[2]!;
    const valStart = m.index + m[0].length;
    const valEnd = expressionEnd(this.src, nextNonWs(this.code, valStart), this.span.bodyEnd);
    const hit = this.valueTaint(valStart, valEnd);
    if (op === "=") this.record(name, m.index, hit);
    else if (hit !== undefined) this.record(name, m.index, hit);
  }

  private onMemberAssignment(m: RegExpExecArray): void {
    const valStart = m.index + m[0].length;
    const valEnd = expressionEnd(this.src, nextNonWs(this.code, valStart), this.span.bodyEnd);
    const hit = this.valueTaint(valStart, valEnd);
    if (hit !== undefined) this.record(m[1]!, m.index, hit);
  }

  private onMutation(m: RegExpExecArray): void {
    const open = m.index + m[0].length - 1;
    const close = this.src.matchOf(open);
    if (close < 0) return;
    const hit = this.valueTaint(open + 1, close);
    if (hit !== undefined) this.record(m[1]!, m.index, hit);
  }

  private onFunction(s: FunctionSpan): void {
    const { code, src } = this;
    let taintedIdx = -1;
    let hit: TaintHit | undefined;
    const p = prevNonWs(code, s.start - 1);
    const open = code[p] === "(" ? p : code[p] === "," ? enclosingOpen(src, p) : -1;
    if (open >= 0 && code[open] === "(") {
      const callee = calleeBefore(code, open);
      if (callee !== undefined && CALLBACK_METHOD_RE.test(callee.name)) {
        const dot = code.lastIndexOf(".", open);
        const recvStart = this.receiverStart(dot);
        const h = recvStart < dot ? this.exprTaint(recvStart, dot) : undefined;
        if (h !== undefined) {
          hit = { ...h, path: "indirect" };
          taintedIdx = /\.reduce(?:Right)?$/.test(callee.name) ? 1 : 0;
        }
      }
    }
    s.params.forEach((param, idx) => {
      for (const n of param.names)
        this.record(n, param.start, idx === taintedIdx ? hit : undefined, s);
    });
  }

  /** Start of the member/call chain ending just before `dot` (e.g. `req.body.items`). */
  private receiverStart(dot: number): number {
    const { code, src } = this;
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

  // ---- guards ----

  guardBefore(name: string, offset: number): TaintGuard | undefined {
    const { code, src } = this;
    const esc = name.replace(/\$/g, "\\$");
    const nameRe = new RegExp(String.raw`(?<![.\w$])${esc}(?![\w$])`);
    const re = /\bif\s*\(/g;
    re.lastIndex = this.span.bodyStart;
    for (let m = re.exec(code); m !== null && m.index < offset; m = re.exec(code)) {
      const open = m.index + m[0].length - 1;
      const close = src.matchOf(open);
      if (close < 0 || close >= offset) continue;
      const cond = code.slice(open + 1, close);
      if (!nameRe.test(cond)) continue;
      if (!this.exitsEarly(close + 1, offset)) continue;
      const kind = this.guardKind(cond, esc);
      if (kind !== undefined) return { kind, offset: m.index };
    }
    return undefined;
  }

  /** The statement starting at `from` returns, throws, redirects or 404s. */
  private exitsEarly(from: number, limit: number): boolean {
    const { code, src } = this;
    const at = nextNonWs(code, from);
    if (at >= limit) return false;
    const exitRe = /^(?:return\b|throw\b|notFound\s*\(|redirect\s*\(|continue\b)/;
    if (exitRe.test(code.slice(at, at + 12))) return true;
    if (code[at] !== "{") return false;
    const close = src.matchOf(at);
    return (
      close > at && /\b(?:return|throw|notFound\s*\(|redirect\s*\()/.test(code.slice(at, close))
    );
  }

  private guardKind(cond: string, esc: string): TaintGuard["kind"] | undefined {
    const n = String.raw`(?<![.\w$])${esc}(?![\w$])`;
    if (new RegExp(String.raw`!\s*[\w$.]+\s*\.\s*(?:includes|has)\s*\(\s*${n}`).test(cond))
      return "allowlist";
    if (new RegExp(String.raw`${n}\s*!==?\s*["'\x60]`).test(cond)) return "allowlist";
    if (new RegExp(String.raw`!\s*(?:\/[^\n]*\/[a-z]*|[\w$.]+)\s*\.\s*test\s*\(\s*${n}`).test(cond))
      return "regex";
    if (
      new RegExp(String.raw`!\s*[\w$.]*(?:is|valid|check|safe|allowed)\w*\s*\(\s*${n}`, "i").test(
        cond,
      )
    )
      return "validator";
    if (new RegExp(String.raw`${n}\s*\.\s*(?:includes|startsWith|indexOf|match)\s*\(`).test(cond))
      return "contains-check";
    if (new RegExp(String.raw`typeof\s+${n}\s*!==?`).test(cond)) return "type-check";
    return undefined;
  }

  state(): TaintState {
    return {
      span: this.span,
      runtime: this.runtime,
      bindings: this.ordered,
      exprTaint: (s, e) => this.exprTaint(s, e),
      exprTaints: (s, e) => this.exprTaints(s, e),
      bindingAt: (name, offset) => {
        const b = this.visible(name, offset);
        return b?.hit === undefined ? undefined : b;
      },
      guardBefore: (name, offset) => this.guardBefore(name, offset),
    };
  }
}

function emptyState(span: FunctionSpan, runtime: TaintRuntime): TaintState {
  return {
    span,
    runtime,
    bindings: [],
    exprTaint: () => undefined,
    exprTaints: () => [],
    bindingAt: () => undefined,
    guardBefore: () => undefined,
  };
}

/**
 * Analyses `span` of `src` (see the module comment). Never throws. Calls with default
 * options (only `runtime` given) are memoized per source, span and runtime; calls with
 * `sources`, `seedParams`, `seedSource` or `inherited` are not.
 */
export function analyzeTaint(
  src: JsSource,
  span: FunctionSpan,
  opts: TaintOptions = {},
): TaintState {
  const runtime = opts.runtime ?? "server";
  const memoizable =
    opts.sources === undefined &&
    opts.seedParams === undefined &&
    opts.seedSource === undefined &&
    opts.inherited === undefined;
  const key = `${span.kind}:${span.start}:${span.end}:${span.role}:${runtime}`;
  let perSource: Map<string, TaintState> | undefined;
  if (memoizable) {
    perSource = MEMO.get(src);
    if (perSource === undefined) {
      perSource = new Map();
      MEMO.set(src, perSource);
    }
    const cached = perSource.get(key);
    if (cached !== undefined) return cached;
  }
  let state: TaintState;
  try {
    const a = new Analysis(src, span, runtime, opts);
    a.run();
    state = a.state();
  } catch {
    state = emptyState(span, runtime);
  }
  perSource?.set(key, state);
  return state;
}
