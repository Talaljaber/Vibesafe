// Line-based request-taint tracking for Python functions (no AST, by design).
//
// Finds `def` spans by indentation and, per function, follows simple assignments from
// request sources (Django/DRF/Flask) so Python sink detectors can tell "built from the
// request" from "built from something else". Bounded: <= 200 statements per function and
// a propagation depth <= 5. Never throws.
import { pythonStatements, type PythonLine, type PythonStatement } from "./python-source.js";

export const MAX_FUNCTION_STATEMENTS = 200;
export const MAX_TAINT_DEPTH = 5;

/** Placeholder for the text of a plain string literal (keeps quotes and length). */
const FILL = "~";
/** Delimiters of an f-string replacement field; the field's code stays visible. */
const FIELD_OPEN = "⟦";
const FIELD_CLOSE = "⟧";

/**
 * Same-length copy of `text` where the contents of plain string literals are replaced by `~`.
 * The code inside f-string replacement fields stays visible, wrapped in U+27E6 / U+27E7 in
 * place of `{` / `}`. Regexes on the mask therefore never match inside strings or docstrings.
 */
export function maskPython(text: string): string {
  const out: string[] = [];
  let i = 0;
  const n = text.length;
  while (i < n) {
    const ch = text[i]!;
    if (ch !== '"' && ch !== "'") {
      out.push(ch);
      i++;
      continue;
    }
    // Prefix letters directly before the quote (already pushed) decide whether it is an f-string.
    let p = i - 1;
    let isF = false;
    let prefixLen = 0;
    while (p >= 0 && /[A-Za-z]/.test(text[p]!) && prefixLen < 3) {
      if (text[p] === "f" || text[p] === "F") isF = true;
      p--;
      prefixLen++;
    }
    if (p >= 0 && /[\w]/.test(text[p]!)) {
      // letters glued to an identifier, not a string prefix
      isF = false;
    }
    const triple = text.startsWith(ch.repeat(3), i);
    const q = triple ? ch.repeat(3) : ch;
    out.push(q);
    i += q.length;
    let depth = 0;
    while (i < n) {
      const c = text[i]!;
      if (depth === 0 && text.startsWith(q, i)) {
        out.push(q);
        i += q.length;
        break;
      }
      if (c === "\\") {
        out.push(FILL);
        if (i + 1 < n) out.push(text[i + 1] === "\n" ? "\n" : FILL);
        i += 2;
        continue;
      }
      if (c === "\n") {
        out.push("\n");
        i++;
        if (!triple && depth === 0) break; // unterminated plain string: stop at line end
        continue;
      }
      if (isF) {
        if (c === "{" && depth === 0 && text[i + 1] === "{") {
          out.push(FILL, FILL);
          i += 2;
          continue;
        }
        if (c === "{") {
          out.push(depth === 0 ? FIELD_OPEN : "{");
          depth++;
          i++;
          continue;
        }
        if (c === "}" && depth > 0) {
          depth--;
          out.push(depth === 0 ? FIELD_CLOSE : "}");
          i++;
          continue;
        }
        if (depth === 0 && c === "}" && text[i + 1] === "}") {
          out.push(FILL, FILL);
          i += 2;
          continue;
        }
        if (depth > 0) {
          out.push(c);
          i++;
          continue;
        }
      }
      out.push(FILL);
      i++;
    }
  }
  return out.join("");
}

/** Removes `name(...)` calls (balanced) for the given dotted call names from masked text. */
function stripCalls(masked: string, names: RegExp): string {
  let s = masked;
  for (let guard = 0; guard < 50; guard++) {
    const m = names.exec(s);
    if (!m) break;
    const open = m.index + m[0].length - 1;
    let depth = 0;
    let end = -1;
    for (let k = open; k < s.length; k++) {
      const c = s[k];
      if (c === "(") depth++;
      else if (c === ")") {
        depth--;
        if (depth === 0) {
          end = k;
          break;
        }
      }
    }
    s = end < 0 ? s.slice(0, m.index) : s.slice(0, m.index) + " 0 " + s.slice(end + 1);
  }
  return s;
}

/** Calls whose result is no longer attacker-shaped text (or is quoted for its sink). */
const CLEANER_RE =
  /(?<![\w.])(?:int|float|bool|len|uuid\s*\.\s*UUID|UUID|os\s*\.\s*path\s*\.\s*basename|basename|shlex\s*\.\s*quote|pipes\s*\.\s*quote|secure_filename|get_valid_filename|safe_join)\s*\(/;

/** Masked text with cleaner calls removed. */
export function stripCleaners(masked: string): string {
  return stripCalls(masked, new RegExp(CLEANER_RE.source));
}

const REQUEST_SOURCE_RE =
  /(?<![\w.])request\s*\.\s*(?:GET|POST|data|query_params|FILES|body|headers|COOKIES|META|args|form|json|values|files|get_json)\b/;

/** True when the masked text reads a request source directly. */
export function hasRequestSource(masked: string): boolean {
  return REQUEST_SOURCE_RE.test(masked);
}

const KEYWORDS = new Set([
  "True",
  "False",
  "None",
  "and",
  "or",
  "not",
  "in",
  "is",
  "if",
  "else",
  "for",
  "lambda",
  "await",
  "return",
  "yield",
]);

/** Identifiers that start a name chain (not preceded by `.`), in masked text. */
export function identifiers(masked: string): string[] {
  const out: string[] = [];
  // The lookahead drops string prefixes (the `f` of f"...").
  const re = /(?<![\w.])[A-Za-z_]\w*(?![\w"'])/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(masked)) !== null) {
    if (!KEYWORDS.has(m[0])) out.push(m[0]);
  }
  return out;
}

const CALL_RE = /(?<![\w.])([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*)\s*\(/;
const PASS_FUNCS = new Set([
  "str",
  "bytes",
  "Path",
  "PurePath",
  "PurePosixPath",
  "PureWindowsPath",
  "join",
  "unquote",
  "unquote_plus",
  "normpath",
  "abspath",
  "realpath",
]);
const PATH_FUNCS = new Set(["join", "normpath", "abspath", "realpath", "normcase", "expanduser"]);
const STR_METHODS = new Set([
  "format",
  "strip",
  "lstrip",
  "rstrip",
  "lower",
  "upper",
  "replace",
  "encode",
  "decode",
  "title",
  "join",
]);

/** Index of the bracket closing the one at `open` (`(` or `[`), or -1. */
function balancedEnd(s: string, open: number): number {
  let depth = 0;
  for (let k = open; k < s.length; k++) {
    const c = s[k];
    if (c === "(" || c === "[") depth++;
    else if (c === ")" || c === "]") {
      depth--;
      if (depth === 0) return k;
    }
  }
  return -1;
}

export interface PythonFunction {
  name: string;
  /** 0-based index of the `def` line and of the last line of the body. */
  start: number;
  end: number;
  indent: number;
  statements: PythonStatement[];
}

/** Every `def` / `async def` with its body statements (by indentation). Nested defs are listed too. */
export function pythonFunctions(statements: PythonStatement[]): PythonFunction[] {
  const out: PythonFunction[] = [];
  for (let i = 0; i < statements.length; i++) {
    const st = statements[i]!;
    const m = /^\s*(?:async\s+)?def\s+(\w+)/.exec(st.head);
    if (!m) continue;
    const body: PythonStatement[] = [];
    let end = st.end;
    for (let j = i + 1; j < statements.length; j++) {
      const next = statements[j]!;
      if (next.indent <= st.indent) break;
      body.push(next);
      end = next.end;
    }
    out.push({ name: m[1]!, start: st.start, end, indent: st.indent, statements: body });
  }
  return out;
}

/** The innermost function containing the 0-based line, if any. */
export function functionAt(funcs: PythonFunction[], line: number): PythonFunction | undefined {
  let best: PythonFunction | undefined;
  for (const f of funcs) {
    if (line >= f.start && line <= f.end && (!best || f.start >= best.start)) best = f;
  }
  return best;
}

interface TaintEvent {
  line: number;
  tainted: boolean;
  depth: number;
  indent: number;
}

/** Result of {@link analyzeFunction}. */
export interface FunctionTaint {
  /** True when the masked expression, evaluated at 0-based `line`, carries request data. */
  isTainted(masked: string, line: number): boolean;
  /** 0-based line of the assignment that made the expression tainted (undefined for direct sources). */
  taintOrigin(masked: string, line: number): number | undefined;
  /** True when the masked expression builds text from a non-constant (and non-guarded) value. */
  nonConstant(masked: string, line: number): boolean;
  /** True when `name` is allowlist-guarded or a literal-opened file handle at `line`. */
  isGuarded(name: string, line: number): boolean;
  isLiteralHandle(name: string): boolean;
}

const ASSIGN_RE =
  /^(\(?\s*[A-Za-z_]\w*(?:\s*,\s*\*?[A-Za-z_]\w*)*\s*,?\s*\)?)\s*(?::[^=]+?)?\s*(\+?)=(?!=)\s*([\s\S]+)$/;
const FOR_RE = /^(?:async\s+)?for\s+([\w\s,()]+?)\s+in\s+([\s\S]+?)\s*:\s*[\s\S]*$/;
const GUARD_NOT_IN_RE = /^(?:el)?if\s+\(?\s*([A-Za-z_]\w*)\s+not\s+in\s+([^:]+):([\s\S]*)$/;
const GUARD_NOT_IN_PREFIX_RE = /^(?:el)?if\s+not\s+\(?\s*([A-Za-z_]\w*)\s+in\s+([^:]+):([\s\S]*)$/;
/** A block that leaves the function or loop iteration, so code after it only sees allowed values. */
const TERMINAL_RE = /^\s*(?:return|raise|continue|abort\s*\()/;
/** Allowlist-looking container: UPPER_CASE / settings.X name or a literal of strings. */
function looksLikeAllowlist(container: string): boolean {
  const c = container.trim();
  if (/(?:^|\.)[A-Z][A-Z0-9_]*\)?$/.test(c)) return true;
  return /^[[({]/.test(c) && /["']/.test(c);
}
const GUARD_IN_RE = /^(?:el)?if\s+\(?\s*([A-Za-z_]\w*)\s+in\s+[^:]+:/;
const ASSERT_IN_RE = /^assert\s+([A-Za-z_]\w*)\s+in\s+/;
const OPEN_LITERAL_RE = /(?<![\w.])open\s*\(\s*(?:[rbuRBU]{0,2})(["'])~*\1/;

function splitNames(lhs: string): string[] {
  return lhs
    .replace(/[()*]/g, "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => /^[A-Za-z_]\w*$/.test(s));
}

/** Allowlist-constant style names (`COLUMNS`, `settings.ALLOWED`) are never "dynamic" in text. */
const CONSTANT_NAME_RE = /^[A-Z][A-Z0-9_]*$/;

/**
 * Builds the taint model of one function. Names become tainted by assignment from a request
 * source or from an expression using a tainted name (f-strings, `%`, `.format`, `+`,
 * `os.path.join`, `.get(...)` and tuple unpacking included). Cleaner calls and allowlist
 * guards (`if x not in ALLOWED: return|raise`, enclosing `if x in ALLOWED:`) stop propagation.
 */
export function analyzeFunction(fn: PythonFunction | undefined): FunctionTaint {
  const events = new Map<string, TaintEvent[]>();
  const nonConstVars = new Set<string>();
  const literalHandles = new Set<string>();
  /** Names assigned only from cleaner calls (int(), shlex.quote(), ...): safe to interpolate. */
  const cleanVars = new Set<string>();
  const guards = new Map<string, Array<[number, number]>>();
  const stmts = fn ? fn.statements.slice(0, MAX_FUNCTION_STATEMENTS) : [];

  // Guards first: ranges of lines (0-based) where a name is allowlist-checked.
  for (let i = 0; i < stmts.length; i++) {
    const st = stmts[i]!;
    const head = maskPython(st.head).trimStart();
    let notIn = GUARD_NOT_IN_RE.exec(head) ?? GUARD_NOT_IN_PREFIX_RE.exec(head);
    let blockEnd = st.end;
    let lastBlock: PythonStatement | undefined;
    for (let j = i + 1; j < stmts.length; j++) {
      if (stmts[j]!.indent <= st.indent) break;
      blockEnd = stmts[j]!.end;
      lastBlock = stmts[j];
    }
    if (notIn) {
      // Only a guard when the block leaves (return/raise/abort/continue) and the container
      // looks like an allowlist; `if x not in seen: seen.add(x)` guards nothing.
      const tail = (notIn[3] ?? "").trim();
      const leaves = tail
        ? TERMINAL_RE.test(tail)
        : lastBlock !== undefined && TERMINAL_RE.test(maskPython(lastBlock.stmt).trimStart());
      if (!leaves || !looksLikeAllowlist(notIn[2] ?? "")) notIn = null;
    }
    const inM = notIn ? null : GUARD_IN_RE.exec(head);
    const assertM = ASSERT_IN_RE.exec(head);
    const name = notIn?.[1] ?? inM?.[1] ?? assertM?.[1];
    if (!name) continue;
    const range: [number, number] = notIn
      ? [blockEnd + 1, Number.MAX_SAFE_INTEGER]
      : assertM
        ? [st.end + 1, Number.MAX_SAFE_INTEGER]
        : [st.start, blockEnd];
    const list = guards.get(name) ?? [];
    list.push(range);
    guards.set(name, list);
  }

  const isGuarded = (name: string, line: number): boolean =>
    (guards.get(name) ?? []).some(([a, b]) => line >= a && line <= b);

  const taintAt = (name: string, line: number): TaintEvent | undefined => {
    const list = events.get(name);
    if (!list) return undefined;
    let last: TaintEvent | undefined;
    for (const e of list) if (e.line < line) last = e;
    return last?.tainted ? last : undefined;
  };

  /**
   * Removes calls whose result is not text built from their input (ORM lookups, helper
   * functions, constructors) together with their trailing `.attr` / `(...)` / `[...]` chain.
   * Taint only survives string building, os.path functions, `.get()` on a request or tainted
   * mapping and plain string methods.
   */
  const stripOpaque = (masked: string, line: number): string => {
    let s = masked;
    let from = 0;
    for (let guard = 0; guard < 100; guard++) {
      const re = new RegExp(CALL_RE.source, "g");
      re.lastIndex = from;
      const m = re.exec(s);
      if (!m) break;
      const parts = m[1]!.split(".").map((x) => x.trim());
      const last = parts[parts.length - 1]!;
      const recv = parts.slice(0, -1);
      const recvText = recv.join(".");
      let keep: boolean;
      if (recv.length === 0) keep = KEYWORDS.has(last) || PASS_FUNCS.has(last);
      else if (recvText === "os.path" || recvText === "path" || recvText === "posixpath")
        keep = PATH_FUNCS.has(last);
      else if (last === "get" || last === "getlist")
        keep = hasRequestSource(recvText) || taintAt(recv[0]!, line) !== undefined;
      else if (STR_METHODS.has(last)) keep = recv.length === 1 || hasRequestSource(recvText);
      else keep = false;
      const open = m.index + m[0].length - 1;
      if (!keep && hasRequestSource(parts.join("."))) keep = true; // request.get_json()
      if (!keep && /^[A-Z]/.test(last)) {
        // Serializer / form constructors fed the request body: S(data=request.data), Form(request.POST)
        keep = splitCallArgs(s, open).some(
          (a) =>
            (/^data\s*=/.test(a) && hasRequestSource(a)) ||
            /^request\s*\.\s*(?:POST|GET|data|FILES|query_params)$/.test(a),
        );
      }
      if (keep) {
        from = open + 1;
        continue;
      }
      let k = balancedEnd(s, open);
      if (k < 0) {
        s = s.slice(0, m.index) + " 0 ";
        break;
      }
      k++;
      for (;;) {
        const t = /^\s*\.\s*[A-Za-z_]\w*/.exec(s.slice(k, k + 80));
        if (t) k += t[0].length;
        else if (s[k] !== "(" && s[k] !== "[") break;
        while (s[k] === "(" || s[k] === "[") {
          const e = balancedEnd(s, k);
          if (e < 0) {
            k = s.length;
            break;
          }
          k = e + 1;
        }
      }
      s = s.slice(0, m.index) + " 0 " + s.slice(k);
      from = m.index + 3;
    }
    return s;
  };

  const exprDepth = (masked: string, line: number): number | undefined => {
    let s = stripOpaque(stripCleaners(masked), line);
    if (hasRequestSource(s)) return 0;
    s = s.replace(/[⟦⟧]/g, " ");
    let best: number | undefined;
    for (const id of identifiers(s)) {
      if (isGuarded(id, line)) continue;
      const e = taintAt(id, line);
      if (e && e.depth < MAX_TAINT_DEPTH && (best === undefined || e.depth + 1 < best)) {
        best = e.depth + 1;
      }
    }
    return best;
  };

  const nonConstantExpr = (masked: string, line: number): boolean => {
    const s = stripCleaners(masked);
    const bare = /^\s*\(?\s*([A-Za-z_]\w*)\s*\)?\s*$/.exec(s);
    if (bare)
      return nonConstVars.has(bare[1]!) && !isGuarded(bare[1]!, line) && !cleanVars.has(bare[1]!);
    const interpolated = s.includes(FIELD_OPEN);
    const percent = /["']\s*%\s*[\w(\[{]/.test(s);
    const format = /\.\s*format\s*\(\s*[^)\s]/.test(s);
    const plus = /(?:[A-Za-z_]\w*[)\]]?\s*\+|\+\s*[A-Za-z_])/.test(s);
    if (!interpolated && !percent && !format && !plus) return false;
    const view = s.replace(/[⟦⟧]/g, " ");
    return identifiers(view).some(
      (id) =>
        !CONSTANT_NAME_RE.test(id) &&
        !isGuarded(id, line) &&
        !cleanVars.has(id) &&
        // function names before "(" are not values
        !new RegExp(`(?<![\\w.])${id}\\s*\\(`).test(view),
    );
  };

  for (const st of stmts) {
    const masked = maskPython(st.stmt).trimStart();
    const line = st.start;
    const forM = FOR_RE.exec(masked);
    if (forM) {
      const d = exprDepth(forM[2]!, line);
      for (const n of splitNames(forM[1]!)) {
        const list = events.get(n) ?? [];
        list.push({ line, tainted: d !== undefined, depth: d ?? 0, indent: st.indent });
        events.set(n, list);
      }
      continue;
    }
    const withM = /^(?:async\s+)?with\s+open\s*\(([\s\S]*?)\)\s+as\s+([A-Za-z_]\w*)\s*:/.exec(
      masked,
    );
    if (withM && OPEN_LITERAL_RE.test("open(" + withM[1]!)) literalHandles.add(withM[2]!);
    const m = ASSIGN_RE.exec(masked);
    if (!m) continue;
    const names = splitNames(m[1]!);
    if (names.length === 0) continue;
    const rhs = m[3]!;
    const d = exprDepth(rhs, line);
    const stripped = stripCleaners(rhs);
    const cleaned = stripped !== rhs && identifiers(stripped).length === 0;
    const augmented = m[2] === "+";
    for (const n of names) {
      const list = events.get(n) ?? [];
      const prev = list.length > 0 ? list[list.length - 1] : undefined;
      if (d !== undefined) {
        list.push({ line, tainted: true, depth: d, indent: st.indent });
      } else if (!augmented && prev?.tainted && st.indent <= prev.indent) {
        list.push({ line, tainted: false, depth: 0, indent: st.indent });
      }
      events.set(n, list);
      if (cleaned && !augmented) cleanVars.add(n);
      if (nonConstantExpr(rhs, line) || (augmented && nonConstVars.has(n))) nonConstVars.add(n);
      if (names.length === 1 && OPEN_LITERAL_RE.test(rhs)) literalHandles.add(n);
    }
  }

  return {
    isTainted: (masked, line) => exprDepth(masked, line) !== undefined,
    taintOrigin: (masked, line) => {
      const s = stripOpaque(stripCleaners(masked), line).replace(/[⟦⟧]/g, " ");
      let best: number | undefined;
      for (const id of identifiers(s)) {
        if (isGuarded(id, line)) continue;
        const e = taintAt(id, line);
        if (e && (best === undefined || e.line > best)) best = e.line;
      }
      return best;
    },
    nonConstant: nonConstantExpr,
    isGuarded,
    isLiteralHandle: (name) => literalHandles.has(name),
  };
}

/** Standalone `nonConstant` check for an expression outside any function (no variable context). */
export function nonConstant(expr: string): boolean {
  return analyzeFunction(undefined).nonConstant(maskPython(expr), 0);
}

/** Splits the top-level arguments of the call whose `(` is at `open` in masked/raw `text`. */
export function splitCallArgs(text: string, open: number): string[] {
  const args: string[] = [];
  let depth = 0;
  let cur = "";
  for (let i = open; i < text.length; i++) {
    const c = text[i]!;
    if (c === "(" || c === "[" || c === "{" || c === FIELD_OPEN) {
      depth++;
      if (depth === 1) continue;
    } else if (c === ")" || c === "]" || c === "}" || c === FIELD_CLOSE) {
      depth--;
      if (depth === 0) {
        if (cur.trim()) args.push(cur.trim());
        return args;
      }
    } else if (c === "," && depth === 1) {
      args.push(cur.trim());
      cur = "";
      continue;
    }
    cur += c;
  }
  if (cur.trim()) args.push(cur.trim());
  return args;
}

/** Convenience: every logical statement of a Python file's scanned lines. */
export function statementsOf(lines: PythonLine[]): PythonStatement[] {
  return pythonStatements(lines);
}
