// Parsing and classification helpers for Firebase security rules: Firestore and Cloud
// Storage rules (`service cloud.firestore` / `service firebase.storage`) and Realtime
// Database rules JSON. Everything here is linear in its input and never throws.

export type RulesService = "firestore" | "storage";
export type AccessClass = "open" | "test-mode" | "signed-in" | "scoped" | "deny";
export interface ConditionClass {
  cls: AccessClass;
  /** Epoch ms of a test-mode expiry, when cls is "test-mode". */
  expiresAt?: number | undefined;
}
export interface AllowStatement {
  service: RulesService;
  /** Match path segments after the service prefix, e.g. ["users", "{userId}"]. */
  segments: string[];
  /** Lower-case methods, e.g. ["read", "write"]. */
  methods: string[];
  /** Raw text after `if` (comments removed), undefined for `allow read;`. */
  condition: string | undefined;
  /** 1-based line of `allow`. */
  line: number;
  /** Line of the terminating `;`. */
  endLine: number;
}
export interface RtdbRule {
  path: string[];
  key: ".read" | ".write";
  value: string | boolean;
  line: number;
}

const MAX_RULES_CHARS = 500_000;

/** Shared scanner: blanks comments (and string contents when `blankStrings`), keeping length and newlines. */
function blank(text: string, blankStrings: boolean): string {
  const out: string[] = [];
  const n = text.length;
  let i = 0;
  const keep = (c: string): string => (c === "\n" || c === "\r" ? c : " ");
  while (i < n) {
    const c = text[i] as string;
    const d = text[i + 1];
    if (c === "/" && d === "/") {
      while (i < n && text[i] !== "\n" && text[i] !== "\r") {
        out.push(" ");
        i++;
      }
    } else if (c === "/" && d === "*") {
      out.push(" ", " ");
      i += 2;
      while (i < n && !(text[i] === "*" && text[i + 1] === "/")) {
        out.push(keep(text[i] as string));
        i++;
      }
      if (i < n) {
        out.push(" ", " ");
        i += 2;
      }
    } else if (c === '"' || c === "'") {
      out.push(c);
      i++;
      while (i < n && text[i] !== c && text[i] !== "\n" && text[i] !== "\r") {
        if (text[i] === "\\" && i + 1 < n && text[i + 1] !== "\n") {
          out.push(blankStrings ? " " : "\\", blankStrings ? " " : (text[i + 1] as string));
          i += 2;
          continue;
        }
        out.push(blankStrings ? " " : (text[i] as string));
        i++;
      }
      if (i < n && text[i] === c) {
        out.push(c);
        i++;
      }
    } else {
      out.push(c);
      i++;
    }
  }
  return out.join("");
}

/** Blanks // and /* *\/ comments and the contents of '...' and "..." strings; same length and newlines. */
export function maskRulesSource(text: string): string {
  return blank(text, true);
}

/** Removes comments only (strings kept), same length. */
export function stripRulesComments(text: string): string {
  return blank(text, false);
}

/** Index of the `}` matching the `{` at `open` (over masked text), or -1 within `limit` chars. */
function matchBrace(masked: string, open: number, limit: number): number {
  let depth = 0;
  const end = Math.min(masked.length, open + limit);
  for (let i = open; i < end; i++) {
    const c = masked[i];
    if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

const FUNCTION_RE = /\bfunction\s+([A-Za-z_]\w*)\s*\(([^)]{0,200})\)\s*\{/g;
const RETURN_BODY_RE = /^\s*return\s+([^;]{1,2000});\s*$/;

/**
 * Rules functions by name -> the returned expression, or null (opaque) when the body is
 * not a single `return <expr>;`. Parameters are not substituted: classification only
 * looks at which constructs appear.
 */
export function collectRuleFunctions(masked: string, raw: string): Map<string, string | null> {
  const fns = new Map<string, string | null>();
  try {
    FUNCTION_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = FUNCTION_RE.exec(masked)) !== null) {
      const name = m[1] as string;
      const open = m.index + m[0].length - 1;
      const close = matchBrace(masked, open, 4000);
      if (close === -1) {
        if (!fns.has(name)) fns.set(name, null);
        continue;
      }
      const body = raw.slice(open + 1, close);
      const r = RETURN_BODY_RE.exec(body);
      if (!fns.has(name)) fns.set(name, r ? (r[1] as string).replace(/\s+/g, " ").trim() : null);
      FUNCTION_RE.lastIndex = close + 1;
    }
  } catch {
    // Never throw.
  }
  return fns;
}

function lineStarts(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text[i] === "\n") starts.push(i + 1);
  return starts;
}

function lineOf(starts: number[], offset: number): number {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if ((starts[mid] as number) <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

const METHODS = new Set(["read", "get", "list", "write", "create", "update", "delete"]);
const MATCH_RE = /match\s+/y;
const ALLOW_RE = /allow\s+/y;
const FUNCTION_KW_RE = /function\s+/y;
const IDENT_BEFORE_RE = /[\w.$]/;

interface Frame {
  segments: string[];
  depthAtOpen: number;
}

/** Parses a firestore/storage rules file; [] when no `service` header. Never throws. */
export function parseRulesFile(text: string): AllowStatement[] {
  try {
    if (text.length === 0 || text.length > MAX_RULES_CHARS) return [];
    const masked = maskRulesSource(text);
    const raw = stripRulesComments(text);
    const svc = /\bservice\s+(cloud\.firestore|firebase\.storage)\b/.exec(masked);
    if (!svc) return [];
    const service: RulesService = svc[1] === "cloud.firestore" ? "firestore" : "storage";
    const starts = lineStarts(text);
    const out: AllowStatement[] = [];
    const stack: Frame[] = [];
    let depth = 0;
    const n = masked.length;
    let i = svc.index + svc[0].length;
    while (i < n) {
      const c = masked[i] as string;
      if (c === "{") {
        depth++;
        i++;
        continue;
      }
      if (c === "}") {
        depth--;
        while (stack.length > 0 && (stack[stack.length - 1] as Frame).depthAtOpen >= depth) {
          stack.pop();
        }
        i++;
        continue;
      }
      if (!/[a-z]/.test(c) || (i > 0 && IDENT_BEFORE_RE.test(masked[i - 1] as string))) {
        i++;
        continue;
      }
      if (c === "f") {
        FUNCTION_KW_RE.lastIndex = i;
        if (FUNCTION_KW_RE.test(masked)) {
          const open = masked.indexOf("{", i);
          const close = open === -1 ? -1 : matchBrace(masked, open, 4000);
          if (close !== -1) {
            i = close + 1;
            continue;
          }
        }
        i++;
        continue;
      }
      if (c === "m") {
        MATCH_RE.lastIndex = i;
        const mm = MATCH_RE.exec(masked);
        if (mm) {
          const start = i + mm[0].length;
          let j = start;
          let found = -1;
          const limit = Math.min(n, start + 300);
          while (j < limit) {
            const ch = masked[j];
            if (ch === "{" && masked[j - 1] !== "/") {
              found = j;
              break;
            }
            if (ch === "{") {
              // Path wildcard `{name}` / `{name=**}`: skip to its closing brace.
              const close = masked.indexOf("}", j);
              if (close === -1 || close >= limit) break;
              j = close + 1;
              continue;
            }
            if (ch === ";" || ch === "}") break;
            j++;
          }
          if (found !== -1) {
            const segments = (raw.slice(start, found).trim().split("/") as string[]).filter(
              (s) => s !== "",
            );
            stack.push({ segments, depthAtOpen: depth });
            i = found;
            continue;
          }
        }
        i++;
        continue;
      }
      if (c === "a") {
        ALLOW_RE.lastIndex = i;
        const am = ALLOW_RE.exec(masked);
        if (am) {
          const start = i + am[0].length;
          const limit = Math.min(n, start + 2000);
          let paren = 0;
          let end = -1;
          for (let j = start; j < limit; j++) {
            const ch = masked[j];
            if (ch === "(" || ch === "[") paren++;
            else if (ch === ")" || ch === "]") paren--;
            else if (ch === ";" && paren <= 0) {
              end = j;
              break;
            }
          }
          if (end !== -1) {
            const stmt = parseAllow(masked, raw, start, end);
            if (stmt) {
              out.push({
                service,
                segments: stripPrefix(
                  service,
                  stack.flatMap((f) => f.segments),
                ),
                methods: stmt.methods,
                condition: stmt.condition,
                line: lineOf(starts, i),
                endLine: lineOf(starts, end),
              });
            }
            i = end + 1;
            continue;
          }
        }
        i++;
        continue;
      }
      i++;
    }
    return out;
  } catch {
    return [];
  }
}

function parseAllow(
  masked: string,
  raw: string,
  start: number,
  end: number,
): { methods: string[]; condition: string | undefined } | null {
  const colon = masked.indexOf(":", start);
  const hasCond = colon !== -1 && colon < end;
  const methodText = masked.slice(start, hasCond ? colon : end);
  const methods = methodText
    .split(",")
    .map((m) => m.trim().toLowerCase())
    .filter((m) => METHODS.has(m));
  if (methods.length === 0) return null;
  let condition: string | undefined;
  if (hasCond) {
    const c = raw
      .slice(colon + 1, end)
      .replace(/\s+/g, " ")
      .trim()
      .replace(/^if\b\s*/, "");
    condition = c === "" ? undefined : c;
  }
  return { methods, condition };
}

function stripPrefix(service: RulesService, segments: string[]): string[] {
  const lead = service === "firestore" ? ["databases", "documents"] : ["b", "o"];
  if (segments[0] === lead[0] && segments.length >= 3 && segments[2] === lead[1]) {
    return segments.slice(3);
  }
  return segments;
}

// ---------------------------------------------------------------------------
// Condition classification

const RANK: Record<AccessClass, number> = {
  open: 4,
  "test-mode": 3,
  "signed-in": 2,
  scoped: 1,
  deny: 0,
};
const MAX_EXPR = 4000;

type AtomResult = ConditionClass | "neutral";

/** Splits at top-level `op` (paren/bracket/brace depth 0, outside quotes). */
function splitTop(text: string, op: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let quote = "";
  let last = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i] as string;
    if (quote) {
      if (c === "\\") i++;
      else if (c === quote) quote = "";
    } else if (c === '"' || c === "'") quote = c;
    else if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") depth--;
    else if (depth === 0 && text.startsWith(op, i)) {
      parts.push(text.slice(last, i));
      i += op.length - 1;
      last = i + 1;
    }
  }
  parts.push(text.slice(last));
  return parts;
}

/** True when the whole text is wrapped by one matching pair of parentheses. */
function isWrapped(text: string): boolean {
  if (text[0] !== "(" || text[text.length - 1] !== ")") return false;
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth === 0 && i < text.length - 1) return false;
    }
  }
  return depth === 0;
}

function combine(text: string, atom: (a: string) => AtomResult, level: number): AtomResult {
  if (level > 12) return { cls: "scoped" };
  const ors = splitTop(text, "||");
  if (ors.length > 1) {
    let best: ConditionClass | null = null;
    for (const part of ors) {
      const r = combine(part, atom, level + 1);
      const c: ConditionClass = r === "neutral" ? { cls: "open" } : r;
      if (best === null || RANK[c.cls] > RANK[best.cls]) best = c;
      else if (RANK[c.cls] === RANK[best.cls] && c.cls === "test-mode") {
        best = { cls: "test-mode", expiresAt: Math.max(best.expiresAt ?? 0, c.expiresAt ?? 0) };
      }
    }
    return best ?? { cls: "scoped" };
  }
  const ands = splitTop(text, "&&");
  if (ands.length > 1) {
    let worst: ConditionClass | null = null;
    for (const part of ands) {
      const r = combine(part, atom, level + 1);
      if (r === "neutral") continue;
      if (worst === null || RANK[r.cls] < RANK[worst.cls]) worst = r;
      else if (RANK[r.cls] === RANK[worst.cls] && r.cls === "test-mode") {
        worst = {
          cls: "test-mode",
          expiresAt: Math.min(worst.expiresAt ?? Infinity, r.expiresAt ?? Infinity),
        };
      }
    }
    return worst ?? "neutral";
  }
  if (isWrapped(text)) return combine(text.slice(1, -1), atom, level + 1);
  return atom(text);
}

/** Replaces calls to known rules functions by their (parenthesised) body; max 3 rounds. */
function inlineFunctions(text: string, fns: ReadonlyMap<string, string | null>): string {
  if (fns.size === 0) return text;
  let cur = text;
  for (let round = 0; round < 3; round++) {
    let changed = false;
    let out = "";
    let i = 0;
    while (i < cur.length) {
      const m = /[A-Za-z_]\w*\(/y;
      m.lastIndex = i;
      const hit = !(i > 0 && /[\w.$]/.test(cur[i - 1] as string)) ? m.exec(cur) : null;
      if (hit) {
        const name = hit[0].slice(0, -1);
        if (fns.has(name)) {
          let depth = 0;
          let j = i + name.length;
          for (; j < cur.length; j++) {
            if (cur[j] === "(") depth++;
            else if (cur[j] === ")") {
              depth--;
              if (depth === 0) break;
            }
          }
          if (j < cur.length) {
            const body = fns.get(name);
            out += `(${body === null || body === undefined ? "__opaque__" : body.replace(/\s+/g, "")})`;
            i = j + 1;
            changed = true;
            continue;
          }
        }
      }
      out += cur[i];
      i++;
    }
    cur = out;
    if (!changed || cur.length > MAX_EXPR) break;
  }
  return cur;
}

const DATE_RE = /^request\.time<=?timestamp\.date\((\d{4}),(\d{1,2}),(\d{1,2})\)$/;
const DATE_REV_RE = /^timestamp\.date\((\d{4}),(\d{1,2}),(\d{1,2})\)>=?request\.time$/;
const VALUE_RE = /^request\.time<=?timestamp\.value\((\d{10,14})\)$/;
const VALUE_REV_RE = /^timestamp\.value\((\d{10,14})\)>=?request\.time$/;
const SIGNED_IN_ATOMS = new Set([
  "request.auth!=null",
  "null!=request.auth",
  "request.auth.uid!=null",
  "null!=request.auth.uid",
  "request.auth.token.email_verified==true",
  "request.auth.token.email_verified",
]);
const NOT_ANONYMOUS_RE =
  /^request\.auth\.token\.firebase\.sign_in_provider!=(?:'anonymous'|"anonymous")$/;
const NEUTRAL_START_RE = /^!?request\.resource\.(?:data|size|contentType)/;
const NEUTRAL_BLOCK_RE = /request\.auth|get\(|exists\(|getAfter\(|existsAfter\(|__opaque__/;

function expiry(ms: number, now: number): ConditionClass {
  return ms <= now ? { cls: "deny" } : { cls: "test-mode", expiresAt: ms };
}

function firestoreAtom(atom: string, now: number): AtomResult {
  if (atom === "true") return { cls: "open" };
  if (atom === "false") return { cls: "deny" };
  let m = DATE_RE.exec(atom) ?? DATE_REV_RE.exec(atom);
  if (m) return expiry(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])), now);
  m = VALUE_RE.exec(atom) ?? VALUE_REV_RE.exec(atom);
  if (m) return expiry(Number(m[1]), now);
  if (SIGNED_IN_ATOMS.has(atom) || NOT_ANONYMOUS_RE.test(atom)) return { cls: "signed-in" };
  if (NEUTRAL_START_RE.test(atom) && !NEUTRAL_BLOCK_RE.test(atom)) return "neutral";
  return { cls: "scoped" };
}

/** Classifies a condition (undefined = no condition = open). `now` is epoch ms. */
export function classifyCondition(
  cond: string | undefined,
  fns: ReadonlyMap<string, string | null>,
  now: number,
): ConditionClass {
  try {
    if (cond === undefined) return { cls: "open" };
    const text = inlineFunctions(cond.replace(/\s+/g, ""), fns);
    if (text === "") return { cls: "open" };
    const r = combine(text, (a) => firestoreAtom(a, now), 0);
    return r === "neutral" ? { cls: "open" } : r;
  } catch {
    return { cls: "scoped" };
  }
}

// ---------------------------------------------------------------------------
// Realtime Database rules

const TRUE_AUTH_ATOMS = new Set([
  "auth!=null",
  "auth!==null",
  "null!=auth",
  "null!==auth",
  "auth.uid!=null",
  "auth.uid!==null",
  "auth!==undefined",
  "auth!=undefined",
]);

function rtdbAtom(atom: string, now: number): AtomResult {
  if (atom === "true") return { cls: "open" };
  if (atom === "false") return { cls: "deny" };
  if (TRUE_AUTH_ATOMS.has(atom)) return { cls: "signed-in" };
  const m = /^now<=?(\d{12,14})$/.exec(atom);
  if (m) return expiry(Number(m[1]), now);
  if (/^!?newData\./.test(atom) && !/auth|root\./.test(atom)) return "neutral";
  return { cls: "scoped" };
}

/** Classifies an RTDB rule value. */
export function classifyRtdbValue(value: string | boolean, now: number): ConditionClass {
  try {
    if (typeof value === "boolean") return { cls: value ? "open" : "deny" };
    const text = value.replace(/\s+/g, "");
    if (text === "" || text.length > MAX_EXPR) return { cls: "scoped" };
    const r = combine(text, (a) => rtdbAtom(a, now), 0);
    return r === "neutral" ? { cls: "open" } : r;
  } catch {
    return { cls: "scoped" };
  }
}

type Token = { t: "str" | "punct" | "lit"; v: string; line: number };

function tokenize(text: string): Token[] {
  const tokens: Token[] = [];
  const n = text.length;
  let line = 1;
  let i = 0;
  while (i < n) {
    const c = text[i] as string;
    if (c === "\n") {
      line++;
      i++;
    } else if (c === " " || c === "\t" || c === "\r") i++;
    else if (c === '"') {
      const startLine = line;
      let j = i + 1;
      while (j < n && text[j] !== '"') {
        if (text[j] === "\\") j++;
        else if (text[j] === "\n") line++;
        j++;
      }
      const lit = text.slice(i, j + 1);
      let v = lit.slice(1, -1);
      try {
        v = JSON.parse(lit) as string;
      } catch {
        // keep the raw text
      }
      tokens.push({ t: "str", v, line: startLine });
      i = j + 1;
    } else if ("{}[]:,".includes(c)) {
      tokens.push({ t: "punct", v: c, line });
      i++;
    } else {
      let j = i;
      while (j < n && !' \t\r\n{}[]:,"'.includes(text[j] as string)) j++;
      if (j === i) j++;
      tokens.push({ t: "lit", v: text.slice(i, j), line });
      i = j;
    }
  }
  return tokens;
}

/** Realtime Database rules JSON (comments allowed): every `.read`/`.write` with its key path below `rules`. */
export function parseDatabaseRules(text: string): RtdbRule[] {
  const out: RtdbRule[] = [];
  try {
    if (text.length === 0 || text.length > MAX_RULES_CHARS) return [];
    const tokens = tokenize(stripRulesComments(text));
    const frames: (string | null)[] = [];
    let i = 0;
    while (i < tokens.length) {
      const tok = tokens[i] as Token;
      if (tok.t === "punct" && tok.v === "{") {
        frames.push(null);
        i++;
      } else if (tok.t === "punct" && tok.v === "}") {
        frames.pop();
        i++;
      } else if (tok.t === "str" && tokens[i + 1]?.t === "punct" && tokens[i + 1]?.v === ":") {
        const key = tok.v;
        const value = tokens[i + 2];
        i += 2;
        if (!value) break;
        if (value.t === "punct" && value.v === "{") {
          frames.push(key);
          i++;
        } else if (value.t === "punct" && value.v === "[") {
          let depth = 0;
          while (i < tokens.length) {
            const t = tokens[i] as Token;
            if (t.t === "punct" && t.v === "[") depth++;
            else if (t.t === "punct" && t.v === "]") {
              depth--;
              if (depth === 0) {
                i++;
                break;
              }
            }
            i++;
          }
        } else {
          if (key === ".read" || key === ".write") {
            const keys = frames.filter((f): f is string => f !== null);
            if (keys[0] === "rules") {
              if (value.t === "str") {
                out.push({ path: keys.slice(1), key, value: value.v, line: tok.line });
              } else if (value.t === "lit" && (value.v === "true" || value.v === "false")) {
                out.push({ path: keys.slice(1), key, value: value.v === "true", line: tok.line });
              }
            }
          }
          i++;
        }
      } else {
        i++;
      }
    }
  } catch {
    // Return what was collected.
  }
  return out;
}

// ---------------------------------------------------------------------------
// Names

export type Sensitivity = "directory" | "private";

const DIRECTORY_NAME_RE =
  /^(?:users?|profiles?|members?|contacts?|docs|documents?|notes?|files|uploads?|settings)$/i;
const PRIVATE_NAME_RE =
  /^(?:accounts?|customers?|orders?|payments?|invoices?|billing|subscriptions?|transactions?|messages?|chats?|conversations?|private|secrets?|admins?|tokens?|sessions?|keys?|credentials?|audit\w*|logs?|emails?|addresses?|medical\w*|health\w*|records?|employees?|patients?|students?|bookings?|reservations?)$/i;

/** "directory": names apps often share with every member; "private": per-user private data; null: not sensitive. */
export function nameSensitivity(name: string): Sensitivity | null {
  if (DIRECTORY_NAME_RE.test(name)) return "directory";
  if (PRIVATE_NAME_RE.test(name)) return "private";
  return null;
}

/** nameSensitivity(name) !== null. */
export function isSensitiveName(name: string): boolean {
  return nameSensitivity(name) !== null;
}
