import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { makeFinding } from "./utils/finding.js";
import { isGenerated, isJsLike, isTestOrFixturePath } from "./utils/file-kind.js";
import { maskCode } from "./utils/route-analyzer.js";

const MAX_PER_FILE = 25;
/** How far back (in characters) the enclosing-function search looks. */
const FUNCTION_LOOKBACK = 20_000;

const MATH_RANDOM_RE = /\bMath\.random\s*\(\s*\)/g;
const DATE_NOW_RE = /\bDate\.now\s*\(\s*\)/g;
/** `Date.now()` concatenated into a string (`+`, template `${}`) or turned into one (`.toString(36)`). */
const DATE_NOW_CONCAT_RE =
  /\+\s*Date\.now\s*\(\s*\)|Date\.now\s*\(\s*\)\s*(?:\.toString\s*\([^)]*\)\s*)?\+|\$\{\s*Date\.now\s*\(\s*\)|Date\.now\s*\(\s*\)\s*\.toString\s*\(/;
/** A cryptographically secure source on the same line makes the value unpredictable anyway. */
const STRONG_RANDOM_RE =
  /\b(?:randomBytes|randomUUID|getRandomValues|randomInt|nanoid|customAlphabet|uuidv4|uuid\.v4|v4)\s*\(|\bcrypto\.subtle\b/;
/** `Math.random() < 0.1` style sampling, never a value. */
const SAMPLING_RE = /Math\.random\s*\(\s*\)\s*[<>]/;

const STRONG_WORDS = new Set([
  "token",
  "tokens",
  "secret",
  "secrets",
  "password",
  "passwords",
  "passwd",
  "passphrase",
  "otp",
  "totp",
  "hotp",
  "nonce",
  "salt",
  "apikey",
  "apikeys",
  "csrf",
  "xsrf",
]);
const KEY_QUALIFIERS = new Set([
  "api",
  "secret",
  "access",
  "signing",
  "private",
  "session",
  "encryption",
  "license",
  "auth",
  "master",
  "hmac",
]);
const CODE_QUALIFIERS = new Set([
  "otp",
  "verification",
  "verify",
  "reset",
  "invite",
  "invitation",
  "auth",
  "confirm",
  "confirmation",
  "mfa",
  "recovery",
  "login",
  "magic",
]);
/** Words that turn `session` / `invite` / `reset` into an identifier-like value. */
const ID_SUFFIXES = new Set(["id", "token", "key", "secret", "code", "link", "hash", "cookie"]);
/** Names that are never a secret even when they also contain a secret-like word. */
const NEGATIVE_WORDS = new Set([
  "cache",
  "query",
  "status",
  "jitter",
  "shuffle",
  "shuffled",
  "color",
  "colour",
  "colors",
  "colours",
  "hue",
  "delay",
  "backoff",
  "retry",
  "timeout",
  "sample",
  "sampling",
  "position",
  "offset",
  "angle",
  "rotation",
  "opacity",
  "duration",
  "interval",
  "animation",
  "particle",
  "noise",
  "index",
  "idx",
  "width",
  "height",
  "length",
  "len",
  "count",
  "size",
  "rounds",
  "expiry",
  "expires",
  "ttl",
  "age",
  "max",
  "min",
  "limit",
  "bucket",
  "mock",
  "fake",
  "dummy",
  "placeholder",
]);
const TYPE_WORDS = new Set([
  "string",
  "number",
  "any",
  "unknown",
  "boolean",
  "bigint",
  "void",
  "never",
  "object",
]);
const NOT_FUNCTION_NAMES = new Set([
  "if",
  "for",
  "while",
  "switch",
  "catch",
  "with",
  "return",
  "function",
  "else",
  "do",
  "try",
  "finally",
  "typeof",
  "await",
  "new",
]);

/** Splits an identifier into lowercase words: `generateApiKey` -> `generate api key`. */
export function identifierWords(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .replace(/([A-Za-z])([0-9])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((w) => w.length > 0);
}

/**
 * True when an identifier names a security-sensitive random value: token, secret,
 * password, otp, nonce, salt, apiKey, a session/invite id, `(api|secret|access|signing|
 * private|session|...)Key` or `(otp|verification|reset|invite|auth|confirm|...)Code`.
 * Names such as `cacheKey`, `queryKey`, `statusCode`, `jitter`, `shuffle`, `color` or a
 * plain React `key` never match.
 */
export function isSecretValueName(name: string): boolean {
  const words = identifierWords(name);
  if (words.length === 0 || words.some((w) => NEGATIVE_WORDS.has(w))) return false;
  for (let i = 0; i < words.length; i++) {
    const w = words[i]!;
    const prev = i > 0 ? words[i - 1] : undefined;
    const next = words[i + 1];
    const last = next === undefined;
    if (STRONG_WORDS.has(w)) return true;
    if ((w === "key" || w === "keys") && prev !== undefined && KEY_QUALIFIERS.has(prev))
      return true;
    if ((w === "code" || w === "codes") && prev !== undefined && CODE_QUALIFIERS.has(prev))
      return true;
    if (
      (w === "session" || w === "invite" || w === "invitation") &&
      (last || ID_SUFFIXES.has(next))
    )
      return true;
    if (w === "reset" && next !== undefined && ID_SUFFIXES.has(next)) return true;
  }
  return false;
}

/** Same as {@link isSecretValueName} but also reports names that are explicitly not secrets. */
function isNegativeName(name: string): boolean {
  return identifierWords(name).some((w) => NEGATIVE_WORDS.has(w));
}

type Target = { kind: "name"; name: string } | { kind: "return" } | { kind: "none" };

const ASSIGN_RE = /([A-Za-z_$][\w$]*)\s*(?:\+|-|\|\||\?\?)?=(?![=>])/g;
const PROPERTY_RE = /([A-Za-z_$][\w$]*)\s*:(?!:)/g;

/**
 * Start offsets of the bracket groups (`(...)`, `[...]`, `{...}`) that open and close
 * inside `stmt`, mapped to their closing offset. A name inside such a group (the
 * `length:` of `Array.from({ length: 32 }, () => Math.random())`) is a sibling of the
 * random value, not something the value feeds.
 */
function closedGroups(stmt: string): Array<[number, number]> {
  const groups: Array<[number, number]> = [];
  const stack: number[] = [];
  for (let i = 0; i < stmt.length; i++) {
    const c = stmt[i];
    if (c === "(" || c === "[" || c === "{") stack.push(i);
    else if ((c === ")" || c === "]" || c === "}") && stack.length > 0) {
      groups.push([stack.pop()!, i]);
    }
  }
  return groups;
}

/**
 * What the value at the end of `prefix` (masked code of the current line up to the
 * random call) feeds: the nearest enclosing assignment or property name, a `return`,
 * or nothing. Names inside bracket groups already closed before the call are ignored.
 */
function targetOf(prefix: string): Target {
  const stmt = prefix.slice(prefix.lastIndexOf(";") + 1);
  const closed = closedGroups(stmt);
  const isClosed = (index: number) => closed.some(([open, close]) => index > open && index < close);
  let best: { index: number; name: string } | undefined;
  for (const re of [ASSIGN_RE, PROPERTY_RE]) {
    re.lastIndex = 0;
    for (const m of stmt.matchAll(re)) {
      const name = m[1]!;
      if (TYPE_WORDS.has(name) || isClosed(m.index ?? 0)) continue;
      if (best === undefined || (m.index ?? 0) > best.index) best = { index: m.index ?? 0, name };
    }
  }
  const ret = /\breturn\b/g;
  let retIndex = -1;
  for (const m of stmt.matchAll(ret)) retIndex = m.index ?? -1;
  if (retIndex >= 0 && (best === undefined || retIndex > best.index)) return { kind: "return" };
  if (best !== undefined) return { kind: "name", name: best.name };
  return { kind: "none" };
}

/** Callee names of the calls still open at the end of `prefix`, innermost first. */
function openCallees(prefix: string): string[] {
  const names: string[] = [];
  let depth = 0;
  for (let i = prefix.length - 1; i >= 0; i--) {
    const c = prefix[i];
    if (c === ")") depth++;
    else if (c === "(") {
      if (depth > 0) depth--;
      else {
        const m = /([A-Za-z_$][\w$]*)\s*$/.exec(prefix.slice(Math.max(0, i - 80), i));
        if (m) names.push(m[1]!);
      }
    }
  }
  return names;
}

/** Index of the `(` matching the `)` at `close` in masked code, or -1. */
function openParenOf(code: string, close: number): number {
  let depth = 0;
  for (let i = close; i >= 0; i--) {
    const c = code[i];
    if (c === ")") depth++;
    else if (c === "(") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/**
 * The function name declared by the header that precedes a `{` (masked code), `""` for
 * an anonymous function, or undefined when the brace does not open a function body.
 */
function functionNameFromHeader(head: string): string | undefined {
  let h = head.trimEnd();
  let arrow = false;
  if (h.endsWith("=>")) {
    arrow = true;
    h = h.slice(0, -2).trimEnd();
  }
  if (!h.endsWith(")")) {
    // `(...): ReturnType` annotation, or a single bare arrow parameter `x =>`.
    const close = h.lastIndexOf(")");
    const tail = close >= 0 ? h.slice(close + 1) : "";
    if (close >= 0 && /^\s*:\s*[^(){};=]*$/.test(tail)) h = h.slice(0, close + 1);
    else if (arrow) {
      const single = /([A-Za-z_$][\w$]*)$/.exec(h);
      if (!single) return undefined;
      return nameBeforeParams(h.slice(0, single.index).trimEnd(), true);
    } else return undefined;
  }
  const open = openParenOf(h, h.length - 1);
  if (open < 0) return undefined;
  let before = h.slice(0, open).trimEnd();
  if (before.endsWith(">")) {
    const lt = before.lastIndexOf("<");
    if (lt >= 0) before = before.slice(0, lt).trimEnd();
  }
  return nameBeforeParams(before, arrow);
}

function nameBeforeParams(before: string, arrow: boolean): string | undefined {
  if (arrow) {
    const bound = /([A-Za-z_$][\w$]*)\s*(?::[^=;{}()]{0,120})?(?:=|:)\s*(?:async\s*)?$/.exec(
      before,
    );
    return bound ? bound[1]! : "";
  }
  const named = /\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)$/.exec(before);
  if (named) return named[1]!;
  if (/\bfunction\s*\*?$/.test(before)) {
    const bound =
      /([A-Za-z_$][\w$]*)\s*(?::[^=;{}()]{0,120})?(?:=|:)\s*(?:async\s*)?function\s*\*?$/.exec(
        before,
      );
    return bound ? bound[1]! : "";
  }
  const method =
    /(?:^|[\s;{},*])(?:async\s+|static\s+|get\s+|set\s+|public\s+|private\s+|protected\s+)*([A-Za-z_$][\w$]*)$/.exec(
      before,
    );
  if (method && !NOT_FUNCTION_NAMES.has(method[1]!)) return method[1]!;
  return undefined;
}

/**
 * Name of the nearest named function enclosing `offset` in masked code (anonymous
 * callbacks are skipped outward), or undefined at top level.
 */
export function enclosingFunctionName(code: string, offset: number): string | undefined {
  let depth = 0;
  const stop = Math.max(0, offset - FUNCTION_LOOKBACK);
  for (let i = offset - 1; i >= stop; i--) {
    const c = code[i];
    if (c === "}") depth++;
    else if (c === "{") {
      if (depth > 0) {
        depth--;
        continue;
      }
      const name = functionNameFromHeader(code.slice(Math.max(0, i - 400), i));
      if (name) return name;
    }
  }
  // An expression-bodied arrow on the same line: `const makeToken = () => Math.random()`.
  const lineStart = code.lastIndexOf("\n", offset - 1) + 1;
  const arrow =
    /([A-Za-z_$][\w$]*)\s*(?::[^=;{}()]{0,120})?=\s*(?:async\s*)?(?:\([^()]*\)|[A-Za-z_$][\w$]*)\s*(?::[^=;{}]{0,80})?=>/.exec(
      code.slice(lineStart, offset),
    );
  return arrow ? arrow[1] : undefined;
}

function lineStartsOf(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
  return starts;
}

function lineIndexAt(starts: readonly number[], offset: number): number {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid]! <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

interface Hit {
  line: number;
  source: "Math.random()" | "Date.now()";
  confidence: "high" | "medium";
}

/**
 * Flags `Math.random()` (and `Date.now()` concatenated into a string) used to build
 * tokens, secrets, passwords, OTP / reset / invite codes, session ids, nonces, salts and
 * API keys. The value is "security-sensitive" when the assignment, property or enclosing
 * function it feeds is named like one (see {@link isSecretValueName}); a neutral helper
 * such as `randomString()` counts when the same file assigns its result to such a name.
 */
export class InsecureRandomDetector implements Detector {
  id = "insecure-random-detector";
  name = "Insecure Randomness";
  category = "crypto" as const;
  description =
    "Detects tokens, API keys, passwords, OTP and reset codes generated with Math.random() or Date.now().";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (!isJsLike(file) || isTestOrFixturePath(file) || isGenerated(file)) continue;
      try {
        const content = await context.readFile(file);
        if (!content.includes("Math.random") && !content.includes("Date.now")) continue;
        if (isGenerated(file, content)) continue;
        findings.push(...this.scanFile(file, content));
      } catch {
        // never throw from a detector
      }
    }
    return findings;
  }

  private scanFile(file: string, content: string): Finding[] {
    const code = maskCode(content);
    const starts = lineStartsOf(code);
    const lines = content.split("\n");
    const hits = new Map<number, Hit>();
    /** Neutral helper functions that call Math.random, with the lines they do it on. */
    const helpers = new Map<string, number[]>();

    MATH_RANDOM_RE.lastIndex = 0;
    for (const m of code.matchAll(MATH_RANDOM_RE)) {
      const offset = m.index ?? 0;
      const lineIdx = lineIndexAt(starts, offset);
      if (hits.has(lineIdx)) continue;
      const lineCode = code.slice(starts[lineIdx]!, starts[lineIdx + 1] ?? code.length);
      if (STRONG_RANDOM_RE.test(lineCode) || SAMPLING_RE.test(lineCode)) continue;
      const verdict = this.classify(code, starts, lineIdx, offset, true);
      if (verdict === "flag") {
        hits.set(lineIdx, { line: lineIdx + 1, source: "Math.random()", confidence: "high" });
      } else if (typeof verdict === "object") {
        const list = helpers.get(verdict.helper) ?? [];
        list.push(lineIdx);
        helpers.set(verdict.helper, list);
      }
    }

    DATE_NOW_RE.lastIndex = 0;
    for (const m of code.matchAll(DATE_NOW_RE)) {
      const offset = m.index ?? 0;
      const lineIdx = lineIndexAt(starts, offset);
      if (hits.has(lineIdx)) continue;
      const lineCode = code.slice(starts[lineIdx]!, starts[lineIdx + 1] ?? code.length);
      if (!DATE_NOW_CONCAT_RE.test(lineCode) || STRONG_RANDOM_RE.test(lineCode)) continue;
      if (this.classify(code, starts, lineIdx, offset, false) === "flag") {
        hits.set(lineIdx, { line: lineIdx + 1, source: "Date.now()", confidence: "high" });
      }
    }

    // One hop: `const resetToken = randomString(32)` makes randomString's Math.random a token source.
    for (const [helper, lineIdxs] of helpers) {
      if (!this.helperFeedsSecret(code, starts, helper)) continue;
      for (const lineIdx of lineIdxs) {
        if (!hits.has(lineIdx)) {
          hits.set(lineIdx, { line: lineIdx + 1, source: "Math.random()", confidence: "medium" });
        }
      }
    }

    const sorted = [...hits.values()].sort((a, b) => a.line - b.line);
    const out: Finding[] = [];
    for (const hit of sorted.slice(0, MAX_PER_FILE)) {
      out.push(this.finding(file, hit, lines[hit.line - 1] ?? ""));
    }
    if (sorted.length > MAX_PER_FILE) {
      const extra = sorted[MAX_PER_FILE]!;
      out.push(
        this.finding(
          file,
          { ...extra, confidence: "medium" },
          `${sorted.length - MAX_PER_FILE} more insecure random values in this file`,
          "summary",
        ),
      );
    }
    return out;
  }

  /**
   * "flag" when the random value feeds a secret-like name; `{ helper }` when it only sits
   * in a neutral named function (a candidate for the one-hop check); "skip" otherwise.
   */
  private classify(
    code: string,
    starts: readonly number[],
    lineIdx: number,
    offset: number,
    allowHelper: boolean,
  ): "flag" | "skip" | { helper: string } {
    let prefix = code.slice(starts[lineIdx]!, offset);
    // `const token =\n  Math.random()...`: the target sits on the previous line.
    if (prefix.trim() === "" && lineIdx > 0) {
      prefix = code.slice(starts[lineIdx - 1]!, offset);
    }
    const target = targetOf(prefix);
    if (target.kind === "name") {
      if (isNegativeName(target.name)) return "skip";
      // JSX attribute (`key={Math.random()}`, `id={...}`): a render key, never a secret.
      const jsx = /([\w$-]+)=\{[^{}:=]*$/.exec(prefix);
      if (jsx && jsx[1] === target.name) return "skip";
      if (isSecretValueName(target.name)) return "flag";
    } else if (target.kind === "none") {
      const callees = openCallees(prefix.slice(prefix.lastIndexOf(";") + 1));
      if (callees.some((n) => isNegativeName(n))) return "skip";
      if (callees.some((n) => isSecretValueName(n))) return "flag";
    }
    if (target.kind === "name" && !allowHelper) return "skip";
    if (target.kind === "none" && !allowHelper) return "skip";
    const fn = enclosingFunctionName(code, offset);
    if (fn === undefined || isNegativeName(fn)) return "skip";
    if (isSecretValueName(fn)) return "flag";
    return allowHelper ? { helper: fn } : "skip";
  }

  /** True when the file assigns or returns a call of `helper` into a secret-like name. */
  private helperFeedsSecret(code: string, starts: readonly number[], helper: string): boolean {
    const escaped = helper.replace(/\$/g, "\\$");
    const callRe = new RegExp(`(?<![\\w$.])${escaped}\\s*\\(`, "g");
    for (const m of code.matchAll(callRe)) {
      const offset = m.index ?? 0;
      const lineIdx = lineIndexAt(starts, offset);
      const prefix = code.slice(starts[lineIdx]!, offset);
      if (/\bfunction\s*\*?\s*$/.test(prefix)) continue; // the declaration itself
      const target = targetOf(prefix);
      if (target.kind === "name" && isSecretValueName(target.name)) return true;
      if (target.kind === "return") {
        const fn = enclosingFunctionName(code, offset);
        if (fn !== undefined && fn !== helper && isSecretValueName(fn)) return true;
      }
    }
    return false;
  }

  private finding(file: string, hit: Hit, evidence: string, discriminator?: string): Finding {
    const isDate = hit.source === "Date.now()";
    return makeFinding({
      category: "crypto",
      ruleId: "crypto/insecure-random-token",
      title: isDate
        ? "Security token built from Date.now()"
        : "Security token generated with Math.random()",
      severity: "high",
      confidence: hit.confidence,
      file,
      line: hit.line,
      evidence,
      discriminator,
      plainEnglishProblem: isDate
        ? "A token, key, password or one-time code is built from the current timestamp (Date.now()), which an attacker can guess to within a few milliseconds."
        : "A token, key, password or one-time code is generated with Math.random(). Math.random() is not a cryptographically secure generator: its output can be predicted from a few observed values.",
      whyItMatters:
        "Anyone who can predict the value can forge it: guess another user's API key, password-reset or invite link, session id or OTP and take over that account or tenant without knowing any password.",
      fixSteps: [
        "Generate the value with a cryptographically secure source: crypto.randomBytes(32).toString('base64url') or crypto.randomUUID() in Node, crypto.getRandomValues() in the browser or edge runtime.",
        "For a random string from an alphabet, use crypto.randomInt(alphabet.length) per character (or a vetted library such as nanoid), never Math.random().",
        "Do not mix in Date.now() or counters to make it 'more random'; they add no secrecy.",
        "Rotate any tokens, keys or codes that were already issued with the weak generator.",
      ],
      aiFixPrompt:
        "This code generates a security-sensitive value (token, API key, password, session id, OTP, reset or invite code) with Math.random() or Date.now(), which are predictable. Replace the generation with a cryptographically secure source: crypto.randomBytes(32).toString('base64url') or crypto.randomUUID() from node:crypto on the server, or crypto.getRandomValues() in browser/edge code. If the value must use a specific alphabet, pick each character with crypto.randomInt(alphabet.length). Keep the function's signature and output format (prefix, length) unchanged, and do not use Math.random() or Date.now() anywhere in the value.",
      learnMoreUrl:
        "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#secure-random-number-generation",
    });
  }
}
