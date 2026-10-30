import type { JsSource } from "./js-source.js";
import { splitArgs, stringEnd, trimRange, nextNonWs, type Range } from "./sinks.js";

/**
 * Cookie option parsing shared by the cookie-flags and CSRF detectors: which cookies carry
 * a session credential, which flags a `res.cookie(...)`-style call sets, and the call sites
 * themselves ({@link findCookieSites}). Everything matches on `src.code` (masked) and reads
 * literal text from `src.text` at the same offsets.
 */

export type FlagState = "true" | "false" | "dynamic" | "missing";
export type SameSiteState = "strict" | "lax" | "none" | "dynamic" | "missing";
export interface CookieFlags {
  httpOnly: FlagState;
  secure: FlagState;
  sameSite: SameSiteState;
  /** maxAge: 0 or expires: new Date(0) */
  deletes: boolean;
}

export const SESSION_TOKENS: ReadonlySet<string> = new Set(
  (
    "session sess sid sessionid ssid connect auth authtoken token accesstoken refreshtoken " +
    "idtoken jwt access refresh login rememberme credential credentials apikey bearer"
  ).split(" "),
);
/** One-purpose flow tokens (CSRF double-submit, OAuth state, preferences, invites, resets, OTP, magic links). */
export const DENY_TOKENS: ReadonlySet<string> = new Set(
  (
    "csrf xsrf callback redirect returnto state nonce pkce verifier theme locale lang language " +
    "consent preview invite reset otp verify verification magic"
  ).split(" "),
);

/** Name tokens marking a metadata cookie about the session (timestamps, provider, status), not the credential. */
const METADATA_TOKENS: ReadonlySet<string> = new Set(
  (
    "at expires expiry expiresat exp time timestamp last provider method type status hint " +
    "expiration created updated"
  ).split(" "),
);

const VALUE_TOKENS: ReadonlySet<string> = new Set([
  "token",
  "jwt",
  "session",
  "sid",
  "sessionid",
  "accesstoken",
  "refreshtoken",
  "idtoken",
]);
const VALUE_CALL_RE =
  /\b(?:jwt\s*\.\s*sign|signToken|signJwt|generateToken|createToken|createSession\w*)\s*\(/;
const VALUE_SIGN_RE = /(?<![.\w$])sign\s*\(|\bnew\s+SignJWT\s*\(/;

/** Splits a cookie name into lower-case tokens plus adjacent-pair joins ("next-auth.session-token" -> next, auth, session, token, nextauth, authsession, sessiontoken). */
export function cookieNameTokens(name: string): string[] {
  const parts = name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .filter((p) => p !== "")
    .map((p) => p.toLowerCase());
  const out = [...parts];
  for (let i = 0; i + 1 < parts.length; i++) out.push(parts[i]! + parts[i + 1]!);
  return out;
}

function hasDeny(tokens: readonly string[]): boolean {
  return tokens.some((t) => DENY_TOKENS.has(t));
}

/** True when the cookie name carries a deny token (a one-purpose flow cookie). */
export function isDeniedCookieName(name: string): boolean {
  return hasDeny(cookieNameTokens(name));
}

/** Session/auth cookie by name. */
export function isSessionCookieName(name: string): boolean {
  const tokens = cookieNameTokens(name);
  return tokens.some((t) => SESSION_TOKENS.has(t)) && !hasDeny(tokens);
}

/** Session/auth cookie by the value expression's text (identifiers and calls). `jwtLibImported`: the file imports/requires `jsonwebtoken` or `jose` (enables a bare `sign(` call). */
export function isSessionCookieValue(valueText: string, jwtLibImported: boolean): boolean {
  const ids = valueText.match(/[A-Za-z_$][\w$]*/g) ?? [];
  const tokens = ids.flatMap((id) => cookieNameTokens(id));
  if (hasDeny(tokens)) return false;
  if (tokens.some((t) => VALUE_TOKENS.has(t))) return true;
  if (VALUE_CALL_RE.test(valueText)) return true;
  return jwtLibImported && VALUE_SIGN_RE.test(valueText);
}

/** A plain literal value (string without `${`, number, boolean) is never a credential. */
const PLAIN_LITERAL_RE = /^(?:(["'])(?:(?!\1)[^\\\n]|\\.)*\1|`[^`$\\]*`|\d+(?:\.\d+)?|true|false)$/;

/** True when `valueText` is a plain literal (no interpolation, identifier or call). */
export function isPlainLiteralValue(valueText: string): boolean {
  return PLAIN_LITERAL_RE.test(valueText.trim());
}

/** Refresh-token cookie: the name carries a refresh token, or the value does (identifier tokens with refresh and none of access/session/sid), whatever the name. */
export function isRefreshCookie(name: string, valueText: string | undefined): boolean {
  const nt = cookieNameTokens(name);
  if (nt.includes("refresh") || nt.includes("refreshtoken")) return true;
  if (valueText === undefined) return false;
  const vt = (valueText.match(/[A-Za-z_$][\w$]*/g) ?? []).flatMap((id) => cookieNameTokens(id));
  if (!vt.includes("refresh") && !vt.includes("refreshtoken")) return false;
  return !vt.some((t) => ["access", "accesstoken", "session", "sid", "sessionid"].includes(t));
}

const JWT_IMPORT_RE = /(?:from\s*|require\s*\(\s*)["'](?:jsonwebtoken|jose)["']/g;

/** True when `src` imports or requires `jsonwebtoken` or `jose` (match start must be code). */
export function importsJwtLib(src: JsSource): boolean {
  if (!src.text.includes("jsonwebtoken") && !src.text.includes("jose")) return false;
  for (const m of src.text.matchAll(JWT_IMPORT_RE)) {
    if (isCodeAt(src, m.index ?? 0)) return true;
  }
  return false;
}

function isCodeAt(src: JsSource, i: number): boolean {
  return src.code[i] === src.text[i] && src.code[i] !== " ";
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export const MISSING_FLAGS: CookieFlags = {
  httpOnly: "missing",
  secure: "missing",
  sameSite: "missing",
  deletes: false,
};
export const DYNAMIC_FLAGS: CookieFlags = {
  httpOnly: "dynamic",
  secure: "dynamic",
  sameSite: "dynamic",
  deletes: false,
};

// ---------------------------------------------------------------------------
// Object literals
// ---------------------------------------------------------------------------

interface Entry {
  /** Property key; undefined for spreads and computed keys. */
  key: string | undefined;
  /** Value range (the key range for a shorthand property); undefined for spreads. */
  value: Range | undefined;
  shorthand: boolean;
  /** `...expr` or a computed key. */
  spread: Range | undefined;
  computed: boolean;
}

const KEY_RE = /^(?:([A-Za-z_$][\w$]*)|(["'])([\w$-]+)\2)\s*(:)?/;

/** Properties of the object literal whose `{` is at `open`. */
function objectEntries(src: JsSource, open: number): Entry[] | undefined {
  if (src.code[open] !== "{") return undefined;
  const close = src.matchOf(open);
  if (close < 0) return undefined;
  const out: Entry[] = [];
  for (const r of splitArgs(src, open, close)) {
    if (src.code.startsWith("...", r.start)) {
      out.push({
        key: undefined,
        value: undefined,
        shorthand: false,
        spread: { start: r.start + 3, end: r.end },
        computed: false,
      });
      continue;
    }
    if (src.code[r.start] === "[") {
      out.push({
        key: undefined,
        value: undefined,
        shorthand: false,
        spread: undefined,
        computed: true,
      });
      continue;
    }
    const m = KEY_RE.exec(src.text.slice(r.start, Math.min(r.end, r.start + 200)));
    if (m === null || src.code[r.start] === " ") continue;
    const key = m[1] ?? m[3]!;
    if (m[4] === ":") {
      out.push({
        key,
        value: trimRange(src, { start: r.start + m[0].length, end: r.end }),
        shorthand: false,
        spread: undefined,
        computed: false,
      });
    } else if (src.code.slice(r.start, r.end).trim() === key) {
      out.push({
        key,
        value: { start: r.start, end: r.start + key.length },
        shorthand: true,
        spread: undefined,
        computed: false,
      });
    }
  }
  return out;
}

/** `{` of a same-file `const|let|var NAME = {` declaration, or undefined. */
function findObjectDecl(src: JsSource, name: string): number | undefined {
  const re = new RegExp(
    String.raw`\b(?:const|let|var)\s+${escapeRe(name)}\s*(?::[^=;{]{0,200})?=\s*\{`,
  );
  const m = re.exec(src.code);
  return m === null ? undefined : m.index + m[0].length - 1;
}

/** Text of a same-file `const NAME = "literal"` declaration. */
function findStringDecl(src: JsSource, name: string): string | undefined {
  const re = new RegExp(
    String.raw`\b(?:const|let|var)\s+${escapeRe(name)}\s*(?::[^=;{]{0,80})?=\s*(["'])`,
  );
  const m = re.exec(src.code);
  if (m === null) return undefined;
  const open = m.index + m[0].length - 1;
  const end = stringEnd(src, open);
  return end < 0 ? undefined : src.text.slice(open + 1, end - 1);
}

const IDENT_RE = /^[A-Za-z_$][\w$]*$/;

/** `{` of an object literal argument, or of the same-file const object it names. */
function objectOpenOf(src: JsSource, r: Range): number | undefined {
  const t = trimRange(src, r);
  if (src.code[t.start] === "{" && src.matchOf(t.start) === t.end - 1) return t.start;
  const id = src.code.slice(t.start, t.end);
  return IDENT_RE.test(id) ? findObjectDecl(src, id) : undefined;
}

interface FlagAcc {
  httpOnly: FlagState | undefined;
  secure: FlagState | undefined;
  sameSite: SameSiteState | undefined;
  deletes: boolean;
  unresolved: boolean;
}

function boolState(code: string): FlagState {
  const v = code.trim();
  return v === "true" ? "true" : v === "false" ? "false" : "dynamic";
}

function collectFlags(src: JsSource, open: number, depth: number, acc: FlagAcc): void {
  const entries = objectEntries(src, open);
  if (entries === undefined) {
    acc.unresolved = true;
    return;
  }
  for (const e of entries) {
    if (e.computed) {
      acc.unresolved = true;
      continue;
    }
    if (e.spread !== undefined) {
      const expr = src.code.slice(e.spread.start, e.spread.end).trim();
      const decl = IDENT_RE.test(expr) && depth < 2 ? findObjectDecl(src, expr) : undefined;
      if (decl === undefined) acc.unresolved = true;
      else collectFlags(src, decl, depth + 1, acc);
      continue;
    }
    if (e.key === undefined || e.value === undefined) continue;
    const valueCode = src.code
      .slice(e.value.start, e.value.end)
      .replace(/\s+(?:as|satisfies)\s+[^]*$/, "")
      .trim();
    switch (e.key) {
      case "httpOnly":
        acc.httpOnly = e.shorthand ? "dynamic" : boolState(valueCode);
        break;
      case "secure":
        acc.secure = e.shorthand ? "dynamic" : boolState(valueCode);
        break;
      case "sameSite": {
        const lit = /^(["'`])(none|lax|strict)\1$/i.exec(
          src.text
            .slice(e.value.start, e.value.end)
            .replace(/\s+(?:as|satisfies)\s+[^]*$/, "")
            .trim(),
        );
        if (e.shorthand) acc.sameSite = "dynamic";
        else if (lit !== null) acc.sameSite = lit[2]!.toLowerCase() as SameSiteState;
        else if (valueCode === "true") acc.sameSite = "strict";
        else if (valueCode === "false") acc.sameSite = "missing";
        else acc.sameSite = "dynamic";
        break;
      }
      case "maxAge":
        acc.deletes = !e.shorthand && valueCode === "0";
        break;
      case "expires":
        if (/^new\s+Date\s*\(\s*0\s*\)$/.test(valueCode)) acc.deletes = true;
        break;
      default:
        break;
    }
  }
}

/** Flags of an object literal starting at `open` (`{`) in src.code, resolving same-file identifiers and spreads (depth <= 2). Unresolvable parts make the missing flags "dynamic". */
export function readCookieFlags(src: JsSource, open: number): CookieFlags {
  const acc: FlagAcc = {
    httpOnly: undefined,
    secure: undefined,
    sameSite: undefined,
    deletes: false,
    unresolved: false,
  };
  collectFlags(src, open, 0, acc);
  const miss = acc.unresolved ? "dynamic" : "missing";
  return {
    httpOnly: acc.httpOnly ?? miss,
    secure: acc.secure ?? miss,
    sameSite: acc.sameSite ?? miss,
    deletes: acc.deletes,
  };
}

/** Flags of an options argument: object literal, same-file const identifier, or anything else (all "dynamic"). */
export function flagsOfArgument(src: JsSource, start: number, end: number): CookieFlags {
  const open = objectOpenOf(src, { start, end });
  if (open === undefined) return { ...DYNAMIC_FLAGS };
  const flags = readCookieFlags(src, open);
  const t = trimRange(src, { start, end });
  const id = src.code.slice(t.start, t.end);
  return IDENT_RE.test(id) ? applyMutations(src, id, flags) : flags;
}

/** `ID.secure = ...`, `ID["secure"] = ...` or `Object.assign(ID, ...)` after the declaration make those flags "dynamic". */
function applyMutations(src: JsSource, id: string, flags: CookieFlags): CookieFlags {
  if (!src.code.includes(id)) return flags;
  const out = { ...flags };
  const e = escapeRe(id);
  if (new RegExp(String.raw`(?<![\w$.])Object\s*\.\s*assign\s*\(\s*${e}\s*,`).test(src.code)) {
    if (out.httpOnly === "missing") out.httpOnly = "dynamic";
    if (out.secure === "missing") out.secure = "dynamic";
    if (out.sameSite === "missing") out.sameSite = "dynamic";
  }
  const re = new RegExp(
    String.raw`(?<![\w$.])${e}\s*(?:\.\s*(httpOnly|secure|sameSite)|\[\s*["'](httpOnly|secure|sameSite)["']\s*\])\s*=(?![=>])`,
    "g",
  );
  for (const m of src.text.matchAll(re)) {
    if (!isCodeAt(src, m.index ?? 0)) continue;
    const k = m[1] ?? m[2];
    if (k === "httpOnly") out.httpOnly = "dynamic";
    else if (k === "secure") out.secure = "dynamic";
    else if (k === "sameSite") out.sameSite = "dynamic";
  }
  return out;
}

/** Flags parsed from a literal Set-Cookie header string ("a=b; Path=/; HttpOnly"). */
export function flagsOfHeaderString(value: string): CookieFlags & { name: string | undefined } {
  const parts = value.split(";");
  const first = parts[0] ?? "";
  const eq = first.indexOf("=");
  const name = eq < 0 ? undefined : first.slice(0, eq).trim();
  const cookieValue = eq < 0 ? "" : first.slice(eq + 1).trim();
  let httpOnly: FlagState = "missing";
  let secure: FlagState = "missing";
  let sameSite: SameSiteState = "missing";
  let deletes = cookieValue === "";
  for (const raw of parts.slice(1)) {
    const attr = raw.trim();
    const i = attr.indexOf("=");
    const k = (i < 0 ? attr : attr.slice(0, i)).trim().toLowerCase();
    const v =
      i < 0
        ? ""
        : attr
            .slice(i + 1)
            .trim()
            .toLowerCase();
    if (k === "httponly") httpOnly = "true";
    else if (k === "secure") secure = "true";
    else if (k === "samesite") {
      sameSite = v === "none" || v === "lax" || v === "strict" ? v : "dynamic";
    } else if (k === "max-age" && v === "0") deletes = true;
    else if (k === "expires" && /\b1970\b/.test(v)) deletes = true;
  }
  return { name, httpOnly, secure, sameSite, deletes };
}

// ---------------------------------------------------------------------------
// Call sites
// ---------------------------------------------------------------------------

export type CookieKind =
  | "express"
  | "next-headers"
  | "next-response"
  | "koa"
  | "serialize"
  | "header"
  | "express-session"
  | "cookie-session"
  | "iron-session";

export interface CookieSite {
  kind: CookieKind;
  /** Offset of the call (or of the `cookieOptions` key). */
  start: number;
  /** Offset of the closing bracket / end of the options value. */
  end: number;
  /** Resolved cookie name ("session" for the session-config kinds). */
  name: string;
  flags: CookieFlags;
  /** A missing httpOnly/secure is reported (true) or the library defaults protect it (false). */
  defaultsOff: boolean;
  /** Session/auth cookie (always true for the session-config kinds). */
  session: boolean;
  /** Refresh-token cookie (not a cookie-session credential for CSRF purposes). */
  refresh: boolean;
  /** The call clears the cookie. */
  deletes: boolean;
}

const EXPRESS_RE = /\b(?:res|resp|response|reply)\s*\.\s*(?:cookie|setCookie)\s*\(/g;
const NEXT_HEADERS_RES = [
  /\bcookies\s*\(\s*\)\s*\.\s*set\s*\(/g,
  /\(\s*await\s+cookies\s*\(\s*\)\s*\)\s*\.\s*set\s*\(/g,
];
const COOKIES_BINDING_RE =
  /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?cookies\s*\(\s*\)/g;
const NEXT_RESPONSE_RE = /\b([A-Za-z_$][\w$]*)\s*\.\s*cookies\s*\.\s*set\s*\(/g;
const NEXT_SERVER_RE = /(?:from\s*|require\s*\(\s*)["']next\/server["']/g;
const KOA_RE = /\bctx\s*\.\s*cookies\s*\.\s*set\s*\(/g;
const SERIALIZE_RE = /\b(?:cookie|cookies)\s*\.\s*serialize\s*\(/g;
const COOKIE_MODULE_RE = /["']cookie["']/g;
const SERIALIZE_BINDING_TAIL_RE = /\{([^{}]{0,300})\}\s*(?:from\s*|=\s*require\s*\(\s*)$/;

/** `{ serialize } from "cookie"` / `= require("cookie")`; bounded windows, linear in file size. */
function importsBareSerialize(src: JsSource): boolean {
  const { text } = src;
  if (!text.includes("serialize")) return false;
  COOKIE_MODULE_RE.lastIndex = 0;
  for (const m of text.matchAll(COOKIE_MODULE_RE)) {
    const i = m.index ?? 0;
    if (!isCodeAt(src, i)) continue;
    const tail = SERIALIZE_BINDING_TAIL_RE.exec(text.slice(Math.max(0, i - 400), i));
    if (tail !== null && /\bserialize\b/.test(tail[1]!)) return true;
  }
  return false;
}
const HEADER_RE = /\.\s*(?:setHeader|set|append|header)\s*\(/g;

function codeMatchExists(src: JsSource, re: RegExp): boolean {
  re.lastIndex = 0;
  for (const m of src.text.matchAll(re)) if (isCodeAt(src, m.index ?? 0)) return true;
  return false;
}

/** Local names bound to the default/namespace export of `mod` (import or require). */
function boundNames(src: JsSource, mod: string): string[] {
  if (!src.text.includes(mod)) return [];
  const m = escapeRe(mod);
  const res = [
    new RegExp(
      String.raw`\bimport\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s*(?:,\s*\{[^}]*\})?\s*from\s*["']${m}["']`,
      "g",
    ),
    new RegExp(
      String.raw`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*["']${m}["']\s*\)`,
      "g",
    ),
  ];
  const out: string[] = [];
  for (const re of res) {
    for (const x of src.text.matchAll(re)) if (isCodeAt(src, x.index ?? 0)) out.push(x[1]!);
  }
  return out;
}

/** Local names bound by `import X`, `* as X` or `const X = require()` of any module in `mods`. */
export function boundModuleNames(src: JsSource, mods: readonly string[]): string[] {
  return mods.flatMap((m) => boundNames(src, m));
}

function nameOf(src: JsSource, r: Range): string {
  const c = src.code[r.start];
  if (c === '"' || c === "'") {
    const e = stringEnd(src, r.start);
    if (e === r.end) return src.text.slice(r.start + 1, e - 1);
  } else if (c === "`" && src.code[r.end - 1] === "`") {
    return src.text.slice(r.start + 1, r.end - 1);
  } else {
    const id = src.code.slice(r.start, r.end);
    if (IDENT_RE.test(id)) return findStringDecl(src, id) ?? id;
  }
  return src.text.slice(r.start, Math.min(r.end, r.start + 200));
}

function emptyString(src: JsSource, r: Range): boolean {
  return /^(["'`])\1$/.test(src.text.slice(r.start, r.end).trim());
}

function entryOf(src: JsSource, open: number, key: string): Entry | undefined {
  return objectEntries(src, open)?.find((e) => e.key === key);
}

/** Every cookie-setting call and session-configuration object in `src`. */
export function findCookieSites(src: JsSource): CookieSite[] {
  const { text, code } = src;
  if (!text.includes("ookie") && !text.includes("express-session")) return [];
  const sites: CookieSite[] = [];
  const seen = new Set<number>();
  const jwt = importsJwtLib(src);

  const classify = (name: string, valueCode: string | undefined): boolean => {
    if (isSessionCookieName(name)) {
      if (!cookieNameTokens(name).some((t) => METADATA_TOKENS.has(t))) return true;
      return valueCode !== undefined && isSessionCookieValue(valueCode, jwt);
    }
    if (valueCode === undefined || isDeniedCookieName(name)) return false;
    return isSessionCookieValue(valueCode, jwt);
  };

  const callSite = (kind: CookieKind, defaultsOff: boolean, open: number): void => {
    if (seen.has(open)) return;
    const close = src.matchOf(open);
    if (close < 0) return;
    const args = splitArgs(src, open, close);
    let nameR: Range | undefined;
    let valueR: Range | undefined;
    let flags: CookieFlags;
    const first = args[0];
    if (
      args.length === 1 &&
      first !== undefined &&
      code[first.start] === "{" &&
      (kind === "next-headers" || kind === "next-response")
    ) {
      nameR = entryOf(src, first.start, "name")?.value;
      valueR = entryOf(src, first.start, "value")?.value;
      flags = readCookieFlags(src, first.start);
    } else {
      nameR = first;
      valueR = args[1];
      const opts = args[2];
      flags =
        opts === undefined ? { ...MISSING_FLAGS } : flagsOfArgument(src, opts.start, opts.end);
    }
    if (nameR === undefined || valueR === undefined) return;
    seen.add(open);
    const name = nameOf(src, nameR);
    const valueCode = code.slice(valueR.start, valueR.end);
    const literal = isPlainLiteralValue(text.slice(valueR.start, valueR.end));
    sites.push({
      kind,
      start: open,
      end: close,
      name,
      flags,
      defaultsOff,
      session: !literal && classify(name, valueCode),
      refresh: isRefreshCookie(name, valueCode),
      deletes: flags.deletes || emptyString(src, valueR),
    });
  };

  const eachMatch = (re: RegExp, fn: (m: RegExpExecArray, open: number) => void): void => {
    re.lastIndex = 0;
    for (let m = re.exec(code); m !== null; m = re.exec(code)) fn(m, m.index + m[0].length - 1);
  };

  // express / fastify
  eachMatch(EXPRESS_RE, (_m, open) => callSite("express", true, open));

  // next/headers
  for (const re of NEXT_HEADERS_RES)
    eachMatch(re, (_m, open) => callSite("next-headers", true, open));
  const bound = new Set<string>();
  eachMatch(COOKIES_BINDING_RE, (m) => void bound.add(m[1]!));
  for (const id of bound) {
    eachMatch(new RegExp(String.raw`(?<![\w$.])${escapeRe(id)}\s*\.\s*set\s*\(`, "g"), (_m, open) =>
      callSite("next-headers", true, open),
    );
  }

  // NextResponse.cookies
  if (text.includes("next/server") && codeMatchExists(src, NEXT_SERVER_RE)) {
    eachMatch(NEXT_RESPONSE_RE, (m, open) => {
      if (m[1] === "req" || m[1] === "request" || m[1] === "ctx") return;
      callSite("next-response", true, open);
    });
  }

  // koa
  eachMatch(KOA_RE, (_m, open) => callSite("koa", false, open));

  // cookie.serialize
  eachMatch(SERIALIZE_RE, (_m, open) => callSite("serialize", true, open));
  if (importsBareSerialize(src)) {
    eachMatch(/(?<![\w$.])serialize\s*\(/g, (_m, open) => callSite("serialize", true, open));
  }

  // literal Set-Cookie headers
  if (/set-cookie/i.test(text)) {
    eachMatch(HEADER_RE, (_m, open) => {
      if (seen.has(open)) return;
      const close = src.matchOf(open);
      if (close < 0) return;
      const args = splitArgs(src, open, close);
      const a0 = args[0];
      const a1 = args[1];
      if (a0 === undefined || a1 === undefined) return;
      if (!/^(["'`])set-cookie\1$/i.test(text.slice(a0.start, a0.end).trim())) return;
      const q = code[a1.start];
      if (q !== '"' && q !== "'" && q !== "`") return;
      if (code[a1.end - 1] !== q) return;
      const value = text.slice(a1.start + 1, a1.end - 1);
      const f = flagsOfHeaderString(value);
      if (value.slice(value.indexOf(";") < 0 ? value.length : value.indexOf(";")).includes("${")) {
        if (f.httpOnly === "missing") f.httpOnly = "dynamic";
        if (f.secure === "missing") f.secure = "dynamic";
        if (f.sameSite === "missing") f.sameSite = "dynamic";
      }
      const name = f.name ?? "";
      const eq = value.indexOf("=");
      const valueText = eq < 0 ? "" : (value.split(";")[0] ?? "").slice(eq + 1);
      seen.add(open);
      sites.push({
        kind: "header",
        start: open,
        end: close,
        name,
        flags: f,
        defaultsOff: true,
        session:
          !!valueText.trim() && !valueText.includes("${") ? false : classify(name, valueText),
        refresh: isRefreshCookie(name, valueText),
        deletes: f.deletes,
      });
    });
  }

  // session configuration objects
  const configSite = (kind: CookieKind, start: number, end: number, flags: CookieFlags): void => {
    if (seen.has(start)) return;
    seen.add(start);
    sites.push({
      kind,
      start,
      end,
      name: "session",
      flags,
      defaultsOff: false,
      session: true,
      refresh: false,
      deletes: flags.deletes,
    });
  };
  const configCalls = (mod: string, kind: "express-session" | "cookie-session"): void => {
    for (const name of boundNames(src, mod)) {
      eachMatch(new RegExp(String.raw`(?<![\w$.])${escapeRe(name)}\s*\(`, "g"), (_m, open) => {
        const close = src.matchOf(open);
        if (close < 0) return;
        const a0 = splitArgs(src, open, close)[0];
        if (a0 === undefined) return;
        const obj = objectOpenOf(src, a0);
        let flags: CookieFlags;
        if (obj === undefined) flags = { ...DYNAMIC_FLAGS };
        else if (kind === "cookie-session") flags = readCookieFlags(src, obj);
        else {
          const entries = objectEntries(src, obj) ?? [];
          const cookie = entries.find((e) => e.key === "cookie");
          if (cookie?.value !== undefined)
            flags = flagsOfArgument(src, cookie.value.start, cookie.value.end);
          else if (entries.some((e) => e.spread !== undefined || e.computed))
            flags = { ...DYNAMIC_FLAGS };
          else flags = { ...MISSING_FLAGS };
        }
        configSite(kind, open, close, flags);
      });
    }
  };
  configCalls("express-session", "express-session");
  configCalls("cookie-session", "cookie-session");

  if (text.includes("iron-session") && codeMatchExists(src, /["']iron-session["']/g)) {
    eachMatch(/(?<![\w$.])cookieOptions\s*:\s*/g, (m) => {
      const valueStart = nextNonWs(code, m.index + m[0].length);
      let end = valueStart;
      if (code[valueStart] === "{") end = src.matchOf(valueStart) + 1;
      else {
        const id = /^[A-Za-z_$][\w$]*/.exec(code.slice(valueStart, valueStart + 80));
        end = valueStart + (id?.[0].length ?? 0);
      }
      if (end <= valueStart) return;
      configSite("iron-session", m.index, end, flagsOfArgument(src, valueStart, end));
    });
  }

  return sites.sort((a, b) => a.start - b.start);
}
