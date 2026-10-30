// ─────────────────────────────────────────────────────────────────────────────
// Auth Bypass Detector
//
// Three ways server code skips the check it appears to perform:
//  - `auth/jwt-decode-without-verify`: a request token is only base64-decoded and its claims
//    gate access (nothing verifies the signature).
//  - `auth/auth-disabled-outside-production`: an auth middleware returns early when the
//    environment is not production (or a SKIP_AUTH-style flag is set).
//  - `auth/secret-check-fails-open`: `if (SECRET && header !== SECRET) return 401` skips the
//    whole check when the secret env var is unset.
// ─────────────────────────────────────────────────────────────────────────────

import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { makeFinding } from "./utils/finding.js";
import { classifyFile, isServerScope } from "./utils/file-kind.js";
import { getJsSource, type JsSource } from "./utils/js-source.js";
import {
  enclosingFunction,
  expressionEnd,
  extractFunctions,
  type FunctionSpan,
} from "./utils/js-functions.js";

const MAX_PER_FILE = 25;
const MAX_BYTES = 600_000;

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Offset just past the `)` closing the call whose `(` is at `open`, or -1. */
function closeOf(src: JsSource, open: number): number {
  const m = src.matchOf(open);
  return m > open ? m : -1;
}

/** The text of a branch starting at `from` (after an `if (...)`): a block or one statement. */
function branchOf(src: JsSource, from: number): { start: number; end: number; block: boolean } {
  let i = from;
  while (i < src.code.length && /\s/.test(src.code[i]!)) i++;
  if (src.code[i] === "{") {
    const m = src.matchOf(i);
    return { start: i + 1, end: m > i ? m : Math.min(src.code.length, i + 400), block: true };
  }
  let end = i;
  while (end < src.code.length && src.code[end] !== ";" && src.code[end] !== "\n") end++;
  // allow `return x\n  .y()` style: extend a trailing-dot / open bracket line
  return { start: i, end: Math.min(end + 1, src.code.length), block: false };
}

const DENY_RE =
  /\b(?:throw\b|return\b[^;\n]{0,200}?(?:\b4\d\d\b|\b5\d\d\b|[Uu]nauthori[sz]ed|[Ff]orbidden|\bredirect\s*\(|\bnotFound\s*\(|UNAUTHORIZED|FORBIDDEN|Error\s*\())/;

interface IfStmt {
  /** offset of `if` */
  at: number;
  condStart: number;
  condEnd: number;
  /** text of the condition (without the parentheses) */
  cond: string;
  codeCond: string;
  branch: { start: number; end: number; block: boolean };
  /** offset just past the whole if statement's consequent */
  after: number;
}

function findIfs(src: JsSource): IfStmt[] {
  const out: IfStmt[] = [];
  const re = /\bif\s*\(/g;
  for (let m = re.exec(src.code); m; m = re.exec(src.code)) {
    const open = m.index + m[0].length - 1;
    const close = closeOf(src, open);
    if (close < 0) continue;
    const branch = branchOf(src, close + 1);
    out.push({
      at: m.index,
      condStart: open + 1,
      condEnd: close,
      cond: src.text.slice(open + 1, close),
      codeCond: src.code.slice(open + 1, close),
      branch,
      after: branch.block ? branch.end + 1 : branch.end,
    });
  }
  return out;
}

/** Top-level operands of `&&` (or undefined when a top-level `||` exists). */
function andOperands(code: string, text: string): string[] | undefined {
  const parts: string[] = [];
  let depth = 0;
  let last = 0;
  for (let i = 0; i < code.length; i++) {
    const c = code[i]!;
    if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") depth--;
    else if (depth === 0 && c === "|" && code[i + 1] === "|") return undefined;
    else if (depth === 0 && c === "&" && code[i + 1] === "&") {
      parts.push(text.slice(last, i));
      last = i + 2;
      i++;
    }
  }
  parts.push(text.slice(last));
  return parts.map((p) => p.trim()).filter((p) => p.length > 0);
}

// ─── jwt-decode-without-verify ───────────────────────────────────────────────

const DECODE_CALL_RE =
  /(?:\b(?:jwt|jsonwebtoken|jose)\s*\.\s*decode|\bdecodeJwt|\bjwtDecode|\bjwt_decode|\bdecode_jwt)\s*(?:<[^>()]*>)?\s*\(/g;
const MANUAL_DECODE_RE =
  /JSON\s*\.\s*parse\s*\(\s*(?:Buffer\s*\.\s*from|atob)\s*\(\s*([A-Za-z_$][\w$]*(?:\??\.\s*[A-Za-z_$][\w$]*)*)\s*\.\s*split\s*\(\s*['"]\.['"]\s*\)\s*\[\s*1\s*\]/g;
const REQUEST_SOURCE_RE =
  /\bsearchParams\s*\.\s*get\s*\(|\bheaders\s*(?:\(\s*\))?\s*\.\s*get\s*\(|\bcookies\s*(?:\(\s*\))?\s*\.\s*get\s*\(|\b(?:req|request|ctx|event)\s*\.\s*(?:query|headers|cookies|body|params|nextUrl)\b|\bgetHeader\s*\(|\bgetCookie\s*\(/;
const TOKENISH_RE = /token|jwt|bearer|session|credential|auth/i;
const TIME_CLAIMS = new Set(["exp", "iat", "nbf"]);
const VERIFY_CALL_RE =
  /(?:\bjwt\s*\.\s*verify|\bjwtVerify|\bverifyToken|\bverifyJwt|\bverifyJWT|\bverify[A-Za-z]*Token|\bvalidate[A-Za-z]*|\bauthenticate[A-Za-z]*|\bcheck[A-Za-z]*Token|\.\s*verify)\s*(?:<[^>()]*>)?\s*\(/g;

/** Names (and the whole-binding name) a statement before `callStart` binds the call result to. */
function resultBinding(src: JsSource, callStart: number): { names: string[]; whole: boolean } {
  const none = { names: [] as string[], whole: false };
  let i = callStart - 1;
  while (i >= 0 && src.code[i] !== ";" && src.code[i] !== "\n") i--;
  const head = src.code.slice(i + 1, callStart);
  const textHead = src.text.slice(i + 1, callStart);
  const m =
    /(?:const|let|var)\s+(\{[^}]*\}|[A-Za-z_$][\w$]*)\s*(?::[^=]*)?=\s*(?:await\s+)?\(?\s*(?:\(\s*)?$/.exec(
      textHead,
    );
  if (!m || head.trim().length === 0) return none;
  const pat = m[1]!;
  if (pat.startsWith("{")) {
    const names = pat
      .slice(1, -1)
      .split(",")
      .map((p) =>
        p
          .split(":")
          .pop()!
          .split("=")[0]!
          .trim()
          .replace(/^\.\.\./, ""),
      )
      .filter((p) => /^[A-Za-z_$][\w$]*$/.test(p));
    return { names, whole: false };
  }
  return { names: [pat], whole: true };
}

function bodyRange(span: FunctionSpan | undefined, src: JsSource): [number, number] {
  return span ? [span.bodyStart, span.bodyEnd] : [0, src.code.length];
}

const MAX_DECLS = 1500;
const MAX_RHS = 400;
const MAX_TAINTED = 800;
const MAX_SITES = 200;
const MAX_ALIAS_SCAN = 20000;

/** Code text of `[from,to)` with comments blanked but string-literal contents kept. */
function codeAndStrings(src: JsSource, from: number, to: number): string {
  let out = "";
  let i = from;
  const blank = (k: number): boolean => src.code[k] === " " && /\S/.test(src.text[k]!);
  while (i < to) {
    if (!blank(i)) {
      out += src.code[i];
      i++;
      continue;
    }
    let j = i;
    while (j < to && blank(j)) j++;
    const prev = src.code[i - 1] ?? "";
    const isString =
      prev === '"' ||
      prev === "'" ||
      prev === "`" ||
      (prev === "}" && (src.text[j] === "`" || src.text.slice(j, j + 2) === "${"));
    out += isString ? src.text.slice(i, j) : " ".repeat(j - i);
    i = j;
  }
  return out;
}

/** Identifier names the file binds from request-derived expressions (computed once per file). */
function requestBindings(src: JsSource): Set<string> {
  const tainted = new Set<string>();
  const re = /(?:const|let|var)\s+(\{[^}]{0,300}\}|[A-Za-z_$][\w$]*)\s*(?::[^=;]{0,120})?=/g;
  interface Decl {
    names: string[];
    direct: boolean;
    ids: string[];
  }
  const decls: Decl[] = [];
  for (let m = re.exec(src.code); m && decls.length < MAX_DECLS; m = re.exec(src.code)) {
    const rhsStart = m.index + m[0].length;
    const limit = Math.min(src.code.length, rhsStart + MAX_RHS);
    const rhs = src.text.slice(rhsStart, Math.min(limit, expressionEnd(src, rhsStart, limit)));
    const pat = /(?:const|let|var)\s+(\{[^}]*\}|[A-Za-z_$][\w$]*)/.exec(
      src.text.slice(m.index, rhsStart),
    );
    const pt = pat?.[1] ?? m[1]!;
    const names: string[] = [];
    if (pt.startsWith("{")) {
      for (const part of pt.slice(1, -1).split(",")) {
        const n = part.split(":").pop()!.split("=")[0]!.trim();
        if (/^[A-Za-z_$][\w$]*$/.test(n)) names.push(n);
      }
    } else names.push(pt);
    decls.push({
      names,
      direct: REQUEST_SOURCE_RE.test(rhs),
      ids: rhs.match(/[A-Za-z_$][\w$]*/g) ?? [],
    });
  }
  for (let pass = 0; pass < 4; pass++) {
    let changed = false;
    for (const d of decls) {
      if (d.names.every((n) => tainted.has(n))) continue;
      if (d.direct || d.ids.some((id) => tainted.has(id))) {
        for (const n of d.names) {
          if (!tainted.has(n) && tainted.size < MAX_TAINTED) {
            tainted.add(n);
            changed = true;
          }
        }
      }
    }
    if (!changed) break;
  }
  return tainted;
}

interface DecodeSite {
  start: number;
  argText: string;
  ident: string | undefined;
}

function decodeSites(src: JsSource): DecodeSite[] {
  const sites: DecodeSite[] = [];
  DECODE_CALL_RE.lastIndex = 0;
  for (let m = DECODE_CALL_RE.exec(src.code); m; m = DECODE_CALL_RE.exec(src.code)) {
    const open = m.index + m[0].length - 1;
    const close = closeOf(src, open);
    if (close < 0) continue;
    const args = src.text.slice(open + 1, close);
    const first = (args.split(",")[0] ?? "").trim();
    // a first argument holding its own commas (calls) keeps the whole text
    const argText = /^[A-Za-z_$][\w$.?!]*$/.test(first) ? first : args.trim();
    const ident = /^[A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*)*$/.test(argText)
      ? argText.replace(/\?/g, "")
      : undefined;
    sites.push({ start: m.index, argText, ident });
  }
  MANUAL_DECODE_RE.lastIndex = 0;
  for (let m = MANUAL_DECODE_RE.exec(src.text); m; m = MANUAL_DECODE_RE.exec(src.text)) {
    if (src.code[m.index] !== "J") continue;
    sites.push({ start: m.index, argText: m[1]!, ident: m[1]!.replace(/\?/g, "") });
  }
  return sites;
}

/** Whether the file verifies `argText`/`ident` somewhere. */
function verifiedInFile(src: JsSource, site: DecodeSite): boolean {
  const norm = (s: string): string => s.replace(/\s+/g, "").replace(/\?/g, "");
  const target = norm(site.argText);
  VERIFY_CALL_RE.lastIndex = 0;
  for (let m = VERIFY_CALL_RE.exec(src.code); m; m = VERIFY_CALL_RE.exec(src.code)) {
    const open = m.index + m[0].length - 1;
    const close = closeOf(src, open);
    if (close < 0) continue;
    const args = norm(src.text.slice(open + 1, close));
    if (site.ident !== undefined) {
      const first = args.split(",")[0] ?? "";
      if (
        first === target ||
        first === `await${target}` ||
        new RegExp(`(?:^|[^\\w$.])${escapeRe(target)}(?![\\w$])`).test(args)
      ) {
        return true;
      }
    } else if (args.includes(target)) return true;
  }
  return false;
}

type Gate = "none" | "time" | "claim";

/**
 * Whether the decoded value gates access in `[from,to)`. `whole` are names bound to the whole
 * payload (a claim member is required); `bare` names are already claims (destructured or
 * aliased). "time" means only exp/iat/nbf are gated.
 */
function gatesAccess(
  src: JsSource,
  whole: readonly string[],
  bare: readonly string[],
  from: number,
  to: number,
  ifs: readonly IfStmt[],
): Gate {
  const all = [...whole, ...bare];
  if (all.length === 0) return "none";
  const alt = all.map(escapeRe).join("|");
  const bareRe =
    bare.length > 0
      ? new RegExp(`(?:^|[^\\w$.])(?:${bare.map(escapeRe).join("|")})(?![\\w$])`)
      : undefined;
  const memberRe =
    whole.length > 0
      ? new RegExp(
          `(?:^|[^\\w$.])(?:${whole.map(escapeRe).join("|")})\\s*\\??\\.\\s*([\\w$]+)`,
          "g",
        )
      : undefined;
  let best = "none" as Gate;
  const note = (g: Gate): void => {
    if (g === "claim" || (g === "time" && best === "none")) best = g;
  };
  for (const s of ifs) {
    if (s.at < from || s.at >= to) continue;
    if (!DENY_RE.test(src.code.slice(s.branch.start, s.branch.end))) continue;
    if (bareRe?.test(s.codeCond)) note("claim");
    if (memberRe) {
      memberRe.lastIndex = 0;
      for (let m = memberRe.exec(s.codeCond); m; m = memberRe.exec(s.codeCond)) {
        note(TIME_CLAIMS.has(m[1]!) ? "time" : "claim");
      }
    }
    if (best === "claim") return best;
  }
  const body = src.code.slice(from, to);
  const cmp = new RegExp(
    `(?:(?:^|[^\\w$.])(?:${alt})\\??\\.([\\w$]+)\\s*(?:===|!==|==|!=))|(?:(?:===|!==|==|!=)\\s*(?:${alt})\\??\\.([\\w$]+))`,
    "g",
  );
  for (let m = cmp.exec(body); m; m = cmp.exec(body)) {
    const tail = body.slice(m.index, m.index + 320);
    if (DENY_RE.test(tail)) note(TIME_CLAIMS.has(m[1] ?? m[2] ?? "") ? "time" : "claim");
    if (best === "claim") return best;
  }
  const lookup = new RegExp(
    `\\b(?:where|filter)\\s*:\\s*\\{[^{}]*?(?:^|[^\\w$.])(?:${alt})\\??\\.[\\w$]+|\\.\\s*eq\\s*\\([^,()]*,\\s*(?:${alt})\\??\\.[\\w$]+|\\b(?:findById|findOne|findUnique|getUserById|getUser|getById)\\s*\\(\\s*(?:\\{[^}]*?)?(?:${alt})\\??\\.[\\w$]+`,
  );
  if (lookup.test(body)) return "claim";
  return best;
}

function jwtFindings(
  src: JsSource,
  file: string,
  spans: readonly FunctionSpan[],
  getBindings: () => Set<string>,
): Finding[] {
  const out: Finding[] = [];
  const ifs = findIfs(src);
  const seen = new Set<number>();
  for (const site of decodeSites(src).slice(0, MAX_SITES)) {
    if (out.length >= MAX_PER_FILE) break;
    const line = src.lineAt(site.start);
    if (seen.has(line)) continue;
    const span = enclosingFunction(spans, site.start);
    const [, to] = bodyRange(span, src);
    // token provenance
    const root = site.ident?.split(/[.]/)[0];
    let requestDerived = REQUEST_SOURCE_RE.test(site.argText);
    if (!requestDerived && root !== undefined) {
      requestDerived = getBindings().has(root);
    }
    let tokenParam = false;
    if (!requestDerived && root !== undefined && span) {
      tokenParam = span.params.some((p) => p.names.includes(root)) && TOKENISH_RE.test(root);
    }
    if (!requestDerived && !tokenParam) continue;
    if (verifiedInFile(src, site)) continue;
    // decoded binding(s)
    const open = src.code.indexOf("(", site.start);
    const { names, whole: wholeBinding } = resultBinding(src, site.start);
    let gate: Gate = "none";
    if (names.length > 0) {
      // aliases: `const id = claims.sub`
      const aliases = new Set<string>();
      const aliasRe = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;]*)?=\s*([^;\n]+)/g;
      const afterCall = open >= 0 ? open : site.start;
      const bodyText = src.text.slice(afterCall, Math.min(to, afterCall + MAX_ALIAS_SCAN));
      const nameRes = names.map((n) => new RegExp(`\\b${escapeRe(n)}\\b`));
      for (let m = aliasRe.exec(bodyText); m; m = aliasRe.exec(bodyText)) {
        if (!src.code.slice(afterCall + m.index, afterCall + m.index + 3).match(/con|let|var/)) {
          continue;
        }
        const rhs = m[2]!;
        if (nameRes.some((re) => re.test(rhs))) aliases.add(m[1]!);
      }
      const whole = wholeBinding ? names : [];
      const bare = wholeBinding ? [...aliases] : [...names, ...aliases];
      gate = gatesAccess(src, whole, bare, afterCall, to, ifs);
    } else {
      // inline: `if (jwt.decode(t).role !== "admin") return 403`
      const closeCall = open >= 0 ? closeOf(src, open) : -1;
      const after = closeCall >= 0 ? src.code.slice(closeCall + 1, closeCall + 80) : "";
      const inlineMember =
        /^\s*(?:as\s+[\w.<>[\]|]+\s*)?\)?\s*\??\.\s*[\w$]+\s*(?:===|!==|==|!=)/.test(after);
      const inIf = ifs.find((s) => s.condStart <= site.start && site.start < s.condEnd);
      const denied =
        inIf !== undefined
          ? DENY_RE.test(src.code.slice(inIf.branch.start, inIf.branch.end))
          : inlineMember && DENY_RE.test(src.code.slice(site.start, site.start + 320));
      if (denied) {
        const claim = /^\s*(?:as\s+[\w.<>[\]|]+\s*)?\)?\s*\??\.\s*([\w$]+)/.exec(after)?.[1];
        gate = claim !== undefined && TIME_CLAIMS.has(claim) ? "time" : "claim";
      }
    }
    if (gate === "none") continue;
    seen.add(line);
    out.push(
      makeFinding({
        category: "auth",
        ruleId: "auth/jwt-decode-without-verify",
        title: "Access decision uses a JWT that was only decoded, never verified",
        severity: "high",
        confidence: requestDerived && gate === "claim" ? "high" : "medium",
        file,
        line,
        evidence: src.lineText(line),
        plainEnglishProblem: `The token on line ${line} is only base64-decoded, and its claims then decide whether the request is allowed or which record it may reach. Nothing in this file checks the token's signature.`,
        whyItMatters:
          "A decoded token is just text the caller wrote. Anyone can forge one with the document id, user id or role they want and pass this check.",
        fixSteps: [
          "Verify the token with the signing key before reading any claim: jwt.verify(token, secret, { algorithms: ['HS256'] }) or jose's jwtVerify.",
          "Reject the request with 401/403 when verification throws.",
          "Only read claims from the verified payload and keep decode for non-security uses such as showing an expiry in the UI.",
        ],
        aiFixPrompt:
          "This server code decodes a JWT from the request (jwt.decode, jwtDecode, decodeJwt or a manual base64 split) and then uses its claims to allow or deny access or to look up a record, without verifying the signature. Replace the decode call with signature verification (jwt.verify with an explicit algorithms list, or jose jwtVerify) using a key from the environment, return 401 when it fails, and read claims only from the verified payload.",
        learnMoreUrl:
          "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
      }),
    );
  }
  return out;
}

// ─── auth-disabled-outside-production ────────────────────────────────────────

const AUTH_FN_RE =
  /auth|authenticate|requireUser|requireAdmin|protect|guard|verify(?:Token|Session|Request)/i;
const ENV_NAME = "(?:NODE_ENV|nodeEnv|APP_ENV|ENVIRONMENT)";
const NONPROD_RES: readonly RegExp[] = [
  new RegExp(`${ENV_NAME}\\s*(?:!==|!=)\\s*['"\`]production['"\`]`),
  new RegExp(`['"\`]production['"\`]\\s*(?:!==|!=)\\s*[\\w$.]*${ENV_NAME}`),
  new RegExp(`${ENV_NAME}\\s*(?:===|==)\\s*['"\`](?:development|dev|local)['"\`]`),
  /!\s*(?:isProd|isProduction)\b/,
  /(?<!!\s*(?:[\w$]+\s*\.\s*)*)(?<![\w$])isDev(?:elopment)?\b(?!\s*\()/,
];
const FLAG_RE =
  /(?<!!\s*)\b(?:process\s*\.\s*env\s*\.\s*)?(?:SKIP_AUTH|DISABLE_AUTH|AUTH_DISABLED|BYPASS_AUTH|skipAuth|disableAuth|authDisabled|bypassAuth)\b/;
const ALLOW_RE =
  /\breturn\s+(?:await\s+)?(?:next\s*\(\s*\)|NextResponse\s*\.\s*next\s*\(|true\b)|\bnext\s*\(\s*\)\s*;?\s*return\b/;
const BODY_DENY_RE =
  /\b40[13]\b|[Uu]nauthori[sz]ed|[Ff]orbidden|UNAUTHORIZED|FORBIDDEN|\bredirect\s*\([^)]{0,200}?(?:log-?in|sign-?in|sign-?on|\/auth\b)/;
const CREDENTIAL_RE = /session|token|cookie|authorization|\buser\b|bearer|jwt|credential|\bauth\b/i;
const NON_AUTH_NAME_RE = /csrf|xsrf|cors|helmet|rate-?limit/i;

function isAuthMiddleware(span: FunctionSpan, file: string, kind: string): boolean {
  if (span.name !== undefined && AUTH_FN_RE.test(span.name)) return true;
  if (span.exportName === "default" && /(^|\/)middleware\//i.test(file)) return true;
  return kind === "next-middleware" && span.role === "middleware";
}

function envFindings(
  src: JsSource,
  file: string,
  kind: string,
  spans: readonly FunctionSpan[],
): Finding[] {
  const out: Finding[] = [];
  if (
    !/NODE_ENV|nodeEnv|APP_ENV|ENVIRONMENT|isProd|isDev|SKIP_AUTH|DISABLE_AUTH|AUTH_DISABLED|BYPASS_AUTH|skipAuth|disableAuth|authDisabled|bypassAuth/.test(
      src.code,
    )
  ) {
    return out;
  }
  const ifs = findIfs(src);
  for (const span of spans) {
    if (span.kind === "module" || span.expressionBody) continue;
    if (!isAuthMiddleware(span, file, kind)) continue;
    const bodyCode = codeAndStrings(src, span.bodyStart, span.bodyEnd);
    if (!BODY_DENY_RE.test(bodyCode)) continue;
    // a middleware that never touches a credential (geo-block, host redirect) is not auth
    if (!(span.name !== undefined && AUTH_FN_RE.test(span.name)) && !CREDENTIAL_RE.test(bodyCode)) {
      continue;
    }
    const subject =
      span.name !== undefined && NON_AUTH_NAME_RE.test(span.name)
        ? "CSRF protection"
        : "Authentication";
    for (const s of ifs) {
      if (out.length >= MAX_PER_FILE) return out;
      if (s.at < span.bodyStart || s.at >= span.bodyEnd) continue;
      if (enclosingFunction(spans, s.at) !== span) continue;
      const branchCode = src.code.slice(s.branch.start, s.branch.end);
      const allow = ALLOW_RE.exec(branchCode);
      if (!allow || DENY_RE.test(branchCode.slice(0, allow.index))) continue;
      const cond = s.cond;
      const nonProd = NONPROD_RES.some((r) => r.test(cond));
      const flag = !nonProd && FLAG_RE.test(cond);
      if (!nonProd && !flag) continue;
      // a bypass that also requires something from the request (secret header, token) is not open
      const operands = andOperands(s.codeCond, s.cond);
      if (operands !== undefined && operands.length > 1) {
        const rest = operands.filter(
          (o) => !NONPROD_RES.some((r) => r.test(o)) && !FLAG_RE.test(o),
        );
        if (rest.some((o) => /header|secret|token|key|cookie|query|req\b|request/i.test(o))) {
          continue;
        }
      }
      const line = src.lineAt(s.at);
      out.push(
        makeFinding({
          category: "auth",
          ruleId: "auth/auth-disabled-outside-production",
          title: flag
            ? `${subject} can be switched off with an environment flag`
            : `${subject} is skipped when NODE_ENV is not production`,
          severity: flag ? "medium" : "high",
          confidence: "medium",
          file,
          line,
          evidence: src.lineText(line),
          plainEnglishProblem: flag
            ? "This auth middleware returns early and lets every request through when an environment flag is set."
            : "This auth middleware lets every request through unless NODE_ENV is exactly 'production'.",
          whyItMatters:
            "Staging, preview and misconfigured deployments often run without NODE_ENV=production (or with the flag set), which leaves the whole protected API open to anyone who can reach it.",
          fixSteps: [
            "Remove the early return so the token check always runs.",
            "For local development, use a real dev token or a seeded test user instead of disabling the check.",
            "If a bypass must exist, fail closed: require NODE_ENV to be explicitly 'development' AND a secret header, and never enable it on hosted environments.",
          ],
          aiFixPrompt:
            "This authentication middleware returns next() early when NODE_ENV is not 'production' (or when a SKIP_AUTH-style flag is set), so any non-production deployment is unauthenticated. Remove the bypass so the credential check always runs, and give local development a real dev token or test user instead.",
        }),
      );
    }
  }
  return out;
}

// ─── secret-check-fails-open ─────────────────────────────────────────────────

const SECRET_NAME_RE = /SECRET|TOKEN|KEY|PASSWORD|AUTH/;
const NOT_SECRET_RE = /URL|URI|HOST|ORIGIN|^NEXT_PUBLIC_|PUBLIC|ENABLED|DISABLED|ISSUER/;

function secretBindings(src: JsSource): Map<string, string> {
  const map = new Map<string, string>();
  const re =
    /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;]*)?=\s*(?:\(\s*)?process\s*\.\s*env\s*\.\s*([A-Z0-9_]+)\s*(?:as\s+string\s*)?!?\s*(?:(?:\?\?|\|\|)\s*(?:''|""|``)\s*)?\)?\s*(?:;|\n|$)/g;
  for (let m = re.exec(src.code); m; m = re.exec(src.code)) {
    const name = src.text
      .slice(m.index, m.index + m[0].length)
      .match(/process\s*\.\s*env\s*\.\s*([A-Z0-9_]+)/);
    const envName = name?.[1];
    if (envName && SECRET_NAME_RE.test(envName) && !NOT_SECRET_RE.test(envName)) {
      map.set(m[1]!, envName);
    }
  }
  return map;
}

const REQUEST_REF_RE =
  /\b(?:req|request|ctx|event)\b|\bheaders?\s*(?:\(\s*\))?\s*[.[]|\bsearchParams\b|\bcookies?\b|\bgetHeader\s*\(|\bgetCookie\s*\(|\bauthorization\b/i;

function failOpenFindings(
  src: JsSource,
  file: string,
  spans: readonly FunctionSpan[],
  getBindings: () => Set<string>,
): Finding[] {
  const out: Finding[] = [];
  if (!src.code.includes("process") || !src.code.includes("env")) return out;
  const bindings = secretBindings(src);
  const ifs = findIfs(src);
  const direct = /process\s*\.\s*env\s*\.\s*([A-Z0-9_]+)/;
  const secretTermOf = (operand: string): string | undefined => {
    const t = operand
      .trim()
      .replace(/^!!\s*/, "")
      .replace(/^Boolean\(\s*([^)]*)\)$/, "$1")
      .trim();
    const dm = new RegExp(`^${direct.source}$`).exec(t);
    if (dm && SECRET_NAME_RE.test(dm[1]!) && !NOT_SECRET_RE.test(dm[1]!)) return t;
    const nm = /^([A-Za-z_$][\w$]*)(?:\s*(?:!==|!=)\s*(?:undefined|null|['"]{2}))?$/.exec(t);
    if (nm && bindings.has(nm[1]!)) return nm[1]!;
    return undefined;
  };
  const mentions = (text: string, term: string): boolean =>
    new RegExp(`(?:^|[^\\w$.])${escapeRe(term)}(?![\\w$])`).test(text);
  /** The compare operand must involve request data (not the secret itself or a literal). */
  const requestish = (cond: string, term: string, at: number): boolean => {
    const rest = cond
      .replace(new RegExp(`(?:^|[^\\w$.])${escapeRe(term)}(?![\\w$])`, "g"), " ")
      .replace(/process\s*\.\s*env\s*\.\s*[A-Z0-9_]+/g, " ");
    if (REQUEST_REF_RE.test(rest)) return true;
    const ids = rest.match(/[A-Za-z_$][\w$]*/g) ?? [];
    if (ids.length === 0) return false;
    const span = enclosingFunction(spans, at);
    const params = new Set<string>();
    for (const p of span?.params ?? []) for (const n of p.names) if (n !== term) params.add(n);
    const tainted = getBindings();
    return ids.some((id) => id !== term && (params.has(id) || tainted.has(id)));
  };
  const compares = (cond: string, term: string, at: number): boolean => {
    if (!mentions(cond, term)) return false;
    if (!/!==?|(?:^|[^\w$])!\s*[\w$.]+\s*\(/.test(cond)) return false;
    return requestish(cond, term, at);
  };
  const guardedEarlier = (term: string, at: number): boolean => {
    const span = enclosingFunction(spans, at);
    const lo = span ? span.bodyStart : 0;
    const guardRe = new RegExp(`^\\s*!\\s*(?:\\(\\s*)?${escapeRe(term)}\\s*\\)?\\s*(?:\\|\\||$)`);
    return ifs.some((g) => {
      if (g.at >= at) return false;
      if (g.at < lo) {
        // a module-scope guard placed before the handler also fails closed
        const owner = enclosingFunction(spans, g.at);
        if (owner !== undefined && owner.kind !== "module") return false;
      }
      return guardRe.test(g.cond) && DENY_RE.test(src.code.slice(g.branch.start, g.branch.end));
    });
  };
  const nestedDenyIf = (s: IfStmt, term: string): IfStmt | undefined => {
    if (!s.branch.block) return undefined;
    return ifs.find(
      (n) =>
        n.at > s.branch.start &&
        n.at < s.branch.end &&
        compares(n.codeCond, term, n.at) &&
        DENY_RE.test(src.code.slice(n.branch.start, n.branch.end)),
    );
  };
  const hasElse = (s: IfStmt): boolean => /^\s*else\b/.test(src.code.slice(s.after, s.after + 20));
  const reported = new Set<number>();
  for (const s of ifs) {
    if (out.length >= MAX_PER_FILE) break;
    let term: string | undefined;
    const ops = andOperands(s.codeCond, s.codeCond);
    if (ops === undefined) continue;
    if (ops.length >= 2) {
      // `S && <compare involving S>`
      for (const o of ops) {
        const t = secretTermOf(o);
        if (t === undefined) continue;
        const cmpOp = ops.find((p) => p !== o && compares(p, t, s.at));
        if (cmpOp !== undefined && DENY_RE.test(src.code.slice(s.branch.start, s.branch.end))) {
          term = t;
          break;
        }
      }
    } else if (ops.length === 1) {
      // `if (S) { if (x !== S) return 401 }`
      const t = secretTermOf(ops[0]!);
      if (t !== undefined && !hasElse(s) && nestedDenyIf(s, t) !== undefined) term = t;
    }
    if (term === undefined) continue;
    if (guardedEarlier(term, s.at)) continue;
    const line = src.lineAt(s.at);
    if (reported.has(line)) continue;
    reported.add(line);
    out.push(
      makeFinding({
        category: "auth",
        ruleId: "auth/secret-check-fails-open",
        title: "Secret check is skipped when the secret is not configured",
        severity: "high",
        confidence: "high",
        file,
        line,
        evidence: src.lineText(line),
        plainEnglishProblem:
          "The request is only rejected when the secret environment variable is set and the caller's value differs. If the variable is missing, the whole check is skipped and the endpoint is public.",
        whyItMatters:
          "A forgotten or mistyped variable in one environment silently turns a protected endpoint (cron, webhook, internal API) into an open one that anyone can call.",
        fixSteps: [
          "Fail closed: reject the request when the secret is not configured (`if (!secret || header !== `Bearer ${secret}`) return 401`).",
          "Or throw at startup when the variable is missing so the misconfiguration cannot ship.",
          "Compare with a constant-time function such as crypto.timingSafeEqual.",
        ],
        aiFixPrompt:
          "This handler checks a shared secret only when the secret env var is set (`if (secret && header !== secret) return 401`), so an unset variable makes the endpoint public. Change it to fail closed: return 401 (or 500) when the secret is missing OR when the supplied value does not match, ideally with a constant-time comparison.",
      }),
    );
  }
  return out;
}

export class AuthBypassDetector implements Detector {
  id = "auth-bypass-detector";
  name = "Auth Bypass Detection";
  category = "auth" as const;
  description =
    "Detects JWTs that are decoded but never verified, auth middleware disabled outside production, and secret checks that fail open.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of context.files) {
      try {
        const text = await context.readFile(file);
        if (!text || text.length > MAX_BYTES) continue;
        const cls = classifyFile(file, text, context.projectContext);
        if (!isServerScope(cls) || cls.testOrFixture || cls.generated) continue;
        const wantsJwt = /decode|jwt_decode|split\s*\(/i.test(text);
        const wantsEnv =
          /NODE_ENV|nodeEnv|APP_ENV|ENVIRONMENT|isProd|isDev|SKIP_AUTH|DISABLE_AUTH|AUTH_DISABLED|BYPASS_AUTH|skipAuth|disableAuth|authDisabled|bypassAuth/.test(
            text,
          );
        const wantsSecret = text.includes("process.env") || /process\s*\.\s*env/.test(text);
        if (!wantsJwt && !wantsEnv && !wantsSecret) continue;
        const src = await getJsSource(context, file);
        const spans = extractFunctions(src, cls);
        let bindings: Set<string> | undefined;
        const getBindings = (): Set<string> => (bindings ??= requestBindings(src));
        if (wantsJwt) findings.push(...jwtFindings(src, file, spans, getBindings));
        if (wantsEnv) findings.push(...envFindings(src, file, cls.kind, spans));
        if (wantsSecret) findings.push(...failOpenFindings(src, file, spans, getBindings));
      } catch {
        // detectors never throw
      }
    }
    return findings;
  }
}
