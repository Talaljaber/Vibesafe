import type { Confidence, Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { makeFinding } from "./utils/finding.js";
import { redactSpan } from "./utils/sanitize-evidence.js";
import {
  classifyFile,
  isGenerated,
  isJsLike,
  isServerScope,
  isTestOrFixturePath,
} from "./utils/file-kind.js";
import { maskCode, splitTopLevel } from "./utils/route-analyzer.js";
import { SECRET_PATTERNS, matchSecretPattern } from "./patterns/secret-patterns.js";

const MAX_PER_RULE_PER_FILE = 25;
const MAX_CALL_LENGTH = 3000;

const JWT_HINT_RE = /jsonwebtoken|\bjwt\b|\bjose\b|jwt-decode|jwtDecode|decodeJwt|\bjws\b/i;

const NS_IMPORT_RE =
  /\bimport\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s*(?:,\s*\{[^}]*\})?\s*from\s*["']jsonwebtoken["']/g;
const NS_REQUIRE_RE =
  /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*["']jsonwebtoken["']\s*\)/g;
const NAMED_IMPORT_RE =
  /\bimport\s*(?:[A-Za-z_$][\w$]*\s*,\s*)?\{([^}]*)\}\s*from\s*["']jsonwebtoken["']/g;
const NAMED_REQUIRE_RE =
  /\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\s*\(\s*["']jsonwebtoken["']\s*\)/g;
const JOSE_IMPORT_RE = /\bfrom\s*["']jose["']|\brequire\s*\(\s*["']jose["']\s*\)/;

/** Fields whose use after a decode means the token drives identity or authorization. */
const IDENTITY_FIELDS =
  "sub|userId|user_id|uid|id|role|roles|email|isAdmin|is_admin|admin|orgId|org_id|tenantId|tenant_id|permissions|scope|scopes|user";
const REQUEST_SOURCE_RE =
  /\b(?:req|request)\.(?:headers|cookies|query|body)\b|\bheaders\s*\(\s*\)|\bcookies\s*\(\s*\)|\.headers\.get\s*\(|\.cookies\.get\s*\(|\bauthorization\b|\bAuthorization\b|\bBearer\b/;
const VERIFY_PRESENT_RE = /[vV]erify\w*\s*\(|\bgetServerSession\s*\(|\bgetToken\s*\(/;

type Kind = "sign" | "verify" | "decode";

interface Call {
  kind: Kind;
  /** Offset of the callee and of the argument list's `(` and `)` (raw and masked agree). */
  start: number;
  open: number;
  close: number;
  /** Argument [start, end) offsets. */
  args: Array<[number, number]>;
  jose: boolean;
}

/**
 * The single summary finding emitted instead of the findings past the per-rule cap:
 * same rule and text, medium confidence (so at most high severity), a count as evidence.
 */
function summaryOf(first: Finding, more: number): Finding {
  return makeFinding({
    category: first.category,
    ruleId: first.ruleId,
    title: first.title,
    severity: first.severity === "critical" ? "high" : first.severity,
    confidence: "medium",
    file: first.file,
    line: first.line,
    evidence: `${more} more ${first.ruleId} findings in this file`,
    discriminator: "summary",
    plainEnglishProblem: first.plainEnglishProblem,
    whyItMatters: first.whyItMatters,
    fixSteps: first.fixSteps,
    aiFixPrompt: first.aiFixPrompt ?? "",
    learnMoreUrl: first.learnMoreUrl,
  });
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

/** Index of the bracket closing the one at `open` in masked code, or -1. */
function closingParen(code: string, open: number): number {
  let depth = 0;
  const end = Math.min(code.length, open + MAX_CALL_LENGTH);
  for (let i = open; i < end; i++) {
    const c = code[i];
    if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Removes `new TextEncoder().encode(...)`, `Buffer.from(...)` and `createSecretKey(...)` wrappers. */
function unwrapKey(expr: string): string {
  let e = expr.trim();
  for (let i = 0; i < 3; i++) {
    const m =
      /^(?:new\s+TextEncoder\s*\(\s*\)\s*\.\s*encode|Buffer\.from|(?:crypto\.)?createSecretKey)\s*\(([\s\S]*)\)$/.exec(
        e,
      );
    if (!m) break;
    e = splitTopLevel(m[1]!)[0]!.trim();
  }
  return e;
}

/** The text of a plain string literal (no interpolation), or undefined. */
function stringLiteral(expr: string): string | undefined {
  const m = /^(["'`])([^]*)\1$/.exec(expr.trim());
  if (!m) return undefined;
  if (m[1] === "`" && m[2]!.includes("${")) return undefined;
  if (m[2]!.includes(m[1]!)) return undefined;
  return m[2];
}

/**
 * Flags jsonwebtoken / jose misuse: a literal signing secret, `jwt.decode()` trusted for
 * identity without any verification in the file, the `none` algorithm, and (hygiene)
 * `jwt.verify()` without an `algorithms` allow-list.
 */
export class JwtMisuseDetector implements Detector {
  id = "jwt-misuse-detector";
  name = "JWT Misuse";
  category = "crypto" as const;
  description =
    "Detects JWTs signed with literal secrets, decoded without verification, accepting alg 'none', or verified without an algorithm allow-list.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (!isJsLike(file) || isTestOrFixturePath(file) || isGenerated(file)) continue;
      try {
        const content = await context.readFile(file);
        if (!JWT_HINT_RE.test(content) || isGenerated(file, content)) continue;
        findings.push(...this.scanFile(file, content, context));
      } catch {
        // never throw from a detector
      }
    }
    return findings;
  }

  private scanFile(file: string, content: string, context: ScanContext): Finding[] {
    const code = maskCode(content);
    const starts = lineStartsOf(code);
    const lines = content.split("\n");
    const calls = this.findCalls(content, code);
    const out: Finding[] = [];
    const count = new Map<string, number>();
    const overflow = new Map<string, { first: Finding; more: number }>();
    const push = (f: Finding): void => {
      const n = count.get(f.ruleId) ?? 0;
      if (n >= MAX_PER_RULE_PER_FILE) {
        const o = overflow.get(f.ruleId);
        if (o) o.more++;
        else overflow.set(f.ruleId, { first: f, more: 1 });
        return;
      }
      count.set(f.ruleId, n + 1);
      out.push(f);
    };
    const lineOf = (offset: number): number => lineIndexAt(starts, offset) + 1;
    const flaggedCalls = new Set<number>();

    // alg "none"
    const noneRe = /\balgorithms?\s*:\s*(?:\[[^\]]{0,200}?)?(["'`])none\1/gi;
    for (const m of content.matchAll(noneRe)) {
      const at = m.index ?? 0;
      if (!/^algorithms?\b/i.test(code.slice(at, at + 11))) continue; // key is code, not text
      const plural = /^algorithms/i.test(m[0]);
      if (!plural && !this.inJwtContext(content, code)) continue;
      const line = lineOf(at);
      const call = calls.find((c) => c.open <= at && at <= c.close);
      if (call) flaggedCalls.add(call.start);
      push(this.algNoneFinding(file, line, lines[line - 1] ?? ""));
    }

    const seenLiteralLines = new Set<number>();
    for (const call of calls) {
      if (call.kind === "decode") continue;
      const keyIndex = call.jose && call.kind === "sign" ? 0 : 1;
      const keyArg = call.args[keyIndex];
      if (!keyArg) continue;
      const literal = this.literalSecret(content, code, keyArg, starts);
      if (literal) {
        flaggedCalls.add(call.start);
        if (seenLiteralLines.has(literal.line)) continue;
        seenLiteralLines.add(literal.line);
        const raw = lines[literal.line - 1] ?? "";
        // A recognised vendor key on that line is the secret detector's finding. The
        // low-confidence generic assignment heuristics do not suppress this more specific rule.
        if (
          SECRET_PATTERNS.some((p) => p.confidence !== "low" && matchSecretPattern(p, raw) !== null)
        )
          continue;
        const evidence =
          literal.value.length > 0
            ? redactSpan(raw, literal.offset - starts[literal.line - 1]!, literal.value)
            : raw;
        push(this.literalSecretFinding(file, literal.line, evidence));
      }
    }

    // verify without an algorithms allow-list (jsonwebtoken only)
    for (const call of calls) {
      if (call.kind !== "verify" || call.jose || flaggedCalls.has(call.start)) continue;
      if (!this.verifyLacksAlgorithms(code, call)) continue;
      const line = lineOf(call.start);
      push(this.verifyWithoutAlgorithmsFinding(file, line, lines[line - 1] ?? ""));
    }

    // decode trusted for auth
    const decodes = calls.filter((c) => c.kind === "decode");
    if (decodes.length > 0 && !VERIFY_PRESENT_RE.test(code)) {
      const cls = classifyFile(file, content, context.projectContext);
      if (isServerScope(cls)) {
        const fromRequest = REQUEST_SOURCE_RE.test(code);
        for (const call of decodes) {
          if (!this.decodeDrivesIdentity(code, call)) continue;
          const line = lineOf(call.start);
          push(
            this.decodeFinding(file, line, lines[line - 1] ?? "", fromRequest ? "high" : "medium"),
          );
        }
      }
    }

    for (const { first, more } of overflow.values()) out.push(summaryOf(first, more));
    return out.sort((a, b) => (a.line ?? 0) - (b.line ?? 0));
  }

  private inJwtContext(content: string, code: string): boolean {
    return (
      /jsonwebtoken|["']jose["']|["']jws["']/.test(content) ||
      /\b(?:jwt|JWT|jsonwebtoken|jose|jws)\s*\./.test(code)
    );
  }

  /** jsonwebtoken sign/verify/decode calls (namespace or named imports), jose sign/jwtVerify/decodeJwt, jwt-decode. */
  private findCalls(content: string, code: string): Call[] {
    const namespaces = new Set<string>();
    for (const re of [NS_IMPORT_RE, NS_REQUIRE_RE]) {
      re.lastIndex = 0;
      for (const m of content.matchAll(re)) namespaces.add(m[1]!);
    }
    // Code that calls jwt.sign(...) without a visible import (re-exported client, global).
    if (/\bjwt\s*\.\s*(?:sign|verify|decode)\s*\(/.test(code)) namespaces.add("jwt");
    const named = new Map<string, Kind>();
    for (const re of [NAMED_IMPORT_RE, NAMED_REQUIRE_RE]) {
      re.lastIndex = 0;
      for (const m of content.matchAll(re)) {
        for (const part of m[1]!.split(",")) {
          const pm = /^\s*(sign|verify|decode)\s*(?:(?:as|:)\s*([A-Za-z_$][\w$]*))?\s*$/.exec(part);
          if (pm) named.set(pm[2] ?? pm[1]!, pm[1] as Kind);
        }
      }
    }
    const jose = JOSE_IMPORT_RE.test(content);

    const calls: Call[] = [];
    const add = (start: number, open: number, kind: Kind, isJose: boolean): void => {
      const close = closingParen(code, open);
      if (close < 0) return;
      const inner = code.slice(open + 1, close);
      const parts = splitTopLevel(inner);
      const args: Array<[number, number]> = [];
      let pos = open + 1;
      for (const p of parts) {
        if (p.trim() !== "") args.push([pos, pos + p.length]);
        pos += p.length + 1;
      }
      calls.push({ kind, start, open, close, args, jose: isJose });
    };

    for (const ns of namespaces) {
      const re = new RegExp(
        `(?<![\\w$.])${escapeRe(ns)}\\s*\\.\\s*(sign|verify|decode)\\s*\\(`,
        "g",
      );
      for (const m of code.matchAll(re)) {
        const start = m.index ?? 0;
        add(start, start + m[0].length - 1, m[1] as Kind, false);
      }
    }
    for (const [local, kind] of named) {
      const re = new RegExp(`(?<![\\w$.])${escapeRe(local)}\\s*\\(`, "g");
      for (const m of code.matchAll(re)) {
        const start = m.index ?? 0;
        if (/\bfunction\s*$/.test(code.slice(Math.max(0, start - 20), start))) continue;
        add(start, start + m[0].length - 1, kind, false);
      }
    }
    if (jose) {
      for (const m of code.matchAll(/(?<![\w$.])jwtVerify\s*\(/g)) {
        const start = m.index ?? 0;
        add(start, start + m[0].length - 1, "verify", true);
      }
      for (const m of code.matchAll(/\.\s*sign\s*\(/g)) {
        const start = m.index ?? 0;
        // jose SignJWT chain: `new SignJWT(...)...sign(key)`; skip `jwt.sign` handled above.
        const before = code.slice(Math.max(0, start - 600), start);
        if (!/\bSignJWT\b/.test(before)) continue;
        add(start, start + m[0].length - 1, "sign", true);
      }
      for (const m of code.matchAll(/(?<![\w$.])decodeJwt\s*\(/g)) {
        const start = m.index ?? 0;
        add(start, start + m[0].length - 1, "decode", true);
      }
    }
    if (/["']jwt-decode["']/.test(content)) {
      for (const m of code.matchAll(/(?<![\w$.])(?:jwtDecode|jwt_decode)\s*\(/g)) {
        const start = m.index ?? 0;
        add(start, start + m[0].length - 1, "decode", false);
      }
    }
    return calls.sort((a, b) => a.start - b.start);
  }

  /**
   * The literal secret passed as the key argument, directly or through a `const NAME =
   * "literal"` declaration in the same file, with the line it is written on.
   */
  private literalSecret(
    content: string,
    code: string,
    arg: [number, number],
    starts: readonly number[],
  ): { value: string; line: number; offset: number } | undefined {
    const raw = content.slice(arg[0], arg[1]);
    const unwrapped = unwrapKey(raw);
    const direct = stringLiteral(unwrapped);
    if (direct !== undefined) {
      if (direct.trim() === "") return undefined;
      const at = arg[0] + raw.indexOf(unwrapped.trim().slice(0, 1));
      return { value: direct, line: lineIndexAt(starts, at) + 1, offset: at + 1 };
    }
    const ident = /^([A-Za-z_$][\w$]*)$/.exec(unwrapped.trim());
    if (!ident) return undefined;
    const declRe = new RegExp(
      `\\b(?:const|let|var)\\s+${escapeRe(ident[1]!)}\\s*(?::[^=;\\n]{0,80})?=\\s*(["'\`])`,
      "g",
    );
    for (const m of code.matchAll(declRe)) {
      const open = (m.index ?? 0) + m[0].length - 1;
      const quote = code[open];
      const close = code.indexOf(quote!, open + 1);
      if (close < 0) continue;
      const lineEnd = code.indexOf("\n", close);
      const rest = code.slice(close + 1, lineEnd < 0 ? code.length : lineEnd);
      if (!/^\s*;?\s*$/.test(rest)) continue; // `"a" || x`, `"a" + x`: not a plain literal
      const value = content.slice(open + 1, close);
      if (value.trim() === "" || (quote === "`" && value.includes("${"))) continue;
      return { value, line: lineIndexAt(starts, open) + 1, offset: open + 1 };
    }
    return undefined;
  }

  private verifyLacksAlgorithms(code: string, call: Call): boolean {
    if (call.args.length < 2) return false;
    if (call.args.length === 2) return true;
    const third = code.slice(call.args[2]![0], call.args[2]![1]).trim();
    if (third.startsWith("{")) return !/\balgorithms\s*:/.test(third);
    // A callback as the third argument means no options object.
    return /^(?:async\s+)?(?:function\b|\([^()]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)/.test(third);
  }

  /** The decoded value (or its destructured fields) is read as identity or role. */
  private decodeDrivesIdentity(code: string, call: Call): boolean {
    const before = code.slice(Math.max(0, call.start - 200), call.start);
    const stmt = before.slice(before.lastIndexOf(";") + 1);
    const destructured = /\{([^{}]*)\}\s*(?::[^=;]{0,80})?=\s*(?:await\s+)?(?:\(\s*)?$/.exec(stmt);
    if (destructured) {
      return new RegExp(`(?:^|[\\s,{])(?:${IDENTITY_FIELDS})\\b`).test(destructured[1]!);
    }
    const bound =
      /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;]{0,80})?=\s*(?:await\s+)?(?:\(\s*)?$/.exec(
        stmt,
      );
    const after = code.slice(call.close + 1, call.close + 160);
    // `jwt.decode(token).sub`, `(jwt.decode(t) as Payload).role`
    if (
      new RegExp(
        `^\\s*(?:as\\s+[\\w$.<>\\[\\]|\\s]+)?\\)?\\s*\\??\\.\\s*(?:${IDENTITY_FIELDS})\\b`,
      ).test(after)
    ) {
      return true;
    }
    if (!bound) {
      // `return jwt.decode(token)` from a getUser/getSession-style helper.
      return (
        /\breturn\s*(?:\(\s*)?$/.test(stmt) &&
        /\b(?:get|current|load|resolve)\w*(?:User|Session|Auth|Viewer|Account)\w*\s*(?:=|\()/.test(
          code.slice(Math.max(0, call.start - 2000), call.start),
        )
      );
    }
    const name = escapeRe(bound[1]!);
    const tail = code.slice(call.close, call.close + 4000);
    return (
      new RegExp(`\\b${name}\\s*\\??\\.\\s*(?:${IDENTITY_FIELDS})\\b`).test(tail) ||
      new RegExp(`\\{[^{}]*\\b(?:${IDENTITY_FIELDS})\\b[^{}]*\\}\\s*=\\s*${name}\\b`).test(tail)
    );
  }

  private literalSecretFinding(file: string, line: number, evidence: string): Finding {
    return makeFinding({
      category: "crypto",
      ruleId: "crypto/jwt-literal-secret",
      severity: "high",
      confidence: "high",
      file,
      line,
      evidence,
      title: "JWT signed or verified with a hardcoded secret",
      plainEnglishProblem:
        "Tokens are signed or verified with a secret written directly in the source code instead of one loaded from the environment.",
      whyItMatters:
        "Anyone who can read the code (a leaked repo, a former contributor, a public bundle) can mint valid tokens for any user or role, and the secret cannot be rotated without a code change.",
      fixSteps: [
        "Move the secret to an environment variable (for example JWT_SECRET) and read it at startup.",
        "Throw at startup when the variable is missing or shorter than 32 characters; do not fall back to a literal.",
        "Generate a new long random secret (e.g. `openssl rand -base64 48`) and set it in every environment.",
        "Treat the old literal as leaked: rotate it and invalidate tokens signed with it.",
      ],
      aiFixPrompt:
        "This code signs or verifies JWTs with a secret written as a string literal. Replace the literal with a value read from an environment variable (e.g. process.env.JWT_SECRET), validated once at module load: throw a clear Error if it is missing or shorter than 32 characters, and never fall back to a hardcoded string. Keep the jwt.sign/jwt.verify calls otherwise unchanged and pass an explicit algorithms allow-list (e.g. { algorithms: ['HS256'] }) to verify.",
      learnMoreUrl:
        "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
    });
  }

  private algNoneFinding(file: string, line: number, evidence: string): Finding {
    return makeFinding({
      category: "crypto",
      ruleId: "crypto/jwt-algorithm-none",
      severity: "high",
      confidence: "high",
      file,
      line,
      evidence,
      title: "JWT accepts or uses the 'none' algorithm",
      plainEnglishProblem:
        "The JWT options allow the 'none' algorithm, which means a token with no signature at all is accepted (or produced).",
      whyItMatters:
        "An attacker can take any token, change the user id or role in it, set alg to 'none', strip the signature, and the server will accept it as genuine.",
      fixSteps: [
        "Remove 'none' from every algorithms / algorithm option.",
        "Verify with an explicit allow-list of the algorithm you actually sign with, e.g. { algorithms: ['HS256'] } or ['RS256'].",
        "Sign with that same algorithm and a real secret or private key.",
      ],
      aiFixPrompt:
        "This JWT code allows or uses the 'none' algorithm, so unsigned tokens are trusted. Remove 'none' from all algorithm options. Make every jwt.sign use a real algorithm (HS256 with a secret from an environment variable, or RS256 with a private key) and every jwt.verify pass an explicit allow-list containing only that algorithm, e.g. { algorithms: ['HS256'] }.",
      learnMoreUrl:
        "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
    });
  }

  private verifyWithoutAlgorithmsFinding(file: string, line: number, evidence: string): Finding {
    return makeFinding({
      category: "crypto",
      ruleId: "crypto/jwt-verify-without-algorithms",
      severity: "low",
      confidence: "medium",
      file,
      line,
      evidence,
      title: "jwt.verify() without an algorithms allow-list",
      plainEnglishProblem:
        "jwt.verify() is called without an `algorithms` option, so the algorithm is taken from the token header instead of being pinned by the server.",
      whyItMatters:
        "Pinning the algorithm closes algorithm-confusion attacks (for example an HS256 token verified with an RSA public key used as an HMAC secret) and protects you if a library default changes. With a single HMAC secret the direct risk is low, so this is hardening.",
      fixSteps: [
        "Pass the algorithm you sign with as an allow-list: jwt.verify(token, secret, { algorithms: ['HS256'] }).",
        "Use the same algorithm explicitly in jwt.sign.",
      ],
      aiFixPrompt:
        "This jwt.verify call has no algorithms allow-list. Add an options object that pins the algorithm used to sign these tokens, e.g. jwt.verify(token, secret, { algorithms: ['HS256'] }) (or ['RS256'] for key pairs), and make the matching jwt.sign call set the same algorithm explicitly. Do not change anything else.",
      learnMoreUrl:
        "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
    });
  }

  private decodeFinding(
    file: string,
    line: number,
    evidence: string,
    confidence: Confidence,
  ): Finding {
    return makeFinding({
      category: "crypto",
      ruleId: "crypto/jwt-decode-for-auth",
      severity: "high",
      confidence,
      file,
      line,
      evidence,
      title: "JWT decoded without verifying its signature",
      plainEnglishProblem:
        "The token is read with a decode function, which only base64-decodes it and does not check the signature, and its user id or role is then trusted. Nothing in this file verifies the token.",
      whyItMatters:
        "Anyone can write a token by hand with any user id or role in it. If the server trusts decoded claims, an attacker can impersonate any user or grant themselves admin access.",
      fixSteps: [
        "Replace the decode call with a verifying call: jwt.verify(token, secret, { algorithms: ['HS256'] }) or jose's jwtVerify(token, key, { algorithms: [...] }).",
        "Reject the request (401) when verification throws, before reading any claim.",
        "Use decode only for non-security purposes such as reading the expiry on the client.",
      ],
      aiFixPrompt:
        "This server code decodes a JWT without verifying its signature and then trusts its claims (user id, role) for authentication or authorization. Replace the decode call with signature verification: jwt.verify(token, secret, { algorithms: ['HS256'] }) from jsonwebtoken, or jwtVerify(token, key, { algorithms: [...] }) from jose, using the secret or public key from an environment variable. Return 401 when verification fails, and only read claims from the verified payload.",
      learnMoreUrl:
        "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
    });
  }
}
