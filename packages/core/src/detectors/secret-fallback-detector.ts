import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { makeFinding } from "./utils/finding.js";
import { redactSpan } from "./utils/sanitize-evidence.js";
import { isGenerated, isJsLike, isTestOrFixturePath } from "./utils/file-kind.js";
import { maskCode } from "./utils/route-analyzer.js";
import { SECRET_PATTERNS, matchSecretPattern } from "./patterns/secret-patterns.js";

const MAX_PER_FILE = 25;

/** `process.env.X ||` / `?? "` (masked code: the literal's quotes survive, its text is blanked). */
const ENV_FALLBACK_RE =
  /\b(?:process\.env|import\.meta\.env)\.([A-Za-z_][\w]*)\s*(\|\||\?\?)\s*(["'`])/g;
/** `const { JWT_SECRET = "dev" } = process.env` (masked code). */
const ENV_DESTRUCTURE_RE = /\{([^{}]{1,600})\}\s*=\s*process\.env\b/g;
const DESTRUCTURED_DEFAULT_RE =
  /(?:^|[,{\s])([A-Za-z_][\w]*)\s*(?::\s*([A-Za-z_$][\w$]*)\s*)?=\s*(["'`])/g;

/** Words that make an env var name a secret. */
const SECRET_WORDS = new Set([
  "SECRET",
  "SECRETS",
  "TOKEN",
  "PASSWORD",
  "PASSWD",
  "PASS",
  "PWD",
  "PASSPHRASE",
  "JWT",
  "SALT",
  "PEPPER",
  "CREDENTIAL",
  "CREDENTIALS",
  "APIKEY",
  "PRIVATEKEY",
]);
/** `<word>_KEY` that is not a secret. */
const NON_SECRET_KEY_QUALIFIERS = new Set([
  "CACHE",
  "QUERY",
  "SORT",
  "PARTITION",
  "PRIMARY",
  "FOREIGN",
  "ROUTING",
  "STORAGE",
  "LOCALE",
  "I18N",
  "SITE",
  "IDEMPOTENCY",
  "REDIS",
  "PREFIX",
]);
/** Words that make a name configuration, not a secret (checked before the secret words). */
const NON_SECRET_WORDS = new Set([
  "PORT",
  "ENV",
  "URL",
  "URLS",
  "URI",
  "HOST",
  "HOSTNAME",
  "ENDPOINT",
  "REGION",
  "ID",
  "PUBLIC",
  "PUBLISHABLE",
  "ANON",
  "EXPIRES",
  "EXPIRY",
  "EXPIRATION",
  "TTL",
  "NAME",
  "ALGORITHM",
  "ALG",
  "ISSUER",
  "AUDIENCE",
  "DOMAIN",
  "PATH",
  "FILE",
  "DIR",
  "MODE",
  "LEVEL",
  "HEADER",
  "ENABLED",
  "DISABLED",
  "REQUIRED",
  "PREFIX",
  "LENGTH",
  "ROUNDS",
  "COST",
  "ITERATIONS",
  "SIZE",
  "TYPE",
  "FORMAT",
  "VERSION",
  "AGE",
  "MAX",
  "MIN",
  "LIMIT",
  "TIMEOUT",
  "COUNT",
]);
/**
 * Words that, after the secret word, make the name a label for where a secret is kept or
 * sent (a cookie, storage key, claim, form field, query parameter or OAuth scope).
 * `COOKIE_SECRET` stays a secret; `AUTH_TOKEN_COOKIE` does not.
 */
const HOLDER_WORDS = new Set([
  "COOKIE",
  "COOKIES",
  "STORAGE",
  "CLAIM",
  "CLAIMS",
  "FIELD",
  "FIELDS",
  "PARAM",
  "PARAMS",
  "SCOPE",
  "SCOPES",
]);
const PUBLIC_PREFIX_RE = /^(?:NEXT_PUBLIC|VITE|PUBLIC|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|GATSBY)_/;
/** Fallback values that are switches or numbers, not secrets. */
const NON_SECRET_VALUE_RE =
  /^(?:true|false|null|undefined|none|yes|no|on|off|\d+(?:\.\d+)?[smhdw]?)$/i;

/**
 * True when an environment variable name holds a secret: SECRET / TOKEN / PASSWORD / JWT /
 * SALT / *_API_KEY / *_PRIVATE_KEY / vendor `*_KEY` and similar. Public (`NEXT_PUBLIC_`,
 * `VITE_`...), `PORT`, `NODE_ENV`, `*_URL`, `*_EMAILS`, expiry, algorithm and size settings
 * are not.
 */
export function isSecretEnvName(name: string): boolean {
  const upper = name.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toUpperCase();
  if (PUBLIC_PREFIX_RE.test(upper)) return false;
  const words = upper.split(/_+/).filter((w) => w.length > 0);
  if (words.some((w) => NON_SECRET_WORDS.has(w))) return false;
  let lastSecret = -1;
  for (let i = 0; i < words.length; i++) {
    const w = words[i]!;
    if (SECRET_WORDS.has(w)) lastSecret = i;
    else if (w === "KEY" || w === "KEYS") {
      const prev = words[i - 1];
      if (prev !== undefined && !NON_SECRET_KEY_QUALIFIERS.has(prev)) lastSecret = i;
    }
  }
  if (lastSecret < 0) return false;
  // `AUTH_TOKEN_COOKIE`, `TOKEN_STORAGE_KEY`, `JWT_CLAIM`: the name of a place a secret goes.
  return !words.slice(lastSecret + 1).some((w) => HOLDER_WORDS.has(w));
}

/** `(jwt|jsonwebtoken).sign|verify`, jose and session/cookie signers given `name` as the secret. */
function signerUsesRe(name: string): RegExp {
  const n = name.replace(/\$/g, "\\$");
  const ref = String.raw`(?:[\w$]+\.)*${n}(?![\w$])`;
  return new RegExp(
    [
      String.raw`\b(?:jwt|jsonwebtoken|JWT|jsonwebtoken\.default)\.(?:sign|verify)\s*\([^;()]{0,200},\s*${ref}`,
      String.raw`(?<![\w$.])(?:sign|verify|jwtVerify)\s*\([^;()]{0,200},\s*${ref}`,
      String.raw`\b(?:secret|secretOrKey|secretOrPrivateKey|secretOrPublicKey|signingKey)\s*:\s*${ref}`,
      String.raw`\bkeys\s*:\s*\[\s*${ref}`,
      String.raw`\bcookieParser\s*\(\s*${ref}`,
      String.raw`\bcreateHmac\s*\([^;()]{0,60},\s*${ref}`,
      String.raw`\b(?:encode|createSecretKey)\s*\(\s*(?:Buffer\.from\s*\(\s*)?${ref}`,
      String.raw`\.sign\s*\(\s*${ref}`,
    ].join("|"),
  );
}

/** Text before the env reference ends inside a signer call or a secret option. */
const INLINE_SIGNER_RE =
  /(?:\b(?:jwt|jsonwebtoken|JWT)\.(?:sign|verify)\s*\([^;]{0,200},\s*|\b(?:secret|secretOrKey|secretOrPrivateKey|signingKey)\s*:\s*|\bkeys\s*:\s*\[\s*|\bcookieParser\s*\(\s*|\bcreateHmac\s*\([^;()]{0,60},\s*|\b(?:encode|createSecretKey)\s*\(\s*)$/;
const BINDING_RE =
  /(?:\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;]{0,80})?|([A-Za-z_$][\w$]*)\s*)=\s*\(?\s*$/;
const PROPERTY_BINDING_RE = /([A-Za-z_$][\w$]*)\s*:\s*\(?\s*$/;

interface Fallback {
  envName: string;
  /** Variable or property the fallback expression is bound to, if any. */
  binding: string | undefined;
  /** Offset of the env reference and of the literal's opening quote (raw/masked offsets agree). */
  envOffset: number;
  open: number;
  close: number;
  inlineSigner: boolean;
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

/** Index of the quote closing the literal opened at `open`, or -1 (unterminated / interpolated). */
function literalEnd(code: string, open: number): number {
  const quote = code[open];
  for (let i = open + 1; i < code.length && i < open + 4000; i++) {
    const c = code[i];
    if (c === quote) return i;
    if (quote === "`" && c === "$" && code[i + 1] === "{") return -1;
    if (quote !== "`" && c === "\n") return -1;
  }
  return -1;
}

/**
 * Flags `process.env.<SECRET> || "literal"` / `?? "literal"` (and destructuring defaults
 * from `process.env`): when the variable is missing the app silently signs or encrypts
 * with a secret that is published in the source. Critical when the same file passes the
 * value to jwt.sign/verify, jose or a session/cookie signer. Lines where a known secret
 * pattern already matches are left to the secret detector.
 */
export class SecretFallbackDetector implements Detector {
  id = "secret-fallback-detector";
  name = "Hardcoded Secret Fallbacks";
  category = "crypto" as const;
  description =
    "Detects secrets read from the environment with a hardcoded string fallback (process.env.X || 'literal').";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (!isJsLike(file) || isTestOrFixturePath(file) || isGenerated(file)) continue;
      try {
        const content = await context.readFile(file);
        if (!content.includes("env")) continue;
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
    const fallbacks = this.collect(code);
    const out: Finding[] = [];
    const seen = new Set<string>();
    const signerCache = new Map<string, boolean>();
    const signerUses = (binding: string): boolean => {
      let used = signerCache.get(binding);
      if (used === undefined) {
        used = signerUsesRe(binding).test(code);
        signerCache.set(binding, used);
      }
      return used;
    };
    let extra = 0;
    let extraLine = 0;
    for (const fb of fallbacks) {
      const literal = content.slice(fb.open + 1, fb.close);
      if (literal.trim() === "" || literal.includes("\n")) continue;
      if (NON_SECRET_VALUE_RE.test(literal.trim())) continue;
      if (!isSecretEnvName(fb.envName)) continue;
      const firstLine = lineIndexAt(starts, fb.envOffset);
      const lastLine = lineIndexAt(starts, fb.close);
      if (this.secretPatternOnLines(lines, firstLine, lastLine)) continue;
      const key = `${fb.envName}:${lastLine}`;
      if (seen.has(key)) continue;
      seen.add(key);
      if (out.length >= MAX_PER_FILE) {
        if (extra++ === 0) extraLine = lastLine + 1;
        continue;
      }
      // Only for findings that are emitted, and once per binding: a whole-file search.
      const signed = fb.inlineSigner || (fb.binding !== undefined && signerUses(fb.binding));
      const raw = lines[lastLine] ?? "";
      const evidence = redactSpan(raw, fb.open + 1 - starts[lastLine]!, literal);
      out.push(this.finding(file, lastLine + 1, fb.envName, signed, evidence));
    }
    if (extra > 0) {
      // One summary instead of an unbounded list; medium confidence caps it at high.
      out.push(
        this.finding(
          file,
          extraLine,
          "summary",
          false,
          `${extra} more hardcoded secret fallbacks in this file`,
          "medium",
        ),
      );
    }
    return out;
  }

  private collect(code: string): Fallback[] {
    const found: Fallback[] = [];
    ENV_FALLBACK_RE.lastIndex = 0;
    for (const m of code.matchAll(ENV_FALLBACK_RE)) {
      const envOffset = m.index ?? 0;
      const open = envOffset + m[0].length - 1;
      const close = literalEnd(code, open);
      if (close < 0) continue;
      const before = code.slice(Math.max(0, envOffset - 300), envOffset);
      const stmt = before.slice(before.lastIndexOf(";") + 1);
      const bound = BINDING_RE.exec(stmt) ?? undefined;
      const prop = bound ? undefined : (PROPERTY_BINDING_RE.exec(stmt) ?? undefined);
      found.push({
        envName: m[1]!,
        binding: bound ? (bound[1] ?? bound[2]) : prop?.[1],
        envOffset,
        open,
        close,
        inlineSigner: INLINE_SIGNER_RE.test(stmt),
      });
    }
    ENV_DESTRUCTURE_RE.lastIndex = 0;
    for (const m of code.matchAll(ENV_DESTRUCTURE_RE)) {
      const innerStart = (m.index ?? 0) + 1;
      const inner = m[1]!;
      DESTRUCTURED_DEFAULT_RE.lastIndex = 0;
      for (const d of inner.matchAll(DESTRUCTURED_DEFAULT_RE)) {
        const open = innerStart + (d.index ?? 0) + d[0].length - 1;
        const close = literalEnd(code, open);
        if (close < 0) continue;
        const envOffset = innerStart + (d.index ?? 0) + d[0].indexOf(d[1]!);
        found.push({
          envName: d[1]!,
          binding: d[2] ?? d[1]!,
          envOffset,
          open,
          close,
          inlineSigner: false,
        });
      }
    }
    return found.sort((a, b) => a.envOffset - b.envOffset);
  }

  /** The secret detector already reports these lines (a live key as the fallback, etc.). */
  private secretPatternOnLines(lines: readonly string[], from: number, to: number): boolean {
    for (let i = from; i <= to; i++) {
      const line = lines[i];
      if (line === undefined) continue;
      if (SECRET_PATTERNS.some((p) => matchSecretPattern(p, line) !== null)) return true;
    }
    return false;
  }

  private finding(
    file: string,
    line: number,
    envName: string,
    signed: boolean,
    evidence: string,
    confidence: "high" | "medium" = "high",
  ): Finding {
    return makeFinding({
      category: "crypto",
      ruleId: "crypto/hardcoded-secret-fallback",
      title: signed
        ? "Token or session signing secret falls back to a hardcoded value"
        : "Secret falls back to a hardcoded value",
      severity: signed ? "critical" : "high",
      confidence,
      file,
      line,
      evidence,
      discriminator: envName,
      plainEnglishProblem: signed
        ? "The secret used to sign or verify tokens or sessions is read from an environment variable, but when the variable is missing the code silently uses a hardcoded string that is visible in the source."
        : "A secret is read from an environment variable, but when the variable is missing the code silently uses a hardcoded string that is visible in the source.",
      whyItMatters: signed
        ? "If the variable is ever unset in an environment (a new deploy target, a preview build, a typo), every token or session is signed with a publicly known key: anyone who reads the code can forge a valid token for any user, role or tenant."
        : "If the variable is ever unset in an environment, the app keeps running with a publicly known secret instead of failing, and anyone who reads the code can use it.",
      fixSteps: [
        "Remove the hardcoded fallback value.",
        "Read the variable once at startup and throw a clear error when it is missing or too short (for example fewer than 32 characters).",
        "Set a long random value (e.g. `openssl rand -base64 48`) in every environment's secret settings, including preview and staging.",
        "If the fallback was ever used in a deployed environment, rotate the secret and invalidate tokens or sessions signed with it.",
      ],
      aiFixPrompt:
        "This code reads a secret from an environment variable but falls back to a hardcoded string when the variable is missing (process.env.X || 'literal' or ?? 'literal'). Remove the hardcoded fallback. Read the variable once at module load, and if it is missing or shorter than 32 characters throw an Error with a clear message so the app refuses to start. Keep the rest of the code using the validated value, and do not log the secret.",
      learnMoreUrl:
        "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
    });
  }
}
