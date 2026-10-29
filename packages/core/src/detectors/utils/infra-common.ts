import type { Finding } from "@talaljaber/vibesafe-shared";
import { SECRET_PATTERNS, matchSecretPattern } from "../patterns/secret-patterns.js";
import { makeFinding } from "./finding.js";

// Shared helpers for the infra detectors (Dockerfile, compose, shell, workflows).
// Every function here is linear in its input and never throws.

/** Secret patterns that recognise a specific token format (not the low-confidence generic ones). */
const SPECIFIC_SECRET_PATTERNS = SECRET_PATTERNS.filter((p) => p.confidence !== "low");

/**
 * True when a specific token format (Stripe, AWS, GitHub, ...) matches the text: those
 * lines are reported by the secret detector. The low-confidence generic patterns
 * (`password = "..."`, `secret = "..."`, bare JWTs) do not count, so quoting a value
 * never decides whether an infra rule reports it.
 */
export function hasSpecificSecret(text: string): boolean {
  return SPECIFIC_SECRET_PATTERNS.some((p) => matchSecretPattern(p, text) !== null);
}

/**
 * The credential word must end the variable name (optionally followed by a numeric or
 * environment suffix), so configuration such as TOKEN_ISSUER, PASSWORD_POLICY or
 * SECRET_MANAGER is not a credential. SECRET_KEY_BASE is Rails' signing secret.
 */
const CREDENTIAL_NAME_RE =
  /(?:SECRET|PASSWORD|PASSWD|PASSPHRASE|TOKEN|API_?KEY|SECRET_?KEY|SESSION_?KEY|(?:^|_)APP_KEY|PRIVATE_?KEY|ACCESS_?KEY|SERVICE_?ROLE(?:_?KEY)?|CREDENTIALS?|AUTH_?KEY|SIGNING_?KEY|ENCRYPTION_?KEY|MASTER_?KEY|^SECRET_KEY_BASE)(?:_?\d+|_(?:PROD|PRODUCTION|LIVE|STAGING|DEV))?$/i;
/** Names that hold a connection string; secret only when the URL carries a password. */
const CONNECTION_NAME_RE = /(?:^|_)(?:URL|URI|DSN|CONNECTION_STRING)$/i;
/** Public by design, whatever the rest of the name says. */
const PUBLIC_NAME_RE =
  /(?:^|_)(?:PUBLIC|PUBLISHABLE|ANON)(?:_|$)|^NEXT_PUBLIC_|^VITE_|^REACT_APP_|^EXPO_PUBLIC_/i;

export type CredentialNameKind = "credential" | "connection" | undefined;

/** Classifies an environment/shell variable name. */
export function credentialNameKind(name: string): CredentialNameKind {
  if (name.length > 200 || PUBLIC_NAME_RE.test(name)) return undefined;
  if (CREDENTIAL_NAME_RE.test(name)) return "credential";
  if (CONNECTION_NAME_RE.test(name)) return "connection";
  return undefined;
}

const PLACEHOLDER_RE =
  /^(?:|x+|\*+|-|null|none|nil|undefined|false|true|change[-_]?me|replace[-_]?me|placeholder|dummy|example|sample|todo|tbd|<[^>]*>|\[[^\]]*\]|\{\{.*\}\}|your[-_].*|.*[-_]here)$/i;
/** Values that name a mode, environment, scheme or algorithm rather than holding a secret. */
const CONFIG_VALUE_RE =
  /^(?:development|production|staging|test|testing|local|dev|prod|bearer|basic|digest|jwt|disabled|enabled|on|off|yes|no|strict|lax|required|optional|auto|(?:hs|rs|es|ps)(?:256|384|512)|argon2(?:id|i|d)?|bcrypt|scrypt|pbkdf2)$/i;
/** File names and relative paths (`creds.json`, `./keys/app.pem`). */
const FILE_VALUE_RE =
  /^(?:\.{1,2}\/|~\/)|\.(?:json|pem|key|crt|cer|p12|pfx|jks|txt|ya?ml|env|conf|ini)$/i;

/** True for empty values and placeholders such as `changeme`, `xxx` or `<token>`. */
export function isPlaceholderValue(value: string): boolean {
  return PLACEHOLDER_RE.test(value);
}

/**
 * True when a literal assigned to a credential-named variable looks like a real
 * secret: not a reference, placeholder, number, path, URL without userinfo or a
 * configuration word.
 */
export function looksLikeSecretValue(value: string): boolean {
  const v = value.trim();
  if (v.length < 4 || v.length > 4096) return false;
  if (v.includes("$") || v.includes("`") || /^\d+$/.test(v) || v.startsWith("/")) return false;
  if (PLACEHOLDER_RE.test(v) || CONFIG_VALUE_RE.test(v) || FILE_VALUE_RE.test(v)) return false;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) {
    // A URL is only a secret when it carries a password.
    const pw = findUrlCredential(v)?.password;
    return pw !== undefined && pw !== "" && !pw.includes("$") && !PLACEHOLDER_RE.test(pw);
  }
  return true;
}

export interface UrlCredential {
  scheme: string;
  user: string;
  password: string;
  host: string;
}

const AFTER_SCHEME_RE = /\/\/([^\s:@/'"]*):([^\s@/'"]+)@([^\s:/?#'"]+)/y;

/**
 * First `scheme://user:password@host` in the text. Scans each `://` once (no
 * backtracking across the line), so it stays linear on long lines.
 */
export function findUrlCredential(text: string): UrlCredential | undefined {
  let from = 0;
  for (;;) {
    const idx = text.indexOf("://", from);
    if (idx === -1) return undefined;
    from = idx + 3;
    let s = idx;
    while (s > 0 && idx - s < 64 && /[A-Za-z0-9+.-]/.test(text[s - 1] ?? "")) s--;
    const scheme = /[A-Za-z][A-Za-z0-9+.-]*$/.exec(text.slice(s, idx))?.[0];
    if (!scheme) continue;
    AFTER_SCHEME_RE.lastIndex = idx + 1;
    const m = AFTER_SCHEME_RE.exec(text);
    if (!m) continue;
    return { scheme, user: m[1] ?? "", password: m[2] ?? "", host: m[3] ?? "" };
  }
}

/** Findings of one rule kept per file before the rest is folded into one summary finding. */
export const MAX_FINDINGS_PER_RULE_PER_FILE = 25;

/**
 * Keeps at most {@link MAX_FINDINGS_PER_RULE_PER_FILE} findings per (rule, file) and
 * replaces the rest with one summary finding at medium confidence, anchored on the
 * first finding that was folded in.
 */
export function capFindingsPerRule(
  findings: Finding[],
  limit = MAX_FINDINGS_PER_RULE_PER_FILE,
): Finding[] {
  const groups = new Map<string, Finding[]>();
  for (const f of findings) {
    const key = `${f.ruleId}\u0000${f.file ?? ""}`;
    const list = groups.get(key);
    if (list) list.push(f);
    else groups.set(key, [f]);
  }
  const out: Finding[] = [];
  for (const list of groups.values()) {
    if (list.length <= limit) {
      out.push(...list);
      continue;
    }
    out.push(...list.slice(0, limit));
    const rest = list.slice(limit);
    const first = rest[0]!;
    out.push(
      makeFinding({
        category: first.category,
        ruleId: first.ruleId,
        title: `${first.title} (${rest.length} more in this file)`,
        severity: first.severity === "critical" ? "high" : first.severity,
        confidence: "medium",
        file: first.file,
        line: first.line,
        evidence: first.evidence,
        discriminator: "summary",
        plainEnglishProblem: `This file has ${rest.length} more findings of this rule after the first ${limit}, starting at line ${first.line ?? "?"}; they are summarized here instead of listed one by one. ${first.plainEnglishProblem}`,
        whyItMatters: first.whyItMatters,
        fixSteps: first.fixSteps,
        aiFixPrompt: first.aiFixPrompt ?? "",
        learnMoreUrl: first.learnMoreUrl,
        deployBlocking: false,
      }),
    );
  }
  return out;
}
