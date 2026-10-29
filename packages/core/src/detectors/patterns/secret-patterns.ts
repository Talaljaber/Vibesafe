import type { Severity } from "@talaljaber/vibesafe-shared";

export interface SecretPattern {
  id: string;
  name: string;
  regex: RegExp;
  confidence: "high" | "medium" | "low";
  /** Severity of a match. Only `critical` matches block deploys. */
  severity: Severity;
  /** Optional extra check on the matched text; a match is ignored when it returns false. */
  validate?: ((match: string) => boolean) | undefined;
  /** Capture group holding the secret value; when set, only that group is redacted in evidence. */
  valueGroup?: number | undefined;
  /** Pattern-specific wording; the secret detector's generic text is used when absent. */
  advice?: SecretAdvice | undefined;
}

/** Finding text for a secret pattern whose risk or fix differs from a plain API key. */
export interface SecretAdvice {
  problem: string;
  why: string;
  fixSteps: string[];
  aiFixPrompt: string;
}

/** Decodes a JWT payload (base64url) and returns its `role` claim, or undefined if unreadable. */
export function decodeJwtRole(token: string): string | undefined {
  try {
    const payload = token.split(".")[1];
    if (!payload) return undefined;
    const json = Buffer.from(payload, "base64url").toString("utf8");
    const parsed: unknown = JSON.parse(json);
    if (parsed && typeof parsed === "object" && "role" in parsed) {
      const role = (parsed as { role: unknown }).role;
      return typeof role === "string" ? role : undefined;
    }
    return undefined;
  } catch {
    return undefined;
  }
}

/**
 * Runs a pattern against a line and returns the first match that passes the pattern's validator.
 * Every candidate on the line is considered, so a placeholder cannot shadow a real secret after it.
 */
export function matchSecretPattern(pattern: SecretPattern, line: string): RegExpExecArray | null {
  const flags = pattern.regex.flags.includes("g") ? pattern.regex.flags : pattern.regex.flags + "g";
  const re = new RegExp(pattern.regex.source, flags);
  for (const match of line.matchAll(re)) {
    if (!match[0]) continue;
    if (pattern.validate && !pattern.validate(match[0])) continue;
    return match as RegExpExecArray;
  }
  return null;
}

const AWS_DOC_EXAMPLE_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

/**
 * True for documentation examples and obvious placeholders (EXAMPLE, xxxx, changeme, etc.).
 * Values like `your-aws-secret` never reach this check: they fail the length/charset constraints.
 * The substring match is intentionally loose; a random real key containing "example" is negligible.
 */
function isPlaceholderValue(value: string): boolean {
  return (
    /example|xxxx|changeme|placeholder|<[^>]*>/i.test(value) ||
    value === AWS_DOC_EXAMPLE_SECRET ||
    /^(.)\1+$/.test(value)
  );
}

function shannonEntropy(value: string): number {
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** A 40-char base64-ish string that is not a placeholder and looks random enough to be a real key. */
export function isLikelyAwsSecretValue(value: string): boolean {
  if (value.length !== 40 || isPlaceholderValue(value)) return false;
  if (!/[A-Za-z]/.test(value) || !/[0-9/+]/.test(value)) return false;
  return new Set(value).size >= 15 && shannonEntropy(value) >= 3.5;
}

/**
 * `scheme://user:password@host` for database and broker URLs. Group 2 is the user, group 3
 * the password (the redacted value), group 4 the host (a hostname or bracketed IPv6).
 */
const DATABASE_URL_RE =
  /\b(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?):\/\/([^\s:/@'"`]*):([^\s@'"`/]+)@([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])/i;

/** Well-known default or documentation passwords that are not a leaked credential. */
const DEFAULT_DB_PASSWORD_RE =
  /^(?:postgres|postgresql|password|passw(?:or)?d|pass|pwd|root|changeme|change_me|example|secret|admin|test|guest|mysql|redis|user|dbpass|db_?password|mypassword|my_password|your[-_]?password.*|\*+|x+|\.{3}|…)$/i;

/** Hosts that never point at a shared or production database. */
function isLocalOrPlaceholderHost(host: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  if (h.startsWith("[")) return true; // bracketed IPv6 literal (in practice ::1 in dev configs)
  if (!h.includes(".")) return true; // single-label hosts (localhost, db, postgres): local or compose
  if (/^(?:127\.\d+\.\d+\.\d+|0\.0\.0\.0|host\.docker\.internal)$/.test(h)) return true;
  if (/\.(?:localhost|local|test|invalid|example|internal\.example)$/.test(h)) return true;
  return /example|your[-_]?(?:db|host|server|project)|placeholder|hostname/.test(h);
}

/**
 * True for a `scheme://user:password@host` URL with a real-looking password and a
 * non-local, non-placeholder host. Interpolated (`${...}`, `$VAR`, `%s`, `{{...}}`) and
 * placeholder (`<password>`, `changeme`, `postgres`) parts never count.
 */
export function isLikelyDatabaseUrl(match: string): boolean {
  const m = DATABASE_URL_RE.exec(match);
  if (!m) return false;
  const user = m[2] ?? "";
  const pass = m[3] ?? "";
  const host = m[4] ?? "";
  const all = `${user}:${pass}@${host}`;
  if (/\$[{A-Za-z_]|\{\{|%[s(]|[<>]/.test(all)) return false;
  if (pass.length < 4 || pass === user) return false;
  if (DEFAULT_DB_PASSWORD_RE.test(pass) || isPlaceholderValue(pass)) return false;
  return !isLocalOrPlaceholderHost(host);
}

export const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: "sec-openai-key",
    name: "OpenAI API Key",
    regex: /sk-[a-zA-Z0-9]{48}/,
    severity: "critical",
    confidence: "high",
  },
  {
    id: "sec-openai-proj-key",
    name: "OpenAI Project API Key",
    regex: /sk-proj-[a-zA-Z0-9_-]{48}/,
    severity: "critical",
    confidence: "high",
  },
  {
    id: "sec-anthropic-key",
    name: "Anthropic API Key",
    regex: /sk-ant-[a-zA-Z0-9_-]{70,}/,
    severity: "critical",
    confidence: "high",
  },
  {
    id: "sec-stripe-live-secret",
    name: "Stripe Live Secret Key",
    regex: /sk_live_[a-zA-Z0-9]{24,}/,
    severity: "critical",
    confidence: "high",
  },
  {
    id: "sec-stripe-test-secret",
    name: "Stripe Test Secret Key",
    regex: /sk_test_[a-zA-Z0-9]{24,}/,
    severity: "low",
    confidence: "high",
  },
  {
    id: "sec-stripe-webhook-secret",
    name: "Stripe Webhook Signing Secret",
    regex: /whsec_[a-zA-Z0-9]{24,}/,
    severity: "high",
    confidence: "high",
  },
  {
    id: "sec-aws-access-key",
    name: "AWS Access Key ID",
    regex:
      /(?<![A-Z0-9])(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}(?![A-Z0-9])/,
    validate: (match) => !isPlaceholderValue(match),
    severity: "critical",
    confidence: "high",
  },
  {
    id: "sec-aws-secret-key",
    name: "AWS Secret Access Key",
    // aws_secret_access_key / AWS_SECRET_ACCESS_KEY / secretAccessKey / awsSecretKey / secret_key,
    // as an assignment, object literal, JSON/YAML `key: value`, Ruby `key => value`, Dockerfile
    // `ENV KEY value` or .env line. Group 2 is the value.
    regex:
      /(aws[_-]?secret[_-]?(?:access[_-]?)?key|secret[_-]?access[_-]?key|secret_key)["']?(?:\s*(?:=>|[:=])\s*|\s+)["']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/i,
    validate: (match) => isLikelyAwsSecretValue(match.slice(-40)),
    valueGroup: 2,
    severity: "critical",
    confidence: "medium",
  },
  {
    id: "sec-github-token",
    name: "GitHub Personal Access Token",
    regex: /gh[pous]_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/,
    severity: "critical",
    confidence: "high",
  },
  {
    id: "sec-supabase-service-key",
    name: "Supabase Service Role Key",
    regex: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/,
    validate: (match) => decodeJwtRole(match) === "service_role",
    severity: "critical",
    confidence: "medium",
  },
  {
    id: "sec-slack-bot-token",
    name: "Slack Bot Token",
    regex: /xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/,
    severity: "critical",
    confidence: "high",
  },
  {
    id: "sec-generic-jwt",
    name: "JSON Web Token",
    regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
    // service_role tokens are reported by sec-supabase-service-key; anon keys are public by design.
    validate: (match) => {
      const role = decodeJwtRole(match);
      return role !== "service_role" && role !== "anon";
    },
    severity: "low",
    confidence: "low",
  },
  {
    id: "sec-google-gcp-api-key",
    name: "Google Cloud Platform API Key",
    regex: /AIza[0-9A-Za-z_-]{35}/,
    severity: "critical",
    confidence: "high",
  },
  {
    id: "sec-discord-bot-token",
    name: "Discord Bot Token",
    regex: /[MNO][a-zA-Z0-9_-]{23,25}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}/,
    severity: "critical",
    confidence: "high",
  },
  {
    id: "sec-sendgrid-api-key",
    name: "SendGrid API Key",
    regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/,
    severity: "critical",
    confidence: "high",
  },
  {
    id: "sec-mailchimp-api-key",
    name: "Mailchimp API Key",
    regex: /[0-9a-f]{32}-us[0-9]{1,2}/,
    severity: "critical",
    confidence: "high",
  },
  {
    id: "sec-database-url",
    name: "Database URL with Password",
    // postgres(ql) / mysql / mariadb / mongodb(+srv) / redis(s) / amqp(s) with user:pass@host.
    // Local, single-label (compose service) and placeholder hosts and default or
    // interpolated passwords are excluded by the validator.
    regex: DATABASE_URL_RE,
    validate: isLikelyDatabaseUrl,
    valueGroup: 3,
    severity: "high",
    confidence: "high",
    advice: {
      problem:
        "A database or broker connection string with a real-looking password and a remote host is written directly in this file.",
      why: "Anyone who can read the repository, a build log or a bundle that includes this file can connect to that database with these credentials and read or change every row, bypassing your application's access checks.",
      fixSteps: [
        "Rotate the database password now; the committed one must be treated as leaked (it stays in git history).",
        "Remove the URL from the file and read it from an environment variable such as DATABASE_URL, with no hardcoded fallback.",
        "Fail fast at startup when the variable is missing instead of falling back to a literal.",
        "Store the real value in your hosting provider's secret settings or an untracked .env file.",
      ],
      aiFixPrompt:
        "This file hardcodes a database connection string that contains a password. Remove the literal URL, read it from process.env.DATABASE_URL (or the matching environment variable) with no hardcoded fallback, and throw a clear error at startup when it is missing. Do not print or log the URL. Remind me to rotate the leaked database password.",
    },
  },
  {
    id: "sec-generic-password",
    name: "Generic Password Assignment",
    regex: /(password|passwd|pwd)\s*[:=]\s*['"]([^'"]+)['"]/i,
    severity: "low",
    confidence: "low",
    valueGroup: 2,
  },
  {
    id: "sec-generic-secret",
    name: "Generic Secret Assignment",
    regex: /(secret|token|api_key|apikey|access_token)\s*[:=]\s*['"]([^'"]{10,})['"]/i,
    severity: "medium",
    confidence: "low",
    valueGroup: 2,
  },
];
