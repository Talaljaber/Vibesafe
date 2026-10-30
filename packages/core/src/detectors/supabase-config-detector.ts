import type {
  Confidence,
  Detector,
  Finding,
  ScanContext,
  Severity,
} from "@talaljaber/vibesafe-shared";
import { classifyPath, isTestOrFixturePath } from "./utils/file-kind.js";
import { makeFinding } from "./utils/finding.js";
import { capFindingsPerRule } from "./utils/infra-common.js";
import { scanTomlLines, tomlGet, type TomlEntry } from "./utils/toml-lines.js";

const SCOPE_NOTE =
  " This file configures your local Supabase stack and anything you push with `supabase config push`; a hosted project uses the values set in the Supabase dashboard (Authentication settings), so check them there too.";
const PASSWORD_DOCS = "https://supabase.com/docs/guides/auth/password-security";
const CONFIG_DOCS = "https://supabase.com/docs/guides/local-development/cli/config";

const ENV_REF_RE = /^env\([A-Za-z_][A-Za-z0-9_]*\)$/;
const HOST_RE = /^https?:\/\/(?:[^@/?#]*@)?(\[[^\]]*\]|[^/:?#]+)/i;

function isLocalHost(host: string): boolean {
  const h = host.toLowerCase();
  return (
    h === "localhost" ||
    h.endsWith(".localhost") ||
    h.startsWith("127.") ||
    h === "0.0.0.0" ||
    h === "[::1]" ||
    h === "host.docker.internal"
  );
}

/** Non-local host of an http(s) URL, or undefined. `httpsOnly` restricts to https. */
function remoteHost(url: string, httpsOnly: boolean): string | undefined {
  const u = url.trim();
  if (httpsOnly && !/^https:\/\//i.test(u)) return undefined;
  const m = HOST_RE.exec(u);
  if (!m) return undefined;
  const host = m[1]!.toLowerCase();
  return isLocalHost(host) ? undefined : host;
}

/** Evidence that the file configures a deployed project and not only the local stack. */
function hostedEvidence(entries: readonly TomlEntry[]): string | undefined {
  const site = tomlGet(entries, "auth", "site_url")?.value;
  if (site?.kind === "string") {
    if (ENV_REF_RE.test(site.value)) return "an environment-variable value";
    const host = remoteHost(site.value, false);
    if (host) return host;
  }
  const redirects = tomlGet(entries, "auth", "additional_redirect_urls")?.value;
  if (redirects?.kind === "string-array") {
    for (const u of redirects.values) {
      const host = remoteHost(u, true);
      if (host) return host;
    }
  }
  return undefined;
}

const boolOf = (e: TomlEntry | undefined): boolean | undefined =>
  e?.value.kind === "bool" ? e.value.value : undefined;

interface Hit {
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  line: number;
  evidence: string;
  problem: string;
  why: string;
  fix: string[];
  prompt: string;
  url: string;
}

/**
 * Checks Supabase auth settings in supabase/config.toml. Template-default rules only fire when
 * site_url / additional_redirect_urls show that the file drives a deployed project; explicit
 * weakenings (short password minimum, long JWT expiry, single email-change confirmation) always do.
 */
export class SupabaseConfigDetector implements Detector {
  id = "supabase-config-detector";
  name = "Supabase Auth Config";
  category = "security_config" as const;
  description =
    "Checks Supabase auth settings in supabase/config.toml (email confirmation, password policy, CAPTCHA, JWT expiry, email change protection).";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (classifyPath(file) !== "supabase-config") continue;
      if (isTestOrFixturePath(file) && context.config.includeTests !== true) continue;
      try {
        const text = await context.readFile(file);
        if (!text.includes("[auth")) continue;
        const { entries, tables } = scanTomlLines(text);
        for (const h of this.check(entries, tables)) {
          findings.push(
            makeFinding({
              category: "security_config",
              ruleId: h.ruleId,
              title: h.title,
              severity: h.severity,
              confidence: h.confidence,
              file,
              line: h.line,
              evidence: h.evidence,
              plainEnglishProblem: h.problem + SCOPE_NOTE,
              whyItMatters: h.why,
              fixSteps: h.fix,
              aiFixPrompt: h.prompt,
              learnMoreUrl: h.url,
            }),
          );
        }
      } catch {
        // Never throw from a detector.
      }
    }
    return capFindingsPerRule(findings);
  }

  private check(entries: readonly TomlEntry[], tables: Map<string, number>): Hit[] {
    const hits: Hit[] = [];
    const host = hostedEvidence(entries);
    const gateText = host
      ? ` The \`site_url\` points at ${host}, so this file drives a deployed project.`
      : "";
    const at = (e: TomlEntry): { line: number; evidence: string } => ({
      line: e.line,
      evidence: e.text,
    });

    const authSignup = tomlGet(entries, "auth", "enable_signup");
    const emailSignup = tomlGet(entries, "auth.email", "enable_signup");
    const signupOpen = boolOf(authSignup) !== false && boolOf(emailSignup) !== false;

    const confirm = tomlGet(entries, "auth.email", "enable_confirmations");
    if (host && confirm && boolOf(confirm) === false && signupOpen) {
      hits.push({
        ruleId: "security_config/supabase-email-confirm-off",
        title: "Supabase email confirmation is turned off",
        severity: "low",
        confidence: "low",
        ...at(confirm),
        problem: `\`enable_confirmations = false\` lets anyone sign up with an email address they do not own.${gateText}`,
        why: "Unconfirmed accounts allow spam sign-ups, impersonation of other people's addresses and account squatting.",
        fix: [
          "Set `[auth.email] enable_confirmations = true` and keep local development working with Inbucket.",
          'Turn on "Confirm email" in the Supabase dashboard for the hosted project.',
        ],
        prompt:
          "Update `supabase/config.toml` so `[auth.email] enable_confirmations = true`, keep local development working (use Inbucket for test emails), and tell me which Supabase dashboard setting to change for the hosted project.",
        url: CONFIG_DOCS,
      });
    }

    const minLen = tomlGet(entries, "auth", "minimum_password_length");
    if (minLen?.value.kind === "int") {
      const n = minLen.value.value;
      const reqs = tomlGet(entries, "auth", "password_requirements");
      const noReqs = reqs?.value.kind === "string" && reqs.value.value === "";
      const reqText = noReqs
        ? " `password_requirements` is empty, so no character mix is required either."
        : "";
      if (n < 6 || (n <= 7 && host)) {
        hits.push({
          ruleId: "security_config/supabase-weak-password",
          title: "Supabase minimum password length is short",
          severity: "low",
          confidence: n < 6 ? "medium" : "low",
          ...at(minLen),
          problem: `A minimum password length of ${n} lets users choose easily guessed passwords.${reqText}${n < 6 ? "" : gateText}`,
          why: "Short passwords are cracked quickly in credential-stuffing and brute-force attacks.",
          fix: [
            'Set `minimum_password_length = 8` (or 12) and `password_requirements = "lower_upper_letters_digits"`.',
            "Enable leaked-password protection in the Supabase dashboard.",
          ],
          prompt:
            'Update `supabase/config.toml` to set `[auth] minimum_password_length = 8` and `password_requirements = "lower_upper_letters_digits"`, and tell me how to enable leaked-password protection in the Supabase dashboard.',
          url: PASSWORD_DOCS,
        });
      }
    }

    if (host && signupOpen && boolOf(tomlGet(entries, "auth.captcha", "enabled")) !== true) {
      const anchor = authSignup ?? emailSignup;
      hits.push({
        ruleId: "security_config/supabase-signup-no-captcha",
        title: "Supabase sign-up has no CAPTCHA",
        severity: "low",
        confidence: "low",
        line: anchor?.line ?? tables.get("auth") ?? 1,
        evidence: anchor?.text ?? "[auth]",
        problem: `Public sign-up is open and no \`[auth.captcha]\` is enabled, so bots can create accounts in bulk.${gateText}`,
        why: "Automated sign-ups send spam through your auth emails and fill the user table.",
        fix: [
          "Enable `[auth.captcha] enabled = true` with hCaptcha or Turnstile, or disable public sign-up.",
          "Set the CAPTCHA secret through an `env(...)` reference, not a literal.",
        ],
        prompt:
          "Update `supabase/config.toml` to enable `[auth.captcha]` with Turnstile or hCaptcha (secret via env), keep local development working, and tell me which dashboard setting to change for the hosted project.",
        url: CONFIG_DOCS,
      });
    }

    const jwt = tomlGet(entries, "auth", "jwt_expiry");
    if (jwt?.value.kind === "int" && jwt.value.value > 86400) {
      hits.push({
        ruleId: "security_config/supabase-long-jwt-expiry",
        title: "Supabase access tokens live longer than a day",
        severity: "low",
        confidence: "high",
        ...at(jwt),
        problem: `\`jwt_expiry = ${jwt.value.value}\` keeps a stolen access token valid for ${jwt.value.value} seconds.`,
        why: "Access tokens cannot be revoked before they expire, so a long lifetime widens the window for a leaked token.",
        fix: [
          "Set `jwt_expiry = 3600` and rely on refresh tokens with rotation for long sessions.",
          "Keep `enable_refresh_token_rotation = true`.",
        ],
        prompt:
          "Update `supabase/config.toml` so `[auth] jwt_expiry = 3600` with refresh token rotation enabled, and tell me which dashboard setting to change for the hosted project.",
        url: CONFIG_DOCS,
      });
    }

    const pwChange = tomlGet(entries, "auth.email", "secure_password_change");
    if (host && pwChange && boolOf(pwChange) === false) {
      hits.push({
        ruleId: "security_config/supabase-password-change-unsafe",
        title: "Supabase password change needs no recent login",
        severity: "low",
        confidence: "low",
        ...at(pwChange),
        problem: `\`secure_password_change = false\` lets a stolen session change the password without re-authentication.${gateText}`,
        why: "An attacker with a short-lived session can lock the real owner out permanently.",
        fix: ["Set `[auth.email] secure_password_change = true`."],
        prompt:
          "Update `supabase/config.toml` so `[auth.email] secure_password_change = true`, and tell me which dashboard setting to change for the hosted project.",
        url: CONFIG_DOCS,
      });
    }

    const dbl = tomlGet(entries, "auth.email", "double_confirm_changes");
    if (dbl && boolOf(dbl) === false) {
      hits.push({
        ruleId: "security_config/supabase-email-change-unconfirmed",
        title: "Supabase email change needs only one confirmation",
        severity: "low",
        confidence: "medium",
        ...at(dbl),
        problem:
          "`double_confirm_changes = false` lets an attacker with a session move the account to their own address with one confirmation.",
        why: "Changing the email is the first step of an account takeover; confirming on both the old and new address blocks it.",
        fix: ["Set `[auth.email] double_confirm_changes = true`."],
        prompt:
          "Update `supabase/config.toml` so `[auth.email] double_confirm_changes = true`, and tell me which dashboard setting to change for the hosted project.",
        url: CONFIG_DOCS,
      });
    }
    return hits;
  }
}
