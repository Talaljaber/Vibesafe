import type { Detector, Finding, FindingCategory, ScanContext, Severity } from "@vibesafe/shared";
import { CATEGORY_PREFIX, createFindingId, redactSecret } from "@vibesafe/shared";
import { sanitizeEvidence } from "./utils/sanitize-evidence.js";
import {
  isDevOnlySettings,
  isSettingsFile,
  joinStatement,
  scanPythonLines,
} from "./utils/python-source.js";

interface DjangoRule {
  id: string;
  category: FindingCategory;
  title: string;
  severity: Severity;
  /** Severity used instead when the file is a dev-only settings module. */
  devSeverity?: Severity;
  /** Settings rules only run in settings modules; view rules run in any .py file. */
  scope: "settings" | "any";
  /** Skip the rule entirely in dev/local/test settings modules. */
  prodOnly?: boolean;
  /** Skip the rule inside a top-level `if DEBUG:` block. */
  skipInDebugBlock?: boolean;
  /** Settings rules match the logical statement (continuations joined); "any" rules the physical line. */
  regex: RegExp;
  /** Optional extra check on the regex match; the rule fires only when it returns true. */
  check?: (m: RegExpExecArray) => boolean;
  problem: string;
  why: string;
  fixSteps: string[];
  aiFixPrompt: string;
}

/*
 * Known limits (line/statement based, no real Python parser, by design):
 *  - Values built by concatenation, helper functions or other variables are not followed.
 *  - A second positional string argument of 8+ chars in a SECRET_KEY call is treated as a fallback
 *    key (medium confidence), e.g. get_secret("key", "utf-8-encoding") is a false positive.
 *  - Settings split across modules via `from .base import *` are scanned per file; "missing"
 *    transport settings are judged across all non-dev settings modules of the project.
 *  - Only a top-level `if DEBUG:` block is recognised as dev-only; other conditionals are not.
 * Bracketed, backslash-continued and multi-line triple-quoted values are joined into one
 * logical statement (see utils/python-source.ts).
 */
const RULES: DjangoRule[] = [
  {
    id: "security_config/django-debug-true",
    category: "security_config",
    title: "Django DEBUG is enabled",
    severity: "high",
    devSeverity: "low",
    scope: "settings",
    regex: /^\s*DEBUG\s*=\s*(?:True\b|[\w.]+\((?=[^)]*(?:,\s*|default\s*=\s*)True\b))/,
    problem: "DEBUG = True is hardcoded (or is the default) in your Django settings.",
    why: "With DEBUG on, Django shows detailed error pages with settings, environment details and source code to anyone who triggers an error.",
    fixSteps: [
      "Read DEBUG from an environment variable, defaulting to False.",
      'For example: DEBUG = os.environ.get("DJANGO_DEBUG", "") == "1".',
      "Only enable it on your local machine.",
    ],
    aiFixPrompt:
      "Please change DEBUG in this Django settings file so it is read from an environment variable and defaults to False in production.",
  },
  {
    id: "security_config/django-allowed-hosts-wildcard",
    category: "security_config",
    title: "Django ALLOWED_HOSTS allows every host",
    severity: "medium",
    scope: "settings",
    regex: /^\s*ALLOWED_HOSTS\s*\+?=\s*[[(][^\])]*['"]\*['"][^\])]*[\])]/,
    problem: 'ALLOWED_HOSTS contains "*", so Django accepts requests for any Host header.',
    why: "A wildcard disables Django's Host header validation, which enables host header poisoning (for example forged password reset links).",
    fixSteps: [
      "List only your real domain names in ALLOWED_HOSTS.",
      "Read them from an environment variable so each environment has its own list.",
    ],
    aiFixPrompt:
      'Please replace the "*" in ALLOWED_HOSTS with my real production domains, read from an environment variable.',
  },
  {
    id: "security_config/django-cors-allow-all",
    category: "security_config",
    title: "Django CORS allows all origins",
    severity: "medium",
    scope: "settings",
    skipInDebugBlock: true,
    regex: /^\s*(?:CORS_ALLOW_ALL_ORIGINS|CORS_ORIGIN_ALLOW_ALL)\s*=\s*True\b/,
    problem: "CORS is configured to accept requests from every origin.",
    why: "Any website can then call your API from a visitor's browser, which is dangerous if your API uses cookies or other ambient credentials.",
    fixSteps: [
      "Set CORS_ALLOW_ALL_ORIGINS to False.",
      "List trusted frontends in CORS_ALLOWED_ORIGINS instead.",
    ],
    aiFixPrompt:
      "Please turn off allow-all CORS in this Django settings file and add an explicit CORS_ALLOWED_ORIGINS list for my frontend domains.",
  },
  {
    id: "security_config/django-insecure-cookie",
    category: "security_config",
    title: "Django cookie is not marked Secure",
    severity: "medium",
    scope: "settings",
    skipInDebugBlock: true,
    regex: /^\s*(?:SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE)\s*=\s*False\b/,
    problem: "A session or CSRF cookie is explicitly allowed to travel over plain HTTP.",
    why: "Cookies without the Secure flag can be intercepted on unencrypted connections, letting attackers hijack sessions.",
    fixSteps: [
      "Set SESSION_COOKIE_SECURE and CSRF_COOKIE_SECURE to True in production.",
      "Serve the site over HTTPS only.",
    ],
    aiFixPrompt:
      "Please set SESSION_COOKIE_SECURE and CSRF_COOKIE_SECURE to True for production in this Django settings file, keeping local development working.",
  },
  {
    id: "security_config/django-ssl-redirect-off",
    category: "security_config",
    title: "Django does not redirect HTTP to HTTPS",
    severity: "medium",
    scope: "settings",
    prodOnly: true,
    skipInDebugBlock: true,
    regex: /^\s*SECURE_SSL_REDIRECT\s*=\s*False\b/,
    problem: "SECURE_SSL_REDIRECT is set to False, so Django serves pages over plain HTTP.",
    why: "Visitors who type your address or follow an http:// link stay on an unencrypted connection, where logins and cookies can be read or changed by anyone on the network.",
    fixSteps: [
      "Set SECURE_SSL_REDIRECT = True in your production settings.",
      "If your host or proxy already redirects to HTTPS, keep it on anyway and set SECURE_PROXY_SSL_HEADER so Django knows the request was secure.",
    ],
    aiFixPrompt:
      "Please enable SECURE_SSL_REDIRECT for production in this Django settings file (keeping local development on HTTP) and set SECURE_PROXY_SSL_HEADER if the app runs behind a proxy.",
  },
  {
    id: "security_config/django-hsts-off",
    category: "security_config",
    title: "Django HSTS is turned off",
    severity: "low",
    scope: "settings",
    prodOnly: true,
    skipInDebugBlock: true,
    regex: /^\s*SECURE_HSTS_SECONDS\s*=\s*0+(?![\d.])/,
    problem:
      "SECURE_HSTS_SECONDS is 0, so browsers are never told to always use HTTPS for your site.",
    why: "Without HSTS, an attacker on the same network can downgrade a visitor's first request to plain HTTP and intercept it.",
    fixSteps: [
      "Set SECURE_HSTS_SECONDS to a positive value in production, starting small (for example 3600) and raising it to 31536000 once HTTPS works everywhere.",
      "Consider SECURE_HSTS_INCLUDE_SUBDOMAINS = True once every subdomain serves HTTPS.",
    ],
    aiFixPrompt:
      "Please enable HSTS in this Django production settings file with a safe starting SECURE_HSTS_SECONDS value and explain how to raise it later.",
  },
  {
    id: "security_config/django-session-cookie-httponly-off",
    category: "security_config",
    title: "Django session cookie is readable by JavaScript",
    severity: "medium",
    scope: "settings",
    prodOnly: true,
    skipInDebugBlock: true,
    regex: /^\s*SESSION_COOKIE_HTTPONLY\s*=\s*False\b/,
    problem:
      "SESSION_COOKIE_HTTPONLY is False, so scripts running in the page can read the session cookie.",
    why: "If any script injection (XSS) gets through, the attacker can steal the session cookie and log in as the user.",
    fixSteps: [
      "Remove the line or set SESSION_COOKIE_HTTPONLY = True (the Django default).",
      "If your frontend needs the session state, expose it through an API instead of the cookie.",
    ],
    aiFixPrompt:
      "Please set SESSION_COOKIE_HTTPONLY back to True in this Django settings file and change any frontend code that reads the session cookie directly.",
  },
  {
    id: "security_config/django-x-frame-options-allow",
    category: "security_config",
    title: "Django allows the site to be framed",
    severity: "medium",
    scope: "settings",
    prodOnly: true,
    skipInDebugBlock: true,
    regex: /^\s*X_FRAME_OPTIONS\s*=\s*\(?\s*[rbuRBU]?['"]\s*ALLOW/i,
    problem: 'X_FRAME_OPTIONS is set to an "ALLOW..." value instead of DENY or SAMEORIGIN.',
    why: "Other websites can load your pages in an invisible frame and trick users into clicking buttons (clickjacking). Browsers also ignore ALLOW-FROM, so it gives no protection.",
    fixSteps: [
      'Set X_FRAME_OPTIONS = "DENY" (the Django default) or "SAMEORIGIN".',
      "If a partner site must embed you, use a Content-Security-Policy frame-ancestors list instead.",
    ],
    aiFixPrompt:
      'Please change X_FRAME_OPTIONS in this Django settings file to "DENY" (or "SAMEORIGIN" if my own pages frame each other).',
  },
  {
    id: "security_config/django-proxy-ssl-header",
    category: "security_config",
    title: "Django SECURE_PROXY_SSL_HEADER looks wrong",
    severity: "low",
    scope: "settings",
    prodOnly: true,
    regex:
      /^\s*SECURE_PROXY_SSL_HEADER\s*=\s*[([]?\s*[rbuRBU]?(['"])(.*?)\1\s*,\s*[rbuRBU]?(['"])(.*?)\3/,
    // Django compares against request.META, whose header keys are upper case and HTTP_-prefixed.
    check: (m) => !/^HTTP_[A-Z0-9_]+$/.test(m[2] ?? "") || m[4] !== "https",
    problem:
      'SECURE_PROXY_SSL_HEADER is not of the form ("HTTP_X_FORWARDED_PROTO", "https"), so Django will never recognise HTTPS requests forwarded by your proxy.',
    why: "Django then treats every request as plain HTTP: SECURE_SSL_REDIRECT can loop forever, secure cookies and CSRF checks misbehave, and people often switch those protections off to make it work.",
    fixSteps: [
      'Use the META name of the header: SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https").',
      "Only set it when your proxy always overwrites that header, otherwise clients can spoof it.",
    ],
    aiFixPrompt:
      'Please fix SECURE_PROXY_SSL_HEADER in this Django settings file to ("HTTP_X_FORWARDED_PROTO", "https") and confirm my proxy sets that header.',
  },
  {
    id: "security_config/django-csrf-exempt",
    category: "security_config",
    title: "Django view is exempt from CSRF protection",
    severity: "medium",
    scope: "any",
    regex:
      /^\s*@(?:\w+\.)*csrf_exempt\b|(?<!def\s)(?<!\w)(?:\w+\.)*csrf_exempt\s*\(|method_decorator\(\s*(?:\w+\.)*csrf_exempt\b/,
    problem: "A view is marked @csrf_exempt, so Django skips CSRF checks for it.",
    why: "If the view changes data for logged-in users, other websites can trick their browsers into submitting requests to it.",
    fixSteps: [
      "Remove @csrf_exempt and send the CSRF token from your frontend.",
      "If this is a webhook or token-authenticated API, verify a signature or token instead.",
    ],
    aiFixPrompt:
      "Please remove @csrf_exempt from this Django view and make the client send the CSRF token, or add signature/token verification if it is a webhook.",
  },
];

const SECRET_KEY_RULE = {
  id: "secret/django-secret-key",
  title: "Hardcoded Django SECRET_KEY",
};
const SECRET_KEY_FALLBACK_RULE = {
  id: "secret/django-secret-key-fallback",
  title: "Hardcoded fallback for Django SECRET_KEY",
};

/** A string literal with optional prefix; `q` is the group number of the quote capture. */
const stringLiteral = (q: number) =>
  "([rbfuRBFU]{0,2})(\"\"\"|'''|\"|')((?:\\\\.|(?!\\" + q + ")[^\\\\])*)";
/** `SECRET_KEY = 'literal'` (optionally parenthesised, prefixed or triple-quoted). */
const SECRET_KEY_REGEX = new RegExp(
  String.raw`^(\s*SECRET_KEY\s*=\s*\(?\s*)` + stringLiteral(3),
  "s",
);
/** `SECRET_KEY = f(...)`: group 1 is everything from the first argument on. */
const SECRET_KEY_CALL_REGEX = /^\s*SECRET_KEY\s*=\s*\(?\s*\w+(?:\.\w+)*\(([\s\S]*)$/;
/** Second positional argument or default=/fallback= keyword that is a string literal. */
const FALLBACK_LITERAL_REGEX = new RegExp(
  String.raw`(?:\b(?:default|fallback)\s*=\s*|,\s*)` + stringLiteral(2),
  "gs",
);
const MIN_FALLBACK_LENGTH = 8;

/** Missing transport settings, reported once per project on its base/production settings module. */
const MISSING_RULES = [
  {
    id: "security_config/django-ssl-redirect-missing",
    setting: "SECURE_SSL_REDIRECT",
    title: "Django HTTPS redirect is not configured",
    problem:
      "No production settings module sets SECURE_SSL_REDIRECT, so Django does not send HTTP visitors to HTTPS.",
    why: "Unless your host or proxy already forces HTTPS, logins and cookies can travel over plain HTTP where anyone on the network can read them.",
    fixSteps: [
      "Add SECURE_SSL_REDIRECT = True to your production settings.",
      'Behind a proxy, also set SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https").',
    ],
    aiFixPrompt:
      "Please add SECURE_SSL_REDIRECT = True to my Django production settings (not local development) and set SECURE_PROXY_SSL_HEADER if the app runs behind a proxy.",
  },
  {
    id: "security_config/django-hsts-missing",
    setting: "SECURE_HSTS_SECONDS",
    title: "Django HSTS is not configured",
    problem:
      "No production settings module sets SECURE_HSTS_SECONDS, so browsers are never told to always use HTTPS for your site.",
    why: "Without HSTS, an attacker on the same network can downgrade a visitor's first request to plain HTTP and intercept it.",
    fixSteps: [
      "Add SECURE_HSTS_SECONDS to your production settings, starting small (for example 3600) and raising it to 31536000 once HTTPS works everywhere.",
      "Skip this if your proxy or CDN already sends a Strict-Transport-Security header.",
    ],
    aiFixPrompt:
      "Please add HSTS to my Django production settings with a safe starting SECURE_HSTS_SECONDS value and explain how to raise it later.",
  },
] as const;

/** Top-level `if DEBUG:` / `if settings.DEBUG:` header: the block below is dev-only. */
const DEBUG_BLOCK_RE = /^if\s+\(?\s*(?:settings\.)?DEBUG\s*\)?\s*:/;
/** `NAME = ...`, `NAME += ...` or `NAME: type = ...` at the start of a statement. */
const ASSIGNMENT_RE = /^\s*([A-Z][A-Z0-9_]*)\s*(?::[^=]*)?\+?=(?!=)/;

interface SettingsModule {
  file: string;
  assigned: Set<string>;
}

/** A full Django settings module: it configures apps or middleware plus DEBUG / hosts / key. */
function looksLikeBaseSettings(assigned: Set<string>): boolean {
  return (
    (assigned.has("INSTALLED_APPS") || assigned.has("MIDDLEWARE")) &&
    (assigned.has("DEBUG") || assigned.has("ALLOWED_HOSTS") || assigned.has("SECRET_KEY"))
  );
}

/** settings/prod.py, settings_production.py, live.py, ... */
function isProductionSettings(filePath: string): boolean {
  const stem = (filePath.replace(/\\/g, "/").split("/").pop() ?? "").replace(/\.py$/i, "");
  return /(^|[_.-])(prod|production|live)($|[_.-])/i.test(stem);
}

export class DjangoSettingsDetector implements Detector {
  id = "django-settings-detector";
  name = "Django Settings Detection";
  category = "security_config" as const;
  description =
    "Detects insecure Django settings (DEBUG, SECRET_KEY, ALLOWED_HOSTS, CORS, cookies, HTTPS redirect, HSTS, framing) and csrf_exempt views.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const modules: SettingsModule[] = [];

    for (const filePath of context.files) {
      if (!filePath.endsWith(".py")) continue;
      const settings = isSettingsFile(filePath);
      const devOnly = isDevOnlySettings(filePath);

      let content: string;
      try {
        content = await context.readFile(filePath);
      } catch {
        continue;
      }
      if (!settings && !content.includes("csrf_exempt")) continue;

      const lines = scanPythonLines(content);
      const assigned = new Set<string>();
      let continuedUntil = -1; // last line index consumed as continuation
      let inDebugBlock = false;

      for (let i = 0; i < lines.length; i++) {
        const first = lines[i]!;
        if (first.startsInString) continue;
        const line = first.code;
        if (!line.trim()) continue;

        const isContinuation = i <= continuedUntil;
        if (!isContinuation && first.indent === 0) inDebugBlock = DEBUG_BLOCK_RE.test(line);
        if (/^\s*(import|from)\s/.test(line)) continue;

        // Join continuation lines (brackets, backslashes, triple-quoted strings) into one statement.
        const { stmt, end } = joinStatement(lines, i);
        if (end > continuedUntil) continuedUntil = end;

        if (settings && !isContinuation) {
          const name = ASSIGNMENT_RE.exec(stmt)?.[1];
          if (name) assigned.add(name);
          const secret = this.matchSecretKey(stmt);
          if (secret) {
            findings.push(this.secretKeyFinding(filePath, i + 1, secret));
            continue;
          }
        }

        for (const rule of RULES) {
          if (rule.scope === "settings" && !settings) continue;
          // Settings rules read the joined statement (and skip continuation lines, so keyword
          // arguments are not mistaken for assignments); view rules read the physical line.
          if (rule.scope === "settings" && isContinuation) continue;
          if (rule.prodOnly && devOnly) continue;
          if (rule.skipInDebugBlock && inDebugBlock && first.indent > 0) continue;
          const m = rule.regex.exec(rule.scope === "settings" ? stmt : line);
          if (!m || (rule.check && !rule.check(m))) continue;
          findings.push(this.ruleFinding(rule, filePath, i + 1, line));
          break;
        }
      }

      if (settings && !devOnly) modules.push({ file: filePath, assigned });
    }

    findings.push(...this.missingTransportFindings(modules));
    return findings;
  }

  /** SECURE_SSL_REDIRECT / SECURE_HSTS_SECONDS set in no production settings module. */
  private missingTransportFindings(modules: SettingsModule[]): Finding[] {
    // Only judge projects with a real settings module; report on the production module when
    // there is one (it is where the fix belongs), otherwise on the base module.
    if (!modules.some((m) => looksLikeBaseSettings(m.assigned))) return [];
    const candidates = modules
      .filter(
        (m) =>
          looksLikeBaseSettings(m.assigned) ||
          (isProductionSettings(m.file) &&
            (m.assigned.has("DEBUG") || m.assigned.has("ALLOWED_HOSTS"))),
      )
      .map((m) => m.file)
      .sort((a, b) => {
        const prod = (f: string) => (isProductionSettings(f) ? 0 : 1);
        return prod(a) - prod(b) || a.length - b.length || a.localeCompare(b);
      });
    const target = candidates[0];
    if (!target) return [];

    const findings: Finding[] = [];
    for (const rule of MISSING_RULES) {
      if (modules.some((m) => m.assigned.has(rule.setting))) continue;
      findings.push({
        id: createFindingId(
          CATEGORY_PREFIX.security_config,
          rule.id,
          target,
          undefined,
          rule.setting,
        ),
        ruleId: rule.id,
        title: rule.title,
        severity: "low",
        category: "security_config",
        deployBlocking: false,
        confidence: "medium",
        file: target,
        evidence: `${rule.setting} is not set in any production settings module`,
        plainEnglishProblem: rule.problem,
        whyItMatters: rule.why,
        fixSteps: [...rule.fixSteps],
        autoFixAvailable: false,
        aiFixPrompt: rule.aiFixPrompt,
      });
    }
    return findings;
  }

  private matchSecretKey(stmt: string): SecretMatch | null {
    const literal = SECRET_KEY_REGEX.exec(stmt);
    if (literal) {
      const head = literal[1] ?? "";
      const prefix = literal[2] ?? "";
      const value = literal[4] ?? "";
      const interpolated = prefix.toLowerCase().includes("f") && value.includes("{");
      if (value.trim() && !interpolated) return { kind: "literal", head, value };
      return null;
    }

    const call = SECRET_KEY_CALL_REGEX.exec(stmt);
    if (!call?.[1]) return null;
    const head = stmt.slice(0, stmt.length - call[1].length);
    for (const m of call[1].matchAll(FALLBACK_LITERAL_REGEX)) {
      const prefix = m[1] ?? "";
      const value = m[3] ?? "";
      if (value.length < MIN_FALLBACK_LENGTH) continue;
      if (prefix.toLowerCase().includes("f") && value.includes("{")) continue;
      return { kind: "fallback", head: head.replace(/\s+/g, " "), value };
    }
    return null;
  }

  private ruleFinding(rule: DjangoRule, filePath: string, lineNo: number, line: string): Finding {
    let severity = rule.severity;
    // e.g. DEBUG in a clearly dev-only settings module is expected
    const devOnly = rule.devSeverity !== undefined && isDevOnlySettings(filePath);
    if (devOnly && rule.devSeverity) severity = rule.devSeverity;
    const indented = /^\s+/.test(line);

    return {
      id: createFindingId(CATEGORY_PREFIX[rule.category], rule.id, filePath, lineNo, line.trim()),
      ruleId: rule.id,
      title: rule.title,
      severity,
      category: rule.category,
      deployBlocking: false,
      confidence: devOnly || indented ? "medium" : "high",
      file: filePath,
      line: lineNo,
      evidence: sanitizeEvidence(line),
      plainEnglishProblem: rule.problem,
      whyItMatters: rule.why,
      fixSteps: rule.fixSteps,
      autoFixAvailable: false,
      aiFixPrompt: rule.aiFixPrompt,
    };
  }

  private secretKeyFinding(filePath: string, lineNo: number, m: SecretMatch): Finding {
    const fallback = m.kind === "fallback";
    const rule = fallback ? SECRET_KEY_FALLBACK_RULE : SECRET_KEY_RULE;
    return {
      id: createFindingId(CATEGORY_PREFIX.secret, rule.id, filePath, lineNo, m.value),
      ruleId: rule.id,
      title: rule.title,
      severity: fallback ? "high" : "critical",
      category: "secret",
      deployBlocking: true,
      confidence: fallback ? "medium" : "high",
      file: filePath,
      line: lineNo,
      evidence: sanitizeEvidence(
        `${m.head.replace(/\s+/g, " ")}"${redactSecret(m.value.trim())}"${fallback ? ", ...)" : ""}`,
      ),
      plainEnglishProblem: fallback
        ? "Django's SECRET_KEY falls back to a key written directly in your settings file when the environment variable is not set."
        : "Django's SECRET_KEY is written directly in your settings file instead of being read from the environment.",
      whyItMatters:
        "SECRET_KEY signs sessions, password reset tokens and cookies. Anyone who sees it (for example in a public repo) can forge them and may be able to take over accounts. A committed fallback is what production silently uses when the variable is missing.",
      fixSteps: [
        "Generate a new SECRET_KEY, since the committed one is compromised.",
        'Read it from the environment with no fallback: SECRET_KEY = os.environ["DJANGO_SECRET_KEY"].',
        "Keep the real value in a .env file or your host's secret store and make sure it is gitignored.",
      ],
      autoFixAvailable: false,
      aiFixPrompt:
        "My Django SECRET_KEY is hardcoded in settings. Please change it to read from an environment variable (failing loudly when missing in production) and tell me what to add to my .env file.",
    };
  }
}

interface SecretMatch {
  kind: "literal" | "fallback";
  /** Source text before the literal, used for evidence. */
  head: string;
  value: string;
}
