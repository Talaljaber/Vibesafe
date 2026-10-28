import type { Detector, Finding, FindingCategory, ScanContext, Severity } from "@vibesafe/shared";
import { CATEGORY_PREFIX, createFindingId, redactSecret } from "@vibesafe/shared";
import { sanitizeEvidence } from "./utils/sanitize-evidence.js";

interface DjangoRule {
  id: string;
  category: FindingCategory;
  title: string;
  severity: Severity;
  /** Severity used instead when the file is a dev-only settings module. */
  devSeverity?: Severity;
  /** Settings rules only run in settings modules; view rules run in any .py file. */
  scope: "settings" | "any";
  /** Settings rules match the logical statement (bracketed lines joined); "any" rules the physical line. */
  regex: RegExp;
  problem: string;
  why: string;
  fixSteps: string[];
  aiFixPrompt: string;
}

/*
 * Known limits (line/statement based, no real Python parser):
 *  - Only bracket continuation is joined; backslash continuation is not.
 *  - Values built by concatenation, helper functions or other variables are not followed.
 *  - Multi-line triple-quoted SECRET_KEY values are only checked on their first line.
 *  - A second positional string argument of 8+ chars in a SECRET_KEY call is treated as a fallback\n *    key (medium confidence), e.g. get_secret("key", "utf-8-encoding") is a false positive.\n *  - A line that closes a triple-quoted string is skipped, even if code follows the closing quotes.\n *  - A second positional string argument of 8+ chars in a SECRET_KEY call is treated as a fallback\n *    key (medium confidence), e.g. get_secret("key", "utf-8-encoding") is a false positive.\n *  - A line that closes a triple-quoted string is skipped, even if code follows the closing quotes.\n *  - Settings split across modules via `from .base import *` are scanned per file.
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

/** `settings.py`, `settings_prod.py`, or any module inside a `settings/` package. */
function isSettingsFile(filePath: string): boolean {
  const parts = filePath.replace(/\\/g, "/").split("/");
  const fileName = parts.pop() ?? "";
  if (!fileName.endsWith(".py")) return false;
  return /^settings([_.-].*)?\.py$/i.test(fileName) || parts.includes("settings");
}

/** Settings modules that are clearly for local development or testing only. */
function isDevOnlySettings(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, "/").toLowerCase();
  const stem = (normalized.split("/").pop() ?? "").replace(/\.py$/, "");
  return /(^|[_.-])(dev|local|development|test|testing)($|[_.-])/.test(stem);
}

interface ScannedLine {
  /** Line without its trailing comment. */
  code: string;
  /** Net bracket depth change, ignoring brackets inside strings. */
  delta: number;
  /** True when the line starts inside a triple-quoted string (docstring body). */
  startsInString: boolean;
}

/** Tokenises one line, tracking triple-quoted strings across lines. */
function scanLine(
  line: string,
  tripleState: string | null,
): { scanned: ScannedLine; state: string | null } {
  const startsInString = tripleState !== null;
  let state = tripleState;
  let quote: string | null = null;
  let delta = 0;
  let end = line.length;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (state) {
      if (ch === "\\") i++;
      else if (line.startsWith(state, i)) {
        state = null;
        i += 2;
      }
    } else if (quote) {
      if (ch === "\\") i++;
      else if (ch === quote) quote = null;
    } else if (line.startsWith('"""', i) || line.startsWith("'''", i)) {
      state = line.slice(i, i + 3);
      i += 2;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === "#") {
      end = i;
      break;
    } else if (ch === "(" || ch === "[" || ch === "{") {
      delta++;
    } else if (ch === ")" || ch === "]" || ch === "}") {
      delta--;
    }
  }
  return { scanned: { code: line.slice(0, end), delta, startsInString }, state };
}

const MAX_STATEMENT_LINES = 40;

export class DjangoSettingsDetector implements Detector {
  id = "django-settings-detector";
  name = "Django Settings Detection";
  category = "security_config" as const;
  description =
    "Detects insecure Django settings (DEBUG, SECRET_KEY, ALLOWED_HOSTS, CORS, cookies) and csrf_exempt views.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const filePath of context.files) {
      if (!filePath.endsWith(".py")) continue;
      const settings = isSettingsFile(filePath);

      let content: string;
      try {
        content = await context.readFile(filePath);
      } catch {
        continue;
      }
      if (!settings && !content.includes("csrf_exempt")) continue;

      const rawLines = content.split("\n").map((l) => l.replace(/\r$/, ""));
      const lines: ScannedLine[] = [];
      let state: string | null = null;
      for (const raw of rawLines) {
        const r = scanLine(raw, state);
        lines.push(r.scanned);
        state = r.state;
      }

      let continuedUntil = -1; // last line index consumed as continuation

      for (let i = 0; i < lines.length; i++) {
        const first = lines[i]!;
        if (first.startsInString) continue;
        const line = first.code;
        if (!line.trim() || /^\s*(import|from)\s/.test(line)) continue;

        // Join bracketed continuation lines into one logical statement.
        let stmt = line;
        let depth = first.delta;
        let end = i;
        for (let j = i + 1; depth > 0 && j < lines.length && j - i < MAX_STATEMENT_LINES; j++) {
          const next = lines[j]!;
          if (next.startsInString) break;
          stmt += " " + next.code.trim();
          depth += next.delta;
          end = j;
        }

        const isContinuation = i <= continuedUntil;

        if (end > continuedUntil) continuedUntil = end;

        if (settings && !isContinuation) {
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
          if (!rule.regex.test(rule.scope === "settings" ? stmt : line)) continue;
          findings.push(this.ruleFinding(rule, filePath, i + 1, line));
          break;
        }
      }
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
      if (value && !interpolated) return { kind: "literal", head, value };
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
        `${m.head.replace(/\s+/g, " ")}"${redactSecret(m.value)}"${fallback ? ", ...)" : ""}`,
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
