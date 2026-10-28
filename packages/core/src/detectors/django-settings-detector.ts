import type { Detector, Finding, FindingCategory, ScanContext, Severity } from "@vibesafe/shared";
import { CATEGORY_PREFIX, createFindingId, redactSecret } from "@vibesafe/shared";
import { sanitizeEvidence } from "./utils/sanitize-evidence.js";

interface DjangoRule {
  id: string;
  category: FindingCategory;
  title: string;
  severity: Severity;
  /** Settings rules only run in settings modules; view rules run in any .py file. */
  scope: "settings" | "any";
  regex: RegExp;
  problem: string;
  why: string;
  fixSteps: string[];
  aiFixPrompt: string;
}

const RULES: DjangoRule[] = [
  {
    id: "security_config/django-debug-true",
    category: "security_config",
    title: "Django DEBUG is enabled",
    severity: "high",
    scope: "settings",
    regex: /^\s*DEBUG\s*=\s*True\b/,
    problem: "DEBUG = True is hardcoded in your Django settings.",
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
    regex: /^\s*ALLOWED_HOSTS\s*=\s*[[(][^\])]*['"]\*['"][^\])]*[\])]/,
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
      /^\s*@(?:\w+\.)*csrf_exempt\b|(?<!def\s)(?<![\w.])csrf_exempt\s*\(|method_decorator\(\s*csrf_exempt\b/,
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
const SECRET_KEY_REGEX = /^(\s*SECRET_KEY\s*=\s*)(['"])((?:(?!\2).)+)\2/;

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

/** Removes a trailing `# comment` that is not inside a string literal. */
function stripTrailingComment(line: string): string {
  let quote: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quote) {
      if (ch === "\\") i++;
      else if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === "#") {
      return line.slice(0, i);
    }
  }
  return line;
}

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

      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        if (!raw) continue;
        const line = stripTrailingComment(raw.replace(/\r$/, ""));
        if (!line.trim() || /^\s*(import|from)\s/.test(line)) continue;

        if (settings) {
          const secret = SECRET_KEY_REGEX.exec(line);
          if (secret && secret[1] && secret[3]) {
            findings.push(this.secretKeyFinding(filePath, i + 1, line, secret[1], secret[3]));
            continue;
          }
        }

        for (const rule of RULES) {
          if (rule.scope === "settings" && !settings) continue;
          if (!rule.regex.test(line)) continue;
          findings.push(this.ruleFinding(rule, filePath, i + 1, line));
          break;
        }
      }
    }

    return findings;
  }

  private ruleFinding(rule: DjangoRule, filePath: string, lineNo: number, line: string): Finding {
    let severity = rule.severity;
    // DEBUG in a clearly dev-only settings module is expected
    const devOnly = rule.id.endsWith("django-debug-true") && isDevOnlySettings(filePath);
    if (devOnly) severity = "low";
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

  private secretKeyFinding(
    filePath: string,
    lineNo: number,
    line: string,
    prefix: string,
    value: string,
  ): Finding {
    return {
      id: createFindingId(CATEGORY_PREFIX.secret, SECRET_KEY_RULE.id, filePath, lineNo, value),
      ruleId: SECRET_KEY_RULE.id,
      title: SECRET_KEY_RULE.title,
      severity: "critical",
      category: "secret",
      deployBlocking: true,
      confidence: "high",
      file: filePath,
      line: lineNo,
      evidence: sanitizeEvidence(`${prefix}"${redactSecret(value)}"`),
      plainEnglishProblem:
        "Django's SECRET_KEY is written directly in your settings file instead of being read from the environment.",
      whyItMatters:
        "SECRET_KEY signs sessions, password reset tokens and cookies. Anyone who sees it (for example in a public repo) can forge them and may be able to take over accounts.",
      fixSteps: [
        "Generate a new SECRET_KEY, since the committed one is compromised.",
        'Read it from the environment: SECRET_KEY = os.environ["DJANGO_SECRET_KEY"].',
        "Keep the real value in a .env file or your host's secret store and make sure it is gitignored.",
      ],
      autoFixAvailable: false,
      aiFixPrompt:
        "My Django SECRET_KEY is hardcoded in settings. Please change it to read from an environment variable (failing loudly when missing in production) and tell me what to add to my .env file.",
    };
  }
}
