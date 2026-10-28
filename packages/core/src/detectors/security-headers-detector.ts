import type { Detector, Finding, ScanContext, Severity } from "@vibesafe/shared";
import { CATEGORY_PREFIX, createFindingId } from "@vibesafe/shared";
import { sanitizeEvidence } from "./utils/sanitize-evidence.js";

const EXPRESS_SOURCE_RE = /\.(?:[cm]?[jt]s|[jt]sx)$/;
const NEXT_CONFIG_RE = /^next\.config\.(?:js|mjs|cjs|ts|mts)$/;
const MIDDLEWARE_RE = /^(?:middleware|proxy)\.(?:js|mjs|cjs|ts|mts)$/;

const EXPRESS_IMPORT_RE = /(?:from\s+["']express["']|require\(\s*["']express["']\s*\))/;
const HELMET_IMPORT_RE = /(?:from\s+["']helmet["']|require\(\s*["']helmet["']\s*\)|import\(\s*["']helmet["']\s*\))/;
const HELMET_USE_RE = /\.use\(\s*(?:[^()]*,\s*)?(?:helmet|[\w$.]*helmet\w*)\s*(?:\(|\))/i;

interface HeaderCheck {
  label: string;
  patterns: RegExp[];
}

const NEXT_HEADERS: HeaderCheck[] = [
  { label: "Content-Security-Policy", patterns: [/content-security-policy/i] },
  { label: "X-Frame-Options (or CSP frame-ancestors)", patterns: [/x-frame-options/i, /frame-ancestors/i] },
  { label: "X-Content-Type-Options", patterns: [/x-content-type-options/i] },
  { label: "Strict-Transport-Security", patterns: [/strict-transport-security/i] },
  { label: "Referrer-Policy", patterns: [/referrer-policy/i] },
];

function normalize(filePath: string): string {
  return filePath.replace(/\\/g, "/");
}

function baseName(filePath: string): string {
  return normalize(filePath).split("/").pop() ?? filePath;
}

function dirName(filePath: string): string {
  const parts = normalize(filePath).split("/");
  parts.pop();
  return parts.join("/");
}

function isTestFile(filePath: string): boolean {
  const normalized = normalize(filePath);
  const name = baseName(normalized);
  return (
    normalized.split("/").includes("__tests__") ||
    normalized.split("/").includes("node_modules") ||
    name.includes(".test.") ||
    name.includes(".spec.")
  );
}

function stripComments(content: string): string {
  return content.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " ")).replace(/^\s*\/\/.*$/gm, "");
}

export class SecurityHeadersDetector implements Detector {
  id = "security-headers-detector";
  name = "Security Headers Detection";
  category = "security_config" as const;
  description = "Detects Express and Next.js apps that do not set standard HTTP security headers.";

  async detect(context: ScanContext): Promise<Finding[]> {
    return [...(await this.detectExpress(context)), ...(await this.detectNext(context))];
  }

  private async detectExpress(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const apps: { filePath: string; line: number; text: string }[] = [];
    let helmetApplied = false;

    for (const filePath of context.files) {
      if (!EXPRESS_SOURCE_RE.test(filePath) || isTestFile(filePath)) continue;
      const raw = await context.readFile(filePath);
      if (!raw) continue;
      const hasHelmet = raw.includes("helmet");
      if (!hasHelmet && !raw.includes("express")) continue;

      const content = stripComments(raw);
      if (HELMET_IMPORT_RE.test(content) && HELMET_USE_RE.test(content)) {
        helmetApplied = true;
      }

      if (!EXPRESS_IMPORT_RE.test(content)) continue;
      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i] ?? "";
        if (/(?<![\w.])express\s*\(\s*\)/.test(line)) {
          apps.push({ filePath, line: i + 1, text: line });
          break;
        }
      }
    }

    // Helmet is often applied in a shared bootstrap file, so any helmet use in the
    // project is treated as protecting every Express app in it.
    if (helmetApplied) return findings;

    for (const app of apps) {
      findings.push({
        id: createFindingId(
          CATEGORY_PREFIX.security_config,
          "security_config/missing-helmet",
          app.filePath,
          app.line,
          "express()",
        ),
        ruleId: "security_config/missing-helmet",
        title: "Express app without helmet security headers",
        severity: "medium",
        category: "security_config",
        deployBlocking: false,
        confidence: "medium",
        file: app.filePath,
        line: app.line,
        evidence: sanitizeEvidence(app.text),
        plainEnglishProblem:
          "This Express app does not use helmet, so it sends no standard security headers and advertises itself with the X-Powered-By: Express header.",
        whyItMatters:
          "Without headers like Content-Security-Policy, X-Content-Type-Options and Strict-Transport-Security, browsers do less to protect your users from clickjacking, MIME sniffing and downgrade attacks, and X-Powered-By tells attackers which framework you run.",
        fixSteps: [
          "Install helmet: npm install helmet.",
          'Import it ("import helmet from \\"helmet\\"") and register it early with app.use(helmet()).',
          'Optionally also call app.disable("x-powered-by") (helmet already removes the header).',
        ],
        autoFixAvailable: false,
        aiFixPrompt:
          "Please add the helmet package to this Express app and register app.use(helmet()) before any routes, configuring Content-Security-Policy for the assets this app serves.",
      });
    }

    return findings;
  }

  private async detectNext(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const configs = context.files.filter((f) => NEXT_CONFIG_RE.test(baseName(f)) && !isTestFile(f));

    for (const configPath of configs) {
      const configRaw = await context.readFile(configPath);
      const configDir = dirName(configPath);
      const sources: string[] = [stripComments(configRaw)];

      // Headers may also be set by middleware or by hosting config next to the app.
      for (const other of context.files) {
        const otherDir = dirName(other);
        const sameApp = otherDir === configDir || otherDir === (configDir ? `${configDir}/src` : "src");
        if (!sameApp) continue;
        const name = baseName(other);
        if (MIDDLEWARE_RE.test(name) || name === "vercel.json") {
          sources.push(stripComments(await context.readFile(other)));
        }
      }

      const combined = sources.join("\n");
      const missing = NEXT_HEADERS.filter((h) => !h.patterns.some((p) => p.test(combined)));
      if (missing.length === 0) continue;

      const noneSet = missing.length === NEXT_HEADERS.length;
      const severity: Severity = noneSet || missing.some((h) => h.label === "Content-Security-Policy") ? "medium" : "low";
      const lines = configRaw.split("\n");
      const headersLineIdx = lines.findIndex((l) => /\bheaders\b/.test(l));
      const line = headersLineIdx >= 0 ? headersLineIdx + 1 : 1;
      const missingList = missing.map((h) => h.label).join(", ");

      findings.push({
        id: createFindingId(
          CATEGORY_PREFIX.security_config,
          "security_config/missing-security-headers",
          configPath,
          line,
          missingList,
        ),
        ruleId: "security_config/missing-security-headers",
        title: "Next.js app is missing security headers",
        severity,
        category: "security_config",
        deployBlocking: false,
        confidence: "medium",
        file: configPath,
        line,
        evidence: sanitizeEvidence(lines[line - 1] ?? ""),
        plainEnglishProblem: `This Next.js app does not set these security headers in next.config or middleware: ${missingList}.`,
        whyItMatters:
          "Security headers tell browsers to block clickjacking, MIME sniffing, insecure transport and leaky referrers. Next.js does not add them by default, and it also sends X-Powered-By: Next.js unless disabled.",
        fixSteps: [
          "Add an async headers() function to next.config that returns these headers for source \"/(.*)\".",
          `Add the missing headers: ${missingList}.`,
          "Set poweredByHeader: false in next.config.",
        ],
        autoFixAvailable: false,
        aiFixPrompt: `Please add an async headers() function to this next.config that sets the missing security headers (${missingList}) on all routes, with a sensible Content-Security-Policy for this app.`,
      });
    }

    return findings;
  }
}
