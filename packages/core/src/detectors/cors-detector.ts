import type { Detector, Finding, ScanContext, Severity } from "@vibesafe/shared";
import { CATEGORY_PREFIX, createFindingId } from "@vibesafe/shared";
import { sanitizeEvidence } from "./utils/sanitize-evidence.js";

const CODE_EXTENSIONS = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"];

const COOKIE_USAGE_RE =
  /cookie-parser|express-session|cookie-session|\breq\.cookies\b|\breq\.session\b|\bres\.cookie\s*\(|\bcookies\s*\(\s*\)|next-auth|iron-session/;
const CORS_IMPORT_RE = /from\s+["']cors["']|require\(\s*["']cors["']\s*\)/;
const CORS_CALL_RE = /(?<![\w.$])cors\s*\(/g;
const ALLOW_ORIGIN_RE = /Access-Control-Allow-Origin/i;
const ALLOW_CREDENTIALS_TRUE_RE = /Access-Control-Allow-Credentials["'`]?\s*[,:]?\s*["'`]?\s*true/i;
const WILDCARD_HEADER_RE =
  /Access-Control-Allow-Origin["'`]?\s*[,:]\s*["'`]\*["'`]|key\s*:\s*["'`]Access-Control-Allow-Origin["'`]\s*,\s*value\s*:\s*["'`]\*["'`]/i;
const REFLECT_ORIGIN_RE =
  /Access-Control-Allow-Origin["'`]?\s*[,:]\s*(?:req(?:uest)?\.headers(?:\.origin|\[\s*["']origin["']\s*\])|[\w.]*headers\.get\(\s*["']origin["']\s*\)|req\.get\(\s*["']origin["']\s*\)|req\.header\(\s*["']origin["']\s*\)|origin\b)/i;
/** Evidence of an allowlist check near a reflected origin. */
const ALLOWLIST_HINT_RE =
  /allow(?:ed)?(?:list|_?origins?)|whitelist|trusted(?:Origins)?|\.includes\s*\(|\.has\s*\(|\.indexOf\s*\(|\.test\s*\(|\.some\s*\(|origin\s*(?:===|==)\s*["'`]/i;

function normalize(filePath: string): string {
  return filePath.replace(/\\/g, "/");
}

function isScannable(filePath: string): boolean {
  if (!CODE_EXTENSIONS.some((ext) => filePath.endsWith(ext))) return false;
  const p = normalize(filePath);
  const name = p.split("/").pop() ?? p;
  return (
    !p.split("/").includes("__tests__") &&
    !name.includes(".test.") &&
    !name.includes(".spec.") &&
    !p.endsWith(".d.ts")
  );
}

/** Next.js route handlers, middleware and next.config files, where manual CORS headers are set. */
function isNextCorsSurface(filePath: string): boolean {
  const p = normalize(filePath);
  const name = p.split("/").pop() ?? p;
  if (/^next\.config\.[cm]?[jt]s$/.test(name)) return true;
  if (/^middleware\.[cm]?[jt]sx?$/.test(name)) return true;
  if (/^route\.[cm]?[jt]sx?$/.test(name)) return true;
  return /(?:^|\/)pages\/api\//.test(p);
}

function lineOf(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i++) if (content.charCodeAt(i) === 10) line++;
  return line;
}

/** Returns the text between the bracket at `openIdx` and its match (exclusive), or undefined. */
function balanced(content: string, openIdx: number): string | undefined {
  const open = content[openIdx];
  const close = open === "(" ? ")" : open === "{" ? "}" : undefined;
  if (!close) return undefined;
  let depth = 0;
  let quote: string | undefined;
  for (let i = openIdx; i < content.length; i++) {
    const ch = content[i] as string;
    if (quote) {
      if (ch === "\\") i++;
      else if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") quote = ch;
    else if (ch === open) depth++;
    else if (ch === close && --depth === 0) return content.slice(openIdx + 1, i);
  }
  return undefined;
}

function isCommentLine(line: string): boolean {
  return /^\s*(\/\/|\/\*|\*)/.test(line);
}

/** Resolve `cors(opts)` where `opts` is a same-file object literal. */
function resolveArgs(content: string, args: string): string {
  const ident = /^\s*([A-Za-z_$][\w$]*)\s*$/.exec(args);
  if (!ident?.[1]) return args;
  const decl = new RegExp(`(?:const|let|var)\\s+${ident[1]}\\b[^=]*=\\s*\\{`).exec(content);
  if (!decl) return args;
  return balanced(content, decl.index + decl[0].length - 1) ?? args;
}

type Rule = "wildcard-credentials" | "default-with-cookies" | "wildcard-header" | "reflected-origin";

export class CorsDetector implements Detector {
  id = "cors-detector";
  name = "CORS Configuration Detection";
  category = "security_config" as const;
  description = "Detects insecure CORS configuration: wildcard or reflected origins, especially with credentials.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const files: { path: string; content: string }[] = [];
    let projectUsesCookies = false;

    for (const filePath of context.files) {
      if (!isScannable(filePath)) continue;
      const content = await context.readFile(filePath);
      if (!content) continue;
      files.push({ path: filePath, content });
      if (COOKIE_USAGE_RE.test(content)) projectUsesCookies = true;
    }

    for (const { path, content } of files) {
      const seen = new Set<number>();
      const push = (rule: Rule, line: number, text: string, severity: Severity): void => {
        if (seen.has(line)) return;
        seen.add(line);
        findings.push(this.createFinding(rule, path, line, sanitizeEvidence(text), severity));
      };
      const lines = content.split("\n");
      const lineText = (n: number): string => lines[n - 1] ?? "";

      if (CORS_IMPORT_RE.test(content)) {
        for (const m of content.matchAll(CORS_CALL_RE)) {
          const line = lineOf(content, m.index);
          if (isCommentLine(lineText(line))) continue;
          const args = balanced(content, m.index + m[0].length - 1);
          if (args === undefined) continue;
          const opts = resolveArgs(content, args);

          if (opts.trim() === "") {
            if (projectUsesCookies) push("default-with-cookies", line, lineText(line), "medium");
            continue;
          }

          const credentials = /credentials\s*:\s*true\b/.test(opts);
          const wildcardOrigin = /origin\s*:\s*(?:["'`]\*["'`]|true\b)/.test(opts);
          const reflectFn = this.isReflectingOriginFn(opts);
          if (credentials && (wildcardOrigin || reflectFn)) {
            push("wildcard-credentials", line, lineText(line), "high");
          } else if (reflectFn) {
            push("reflected-origin", line, lineText(line), "high");
          }
        }
      }

      // Manual headers: wildcards only on Next.js surfaces, reflection in any file.
      if (!ALLOW_ORIGIN_RE.test(content)) continue;
      const nextSurface = isNextCorsSurface(path);
      const hasCredentials = ALLOW_CREDENTIALS_TRUE_RE.test(content);

      for (let i = 0; i < lines.length; i++) {
        const text = lines[i] ?? "";
        if (isCommentLine(text)) continue;

        if (REFLECT_ORIGIN_RE.test(text)) {
          const window = lines.slice(Math.max(0, i - 8), i + 1).join("\n");
          if (!ALLOWLIST_HINT_RE.test(window)) push("reflected-origin", i + 1, text, "high");
          continue;
        }
        if (nextSurface && WILDCARD_HEADER_RE.test(text)) {
          push("wildcard-header", i + 1, text, hasCredentials ? "high" : "medium");
        }
      }
    }

    return findings;
  }

  /** `origin: (origin, cb) => cb(null, true)` with no comparison against an allowlist. */
  private isReflectingOriginFn(opts: string): boolean {
    const m = /origin\s*:\s*(?:async\s*)?(?:function\s*\w*\s*)?\(/.exec(opts);
    if (!m) return false;
    const body = opts.slice(m.index);
    if (!/\(\s*null\s*,\s*true\s*\)/.test(body)) return false;
    return !ALLOWLIST_HINT_RE.test(body) && !/[!=]==?\s/.test(body);
  }

  private createFinding(rule: Rule, file: string, line: number, evidence: string, severity: Severity): Finding {
    const ruleId = `security_config/cors-${rule}`;
    const copy: Record<Rule, { title: string; problem: string }> = {
      "wildcard-credentials": {
        title: "CORS allows any origin with credentials",
        problem:
          "Your CORS setup allows every website to call this API with the visitor's cookies or credentials attached.",
      },
      "default-with-cookies": {
        title: "CORS enabled with default options in a cookie-based app",
        problem:
          "`cors()` is called with no options, which allows requests from any origin, in an app that uses cookies or sessions.",
      },
      "wildcard-header": {
        title: 'Access-Control-Allow-Origin set to "*"',
        problem:
          "This route sets `Access-Control-Allow-Origin: *`, so any website in the world can read its responses from the browser.",
      },
      "reflected-origin": {
        title: "CORS reflects the request Origin without an allowlist",
        problem: "The server echoes back whatever Origin the browser sends, which is the same as allowing every website.",
      },
    };
    const { title, problem } = copy[rule];
    return {
      id: createFindingId(CATEGORY_PREFIX.security_config, ruleId, file, line, evidence),
      ruleId,
      title,
      severity,
      category: "security_config",
      deployBlocking: false,
      confidence: rule === "default-with-cookies" ? "medium" : "high",
      file,
      line,
      evidence,
      plainEnglishProblem: problem,
      whyItMatters:
        "A malicious site can make a logged-in visitor's browser call your API and read the response, leaking private data or performing actions as that user.",
      fixSteps: [
        "Replace the wildcard or reflected origin with an explicit allowlist of the origins you trust (an array, a regex or a checking function).",
        "Only enable `credentials: true` for origins on that allowlist.",
        "Load the allowed origins from an environment variable so production and development can differ.",
      ],
      autoFixAvailable: false,
      aiFixPrompt:
        "Please restrict this CORS configuration to an explicit allowlist of trusted origins read from an environment variable, and never combine a wildcard or reflected origin with credentials.",
    };
  }
}
