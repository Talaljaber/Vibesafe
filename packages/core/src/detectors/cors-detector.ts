import type { Detector, Finding, ScanContext, Severity } from "@vibesafe/shared";
import { CATEGORY_PREFIX, createFindingId } from "@vibesafe/shared";
import { sanitizeEvidence } from "./utils/sanitize-evidence.js";

const CODE_EXTENSIONS = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"];

const COOKIE_USAGE_RE =
  /cookie-parser|express-session|cookie-session|\breq\.cookies\b|\breq\.session\b|\bres\.cookie\s*\(|\bcookies\s*\(\s*\)|next-auth|iron-session/;
const CORS_IMPORT_RE = /from\s+["']cors["']|require\(\s*["']cors["']\s*\)/;
/** Local bindings of the cors package: default import, namespace import, or require assignment. */
const CORS_BINDING_RES = [
  /import\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s*(?:,\s*\{[^}]*\})?\s*from\s*["']cors["']/g,
  /import\s*\{[^}]*\bdefault\s+as\s+([A-Za-z_$][\w$]*)[^}]*\}\s*from\s*["']cors["']/g,
  /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*["']cors["']\s*\)/g,
];
const ALLOW_ORIGIN_RE = /Access-Control-Allow-Origin/i;
const ALLOW_CREDENTIALS_TRUE_RE = /Access-Control-Allow-Credentials["'`]?\s*[,:]?\s*["'`]?\s*true/i;
const WILDCARD_HEADER_RE =
  /Access-Control-Allow-Origin["'`]?\s*[,:]\s*["'`]\*["'`]|key\s*:\s*["'`]Access-Control-Allow-Origin["'`]\s*,\s*value\s*:\s*["'`]\*["'`]/gi;
const REFLECT_ORIGIN_RE =
  /Access-Control-Allow-Origin["'`]?\s*[,:]\s*(?:req(?:uest)?\.headers(?:\.origin|\[\s*["']origin["']\s*\])|[\w.]*headers\.get\(\s*["']origin["']\s*\)|req\.get\(\s*["']origin["']\s*\)|req\.header\(\s*["']origin["']\s*\)|origin\b)/gi;
/** How many lines above a reflected header we look for an allowlist check (a heuristic). */
const ALLOWLIST_WINDOW_LINES = 25;
/** Names that suggest an allowlist. */
const ALLOWLIST_NAME_RE = /allow(?:ed)?(?:list|_?origins?)|whitelist|trusted(?:Origins)?/i;

/** Evidence of an allowlist check that involves the reflected origin variable `ident`. */
function hasAllowlistHint(text: string, ident: string): boolean {
  if (ALLOWLIST_NAME_RE.test(text)) return true;
  const id = ident.replace(/\$/g, "\\$");
  return new RegExp(
    `\\.(?:includes|has|indexOf|test|some)\\s*\\([^\\n]*\\b${id}\\b|\\b${id}\\b\\s*(?:===|==)\\s*["'\`]|["'\`]\\s*(?:===|==)\\s*${id}\\b`,
  ).test(text);
}
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

/**
 * Blanks out comments and regex literal bodies (keeping length and newlines, so offsets and
 * line numbers are unchanged) so quote tracking and option regexes are not fooled by them.
 */
function stripNoise(src: string): string {
  const out = src.split("");
  const len = src.length;
  const blank = (from: number, to: number): void => {
    for (let k = from; k < to; k++) if (out[k] !== "\n" && out[k] !== "\r") out[k] = " ";
  };
  let last = "";
  let i = 0;
  while (i < len) {
    const ch = src[i] as string;
    const next = src[i + 1];
    if (ch === "/" && next === "/") {
      let e = src.indexOf("\n", i);
      if (e < 0) e = len;
      blank(i, e);
      i = e;
    } else if (ch === "/" && next === "*") {
      const c = src.indexOf("*/", i + 2);
      const e = c < 0 ? len : c + 2;
      blank(i, e);
      i = e;
    } else if (ch === '"' || ch === "'" || ch === "`") {
      let j = i + 1;
      while (j < len) {
        const c = src[j];
        if (c === "\\") {
          j += 2;
          continue;
        }
        if (c === ch || (c === "\n" && ch !== "`")) break;
        j++;
      }
      i = Math.min(j + 1, len);
      last = ch;
    } else if (ch === "/" && (last === "" || "(,=:[!&|?+-*%~^;{".includes(last))) {
      let j = i + 1;
      let inClass = false;
      while (j < len) {
        const c = src[j];
        if (c === "\\") {
          j += 2;
          continue;
        }
        if (c === "\n") break;
        if (c === "[") inClass = true;
        else if (c === "]") inClass = false;
        else if (c === "/" && !inClass) break;
        j++;
      }
      blank(i + 1, Math.min(j, len));
      i = Math.min(j + 1, len);
      last = ")";
    } else {
      if (!/\s/.test(ch)) last = ch;
      i++;
    }
  }
  return out.join("");
}

/** Returns the text between the bracket at `openIdx` and its match (exclusive), or undefined. Expects comment-stripped input. */
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

/** Fallback when brackets cannot be balanced: the next 15 lines from the call. */
function boundedWindow(content: string, openIdx: number): string {
  let end = openIdx;
  for (let n = 0; n < 15 && end >= 0; n++) end = content.indexOf("\n", end + 1);
  return content.slice(openIdx + 1, end < 0 ? content.length : end);
}

/** Resolve `cors(opts)` where `opts` is a same-file object literal. Spread, imported or cross-file options are not resolved. */
function resolveArgs(content: string, args: string): string {
  const ident = /^\s*([A-Za-z_$][\w$]*)\s*$/.exec(args);
  if (!ident?.[1]) return args;
  const id = ident[1].replace(/\$/g, "\\$");
  const decl = new RegExp(`(?:const|let|var)\\s+${id}\\b[^=]*=\\s*\\{`).exec(content);
  if (!decl) return args;
  return balanced(content, decl.index + decl[0].length - 1) ?? args;
}

function corsBindings(code: string): string[] {
  const names = new Set<string>();
  for (const re of CORS_BINDING_RES) for (const m of code.matchAll(re)) if (m[1]) names.add(m[1]);
  if (names.size === 0) names.add("cors");
  return [...names];
}

function usesCookies(content: string): boolean {
  return COOKIE_USAGE_RE.test(content);
}

type Rule = "wildcard-credentials" | "default-with-cookies" | "wildcard-header" | "reflected-origin";

/**
 * Heuristics and known limits: options that are spread, imported or built in another file are
 * not resolved (treated as safe). Reflected headers are suppressed when an allowlist hint that
 * mentions the origin variable (or an allowlist-like name) appears in the preceding
 * ALLOWLIST_WINDOW_LINES lines; a check further away is not seen. Credentials headers are
 * matched file-wide. Browsers block a literal `*` with credentials, so that is medium;
 * reflection (`origin: true`, reflecting functions, reflected headers) is high.
 */
export class CorsDetector implements Detector {
  id = "cors-detector";
  name = "CORS Configuration Detection";
  category = "security_config" as const;
  description = "Detects insecure CORS configuration: wildcard or reflected origins, especially with credentials.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const paths = context.files.filter(isScannable);

    // Pass 1: only the cookie-usage boolean is kept per file (the pipeline may still cache file contents).
    let projectUsesCookies = false;
    for (const filePath of paths) {
      const content = await context.readFile(filePath);
      if (content && usesCookies(stripNoise(content))) {
        projectUsesCookies = true;
        break;
      }
    }

    for (const path of paths) {
      const content = await context.readFile(path);
      if (!content) continue;
      const code = stripNoise(content);
      const origLines = content.split("\n");
      const codeLines = code.split("\n");
      const lineText = (n: number): string => origLines[n - 1] ?? "";
      const seen = new Set<number>();
      const push = (rule: Rule, line: number, severity: Severity): void => {
        if (seen.has(line)) return;
        seen.add(line);
        findings.push(this.createFinding(rule, path, line, sanitizeEvidence(lineText(line)), severity));
      };

      if (CORS_IMPORT_RE.test(code)) {
        const names = corsBindings(code).map((n) => n.replace(/\$/g, "\\$"));
        const callRe = new RegExp(`(?<![\\w.$])(?:${names.join("|")})\\s*\\(`, "g");
        for (const m of code.matchAll(callRe)) {
          const line = lineOf(code, m.index);
          const openIdx = m.index + m[0].length - 1;
          const args = balanced(code, openIdx) ?? boundedWindow(code, openIdx);
          const opts = resolveArgs(code, args);

          if (opts.trim() === "") {
            if (projectUsesCookies) push("default-with-cookies", line, "medium");
            continue;
          }

          const credentials = /credentials\s*:\s*true\b/.test(opts);
          const wildcardStar = /origin\s*:\s*["'`]\*["'`]/.test(opts);
          const originTrue = /origin\s*:\s*true\b/.test(opts);
          if (this.isReflectingOriginFn(opts) || (credentials && originTrue)) {
            push("reflected-origin", line, "high");
          } else if (credentials && wildcardStar) {
            push("wildcard-credentials", line, "medium");
          } else if ((wildcardStar || originTrue) && projectUsesCookies) {
            push("default-with-cookies", line, "medium");
          }
        }
      }

      // Manual headers: reflection and wildcards in any file.
      if (!ALLOW_ORIGIN_RE.test(code)) continue;
      const hasCredentials = ALLOW_CREDENTIALS_TRUE_RE.test(code);

      for (const m of code.matchAll(REFLECT_ORIGIN_RE)) {
        const line = lineOf(code, m.index);
        const window = codeLines.slice(Math.max(0, line - 1 - ALLOWLIST_WINDOW_LINES), line).join("\n");
        if (!hasAllowlistHint(window, "origin")) push("reflected-origin", line, "high");
      }
      if (isNextCorsSurface(path) || hasCredentials || projectUsesCookies) {
        for (const m of code.matchAll(WILDCARD_HEADER_RE)) push("wildcard-header", lineOf(code, m.index), "medium");
      }
    }

    return findings;
  }

  /** `origin: (origin, cb) => cb(null, true)` or `cb(null, origin)` with no allowlist check on the origin. */
  private isReflectingOriginFn(opts: string): boolean {
    const m = /origin\s*:\s*(?:async\s*)?(?:function\s*\w*\s*)?\(\s*([A-Za-z_$][\w$]*)?/.exec(opts);
    if (!m) return false;
    const param = m[1];
    const body = opts.slice(m.index);
    const target = param ? `(?:true|${param.replace(/\$/g, "\\$")})` : "true";
    if (!new RegExp(`\\(\\s*null\\s*,\\s*${target}\\s*\\)`).test(body)) return false;
    return !hasAllowlistHint(body, param ?? "origin") && !/[!=]==?\s/.test(body);
  }
  private createFinding(rule: Rule, file: string, line: number, evidence: string, severity: Severity): Finding {
    const ruleId = `security_config/cors-${rule}`;
    const copy: Record<Rule, { title: string; problem: string }> = {
      "wildcard-credentials": {
        title: "CORS combines a wildcard origin with credentials",
        problem:
          "Your CORS setup pairs `origin: \"*\"` with `credentials: true`. Browsers block credentialed requests to a wildcard, so this is a misconfiguration that likely breaks your app and tempts people to reflect any origin instead.",
      },
      "default-with-cookies": {
        title: "CORS enabled with default options in a cookie-based app",
        problem:
          "`cors()` is called with no options or an any-origin setting (`origin: \"*\"` / `origin: true`), which allows requests from any origin, in an app that uses cookies or sessions.",
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
