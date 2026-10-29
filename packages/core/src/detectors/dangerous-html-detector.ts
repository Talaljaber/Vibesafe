import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { CATEGORY_PREFIX, createFindingId } from "@talaljaber/vibesafe-shared";
import { sanitizeEvidence } from "./utils/sanitize-evidence.js";
import { isGenerated } from "./utils/file-kind.js";

const SCANNABLE_SUFFIXES = [".tsx", ".jsx", ".js", ".mjs", ".cjs"] as const;

const DANGEROUS_HTML_RE = /dangerouslySetInnerHTML/;

/** Packages whose default/namespace import is an HTML sanitizer. */
const SANITIZER_MODULES = ["dompurify", "isomorphic-dompurify", "sanitize-html", "xss"];

/** Sanitizer calls recognised without looking at imports. `marked.parse` is not one. */
const KNOWN_SANITIZER_CALL_RE =
  /\b(?:DOMPurify|DomPurify|dompurify|purify)\s*\.\s*sanitize\s*\(|\bsanitize(?:Html|HTML)?\s*\(|\bfilterXSS\s*\(/;

/** How far ahead of the attribute the `__html:` key may sit. */
const HTML_KEY_WINDOW = 400;
/** Longest initializer read when tracing a variable back to its declaration. */
const MAX_INITIALIZER = 4000;
const MAX_TRACE_DEPTH = 3;

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Local names bound to a sanitizer module (`import X from "dompurify"`, `require("sanitize-html")`). */
function sanitizerBindings(content: string): string[] {
  const names = new Set<string>();
  const modules = SANITIZER_MODULES.map(escapeRe).join("|");
  const importRe = new RegExp(
    String.raw`\bimport\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s*(?:,\s*\{[^}]*\})?\s*from\s*['"](?:${modules})['"]`,
    "g",
  );
  const namedRe = new RegExp(
    String.raw`\bimport\s*\{([^}]*)\}\s*from\s*['"](?:${modules})['"]`,
    "g",
  );
  const requireRe = new RegExp(
    String.raw`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"](?:${modules})['"]\s*\)`,
    "g",
  );
  for (const m of content.matchAll(importRe)) if (m[1]) names.add(m[1]);
  for (const m of content.matchAll(requireRe)) if (m[1]) names.add(m[1]);
  for (const m of content.matchAll(namedRe)) {
    for (const part of (m[1] ?? "").split(",")) {
      const local = part
        .split(/\s+as\s+/)
        .pop()
        ?.trim();
      if (local && /^[A-Za-z_$][\w$]*$/.test(local)) names.add(local);
    }
  }
  return [...names];
}

function isSanitizedExpression(expr: string, bindings: readonly string[]): boolean {
  if (KNOWN_SANITIZER_CALL_RE.test(expr)) return true;
  for (const name of bindings) {
    const n = escapeRe(name);
    if (new RegExp(String.raw`(?<![\w$.])${n}\s*(?:\.\s*sanitize\s*)?\(`).test(expr)) return true;
  }
  return false;
}

/**
 * Reads one expression starting at `start`, stopping at a `,`, `;`, `}` or `)` that closes
 * nothing opened inside it. Skips string and template literals. Bounded by `max` chars.
 */
function readExpression(content: string, start: number, max: number): string {
  let depth = 0;
  let i = start;
  const end = Math.min(content.length, start + max);
  while (i < end) {
    const ch = content[i]!;
    if (ch === '"' || ch === "'" || ch === "`") {
      const quote = ch;
      i++;
      while (i < end && content[i] !== quote) {
        if (content[i] === "\\") i++;
        i++;
      }
      i++;
      continue;
    }
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") {
      if (depth === 0) break;
      depth--;
    } else if ((ch === "," || ch === ";") && depth === 0) break;
    i++;
  }
  return content.slice(start, i).trim();
}

/** The initializer of the closest `const|let|var name =` or `name =` before `before`. */
function initializerOf(content: string, name: string, before: number): string | undefined {
  const n = escapeRe(name);
  const re = new RegExp(
    String.raw`(?:\b(?:const|let|var)\s+${n}|(?<![\w$.])${n})\s*=(?![=>])`,
    "g",
  );
  let last: RegExpExecArray | undefined;
  for (const m of content.slice(0, before).matchAll(re)) last = m as RegExpExecArray;
  if (!last) return undefined;
  return readExpression(content, last.index + last[0].length, MAX_INITIALIZER);
}

/** True when the HTML handed to the attribute provably went through a sanitizer. */
function htmlIsSanitized(content: string, attrIndex: number, bindings: readonly string[]): boolean {
  const ahead = content.slice(attrIndex, attrIndex + HTML_KEY_WINDOW);
  const key = /__html\s*:\s*/.exec(ahead);
  if (!key) return false;
  let expr = readExpression(content, attrIndex + key.index + key[0].length, MAX_INITIALIZER);
  for (let depth = 0; depth <= MAX_TRACE_DEPTH; depth++) {
    if (isSanitizedExpression(expr, bindings)) return true;
    // Follow a bare identifier (optionally `as string` / `?? ''`) back to its declaration.
    const ident = /^([A-Za-z_$][\w$]*)(?:\s+as\s+[\w$.<>[\]| ]+)?(?:\s*\?\?\s*(?:''|""|``))?$/.exec(
      expr,
    );
    if (!ident?.[1]) return false;
    const init = initializerOf(content, ident[1], attrIndex);
    if (init === undefined) return false;
    expr = init;
  }
  return false;
}

/**
 * Flags `dangerouslySetInnerHTML` in JSX/TSX and plain JS files. The attribute
 * is a common XSS vector when the injected HTML is user-controlled and not
 * sanitized. HTML is treated as sanitized only when the `__html` value itself, or the
 * variable it names (traced back to its declaration, including multi-line `useMemo`
 * initializers), goes through DOMPurify / isomorphic-dompurify / sanitize-html / xss.
 * Rendering Markdown (`marked.parse`) alone does not sanitize.
 */
export class DangerousHtmlDetector implements Detector {
  id = "dangerous-html-detector";
  name = "Dangerous HTML Detection";
  category = "xss" as const;
  description =
    "Detects `dangerouslySetInnerHTML` usage, a common XSS vector when input isn't sanitized.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const filePath of context.files) {
      if (!SCANNABLE_SUFFIXES.some((suffix) => filePath.endsWith(suffix))) continue;

      const content = await context.readFile(filePath);
      if (!content.includes("dangerouslySetInnerHTML") || isGenerated(filePath, content)) continue;
      const lines = content.split("\n");
      const bindings = sanitizerBindings(content);

      let offset = 0;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const lineStart = offset;
        offset += (line ?? "").length + 1;
        if (line === undefined) continue;

        const match = DANGEROUS_HTML_RE.exec(line);
        if (match && match[0]) {
          if (/^\s*(\/\/|\/\*|\*)/.test(line)) continue;
          // JSON-LD: serialising a trusted object into a script tag.
          const window = lines.slice(Math.max(0, i - 3), i + 4).join("\n");
          const jsonLd =
            /application\/ld\+json/.test(window) && /JSON\.stringify\s*\(/.test(window);
          if (jsonLd) continue;
          try {
            if (htmlIsSanitized(content, lineStart + match.index, bindings)) continue;
          } catch {
            // Fall through and report: never throw from a detector.
          }
          findings.push(this.createFinding(filePath, i + 1, sanitizeEvidence(match[0])));
        }
      }
    }

    return findings;
  }

  private createFinding(filePath: string, line: number, evidence: string): Finding {
    return {
      id: createFindingId(
        CATEGORY_PREFIX.xss,
        "xss/dangerously-set-inner-html",
        filePath,
        line,
        evidence,
      ),
      ruleId: "xss/dangerously-set-inner-html",
      title: "dangerouslySetInnerHTML usage",
      severity: "high",
      category: "xss",
      deployBlocking: false,
      confidence: "medium",
      file: filePath,
      line,
      evidence,
      plainEnglishProblem: `Your React component injects raw HTML directly into the page using \`dangerouslySetInnerHTML\`.`,
      whyItMatters: `If the HTML ever comes from users (database, API, or URL), an attacker can inject <script> tags to steal sessions or deface your app. This attribute is a common XSS attack vector.`,
      fixSteps: [
        "Check where the HTML string comes from — is it user-controlled (from API/database/URL) or a trusted constant?",
        "If user-controlled: sanitize it with a library like DOMPurify before rendering: `DOMPurify.sanitize(html)`. Rendering Markdown (for example with `marked`) does not sanitize; sanitize its output too.",
        "If possible, avoid raw HTML entirely: render React elements/components instead of HTML strings.",
        "If it must stay, document why the input is trusted near the attribute.",
      ],
      autoFixAvailable: false,
      aiFixPrompt: `I have a React component using dangerouslySetInnerHTML. Review where the HTML comes from. If it is user-controlled, sanitize it with DOMPurify before rendering. Show me the updated code.`,
    };
  }
}
