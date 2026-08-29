import type { Detector, Finding, ScanContext } from "@vibesafe/shared";
import crypto from "crypto";

const SCANNABLE_SUFFIXES = [".tsx", ".jsx", ".js", ".mjs", ".cjs"] as const;

const DANGEROUS_HTML_RE = /dangerouslySetInnerHTML/;

/**
 * Flags `dangerouslySetInnerHTML` in JSX/TSX and plain JS files. The attribute
 * is a common XSS vector when the injected HTML is user-controlled and not
 * sanitized.
 */
export class DangerousHtmlDetector implements Detector {
  id = "dangerous-html-detector";
  name = "Dangerous HTML Detection";
  category = "xss" as const;
  description = "Detects `dangerouslySetInnerHTML` usage, a common XSS vector when input isn't sanitized.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const filePath of context.files) {
      if (!SCANNABLE_SUFFIXES.some((suffix) => filePath.endsWith(suffix))) continue;

      const content = await context.readFile(filePath);
      const lines = content.split("\n");

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line === undefined) continue;

        const match = DANGEROUS_HTML_RE.exec(line);
        if (match && match[0]) {
          findings.push(this.createFinding(filePath, i + 1, match[0]));
        }
      }
    }

    return findings;
  }

  private createFinding(filePath: string, line: number, evidence: string): Finding {
    return {
      id: `XSS-${crypto.randomBytes(3).toString("hex")}`,
      ruleId: "xss/dangerously-set-inner-html",
      title: "dangerouslySetInnerHTML usage",
      severity: "high",
      category: "xss",
      deployBlocking: false,
      confidence: "high",
      file: filePath,
      line,
      evidence,
      plainEnglishProblem: `Your React component injects raw HTML directly into the page using \`dangerouslySetInnerHTML\`.`,
      whyItMatters: `If the HTML ever comes from users (database, API, or URL), an attacker can inject <script> tags to steal sessions or deface your app. This attribute is a common XSS attack vector.`,
      fixSteps: [
        "Check where the HTML string comes from — is it user-controlled (from API/database/URL) or a trusted constant?",
        "If user-controlled: sanitize it with a library like DOMPurify before rendering: `DOMPurify.sanitize(html)`.",
        "If possible, avoid raw HTML entirely: render React elements/components instead of HTML strings.",
        "If it must stay, document why the input is trusted near the attribute.",
      ],
      autoFixAvailable: false,
      aiFixPrompt: `I have a React component using dangerouslySetInnerHTML. Review where the HTML comes from. If it is user-controlled, sanitize it with DOMPurify before rendering. Show me the updated code.`,
    };
  }
}
