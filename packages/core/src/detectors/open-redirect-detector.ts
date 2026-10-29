import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { SINK_NEEDLES, sinkPatternsOf } from "./patterns/sink-patterns.js";
import { makeFinding } from "./utils/finding.js";
import { expressionEnd } from "./utils/js-functions.js";
import {
  SinkAnalyzer,
  capPerRule,
  findSinkCalls,
  loadSinkFile,
  prevNonWs,
  sinkArgs,
  type Range,
  type SinkCall,
  type SinkFile,
} from "./utils/sinks.js";

const AI_PROMPT =
  'This server code redirects the browser to a URL taken from request data (a `next`, `returnTo` or `callbackUrl` parameter) without checking that it stays on this site, which is an open redirect: attackers send victims a link to your domain that lands on their phishing page, often right after login. Fix it by only accepting same-site relative paths: require the value to start with a single `/` and not with `//` or `/\\`, and build the target with `new URL(value, request.url)`, then confirm `target.origin` equals your own origin before redirecting; otherwise fall back to a fixed default such as `/dashboard`. A check like `value.startsWith("http")` does not make it safe. If external destinations are needed, compare the parsed hostname against a fixed allowlist.';

/**
 * Redirects to a target controlled by request data (`injection/open-redirect`):
 * `NextResponse.redirect`, `Response.redirect`, `redirect()` from next/navigation,
 * `res.redirect`, `ctx.redirect` and `Location` headers. High when the attacker chooses
 * the whole target (directly or through a ternary branch), medium when the value is
 * appended to a fixed origin without a leading `/` (`${origin}${next}` with
 * `next=@evil.com`). Same-origin construction (`new URL("/login", req.url)`), relative-path
 * checks (`startsWith("/") && !startsWith("//")`), origin comparisons and allowlists are
 * safe; `startsWith("http")` is never a guard.
 */
export class OpenRedirectDetector implements Detector {
  id = "open-redirect-detector";
  name = "Open Redirect";
  category = "injection" as const;
  description =
    "Detects redirects whose target comes from request data without a same-site or allowlist check.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const patterns = sinkPatternsOf("redirect");
    for (const file of context.files) {
      const f = await loadSinkFile(context, file, SINK_NEEDLES.redirect);
      if (f === undefined) continue;
      const an = new SinkAnalyzer(f, "redirect");
      const out: Finding[] = [];
      for (const call of findSinkCalls(f.src, patterns, f.aliases)) {
        try {
          if (call.pattern.locationHeader === true && !this.isLocationName(f, call.args[0]))
            continue;
          for (const arg of sinkArgs(call)) {
            const finding = this.check(f, an, arg, call.start, call);
            if (finding !== undefined) {
              out.push(finding);
              break;
            }
          }
        } catch {
          // a detector never throws
        }
      }
      for (const value of this.locationProperties(f)) {
        try {
          const finding = this.check(f, an, value, value.start, undefined);
          if (finding !== undefined) out.push(finding);
        } catch {
          // a detector never throws
        }
      }
      findings.push(...capPerRule(out));
    }
    return findings;
  }

  private isLocationName(f: SinkFile, arg: Range | undefined): boolean {
    if (arg === undefined) return false;
    return /^(["'`])location\1$/i.test(f.src.text.slice(arg.start, arg.end));
  }

  /** Values of `Location:` properties in header objects (`headers: { Location: url }`). */
  private locationProperties(f: SinkFile): Range[] {
    const out: Range[] = [];
    const { text, code } = f.src;
    if (!/location/i.test(text)) return out;
    const re = /(["']?)location\1\s*:/gi;
    for (let m = re.exec(text); m !== null; m = re.exec(text)) {
      const colon = m.index + m[0].length - 1;
      if (code[colon] !== ":") continue; // inside a comment or a string
      if (m[1] === "" && code.slice(m.index, m.index + 8).toLowerCase() !== "location") continue;
      if (m[1] !== "" && code[m.index] !== m[1]) continue;
      const prev = prevNonWs(code, m.index - 1);
      if (code[prev] !== "{" && code[prev] !== ",") continue; // an object key
      const start = colon + 1;
      const end = expressionEnd(f.src, start);
      if (end > start) out.push({ start, end });
    }
    return out;
  }

  private check(
    f: SinkFile,
    an: SinkAnalyzer,
    arg: Range,
    at: number,
    call: SinkCall | undefined,
  ): Finding | undefined {
    const t = an.argTaint(arg, at);
    if (t === undefined) return undefined;
    const position = an.position(t.state, arg, at);
    if (position !== "whole" && position !== "url-origin") return undefined;
    const whole = position === "whole";
    const callLine = call === undefined ? f.src.lineAt(at) : call.line;
    return makeFinding({
      category: "injection",
      ruleId: "injection/open-redirect",
      title: "Redirect Target Taken From Request Data",
      severity: whole ? "high" : "medium",
      confidence: t.confidence,
      file: f.file,
      line: callLine,
      evidence: f.src.lineText(callLine).trim(),
      discriminator: `${at}`,
      plainEnglishProblem: whole
        ? `The redirect target comes from the ${t.hit.source.label} and can be any URL, so a link to your site can bounce users to an attacker's page.`
        : `The redirect target is your origin followed by a value from the ${t.hit.source.label} with no leading \`/\` enforced, so a value like \`@evil.com\` or \`.evil.com\` sends users to another host.`,
      whyItMatters:
        "Open redirects make phishing links look trustworthy (they start with your domain), and after login they can leak auth codes or tokens to the attacker's site.",
      fixSteps: [
        "Only accept relative paths: require the value to start with `/` but not `//` or `/\\`, otherwise use a default such as `/dashboard`.",
        "Build the target with `new URL(value, request.url)` and redirect only if `target.origin` equals your own origin.",
        'For external destinations, compare the parsed hostname with a fixed allowlist. Never treat `startsWith("http")` as a safety check.',
      ],
      aiFixPrompt: AI_PROMPT,
      learnMoreUrl:
        "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
    });
  }
}
