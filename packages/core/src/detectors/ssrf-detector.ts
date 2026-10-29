import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { SINK_NEEDLES, sinkPatternsOf } from "./patterns/sink-patterns.js";
import { makeFinding } from "./utils/finding.js";
import {
  SinkAnalyzer,
  capPerRule,
  findSinkCalls,
  loadSinkFile,
  sinkAnchor,
  type SinkCall,
  type SinkFile,
} from "./utils/sinks.js";

const AI_PROMPT =
  'This server code makes an outbound HTTP request (fetch/axios/got/http.request) to a URL taken from request data, which is server-side request forgery (SSRF): attackers can make the server call internal services, localhost admin ports or the cloud metadata endpoint (169.254.169.254). Fix it by allowlisting destinations: parse the URL with `new URL()`, require `https:`, and reject it unless `url.hostname` is in a fixed set of allowed hosts. If arbitrary public URLs are a real requirement (link previews, webhooks), resolve the hostname with dns.lookup and reject private, loopback, link-local and metadata addresses, connect to the vetted IP, set `redirect: "manual"` (re-checking every redirect target), and apply a short timeout and response size limit. A regex that only checks for `http(s)://` is not a fix. Keep the feature working for allowed URLs.';

/**
 * Outbound requests to a URL controlled by request data (`injection/ssrf-user-controlled-url`):
 * `fetch`, `axios`, `got`, `ky`, `undici`, `superagent`, `http(s).get/request`. Reported
 * when the attacker chooses the whole URL or its host (`` `https://${host}/x` ``,
 * `` `${base}${path}` ``); a tainted path or query under a fixed origin is not. A scheme
 * check (`/^https?:\/\//.test(url)`) is never a guard; a hostname allowlist is.
 */
export class SsrfDetector implements Detector {
  id = "ssrf-detector";
  name = "Server-Side Request Forgery";
  category = "injection" as const;
  description =
    "Detects server code that fetches a URL taken from request data without restricting the destination host.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const patterns = sinkPatternsOf("ssrf");
    for (const file of context.files) {
      const f = await loadSinkFile(context, file, SINK_NEEDLES.ssrf);
      if (f === undefined) continue;
      const calls = findSinkCalls(f.src, patterns, f.aliases);
      if (calls.length === 0) continue;
      const an = new SinkAnalyzer(f, "ssrf");
      const out: Finding[] = [];
      for (const call of calls) {
        try {
          const finding = this.check(f, an, call);
          if (finding !== undefined) out.push(finding);
        } catch {
          // a detector never throws
        }
      }
      findings.push(...capPerRule(out));
    }
    return findings;
  }

  private check(f: SinkFile, an: SinkAnalyzer, call: SinkCall): Finding | undefined {
    const arg = call.args[0];
    if (arg === undefined || f.src.code[arg.start] === "{") return undefined;
    const t = an.argTaint(arg, call.start);
    if (t === undefined) return undefined;
    const position = an.position(t.state, arg, call.start);
    if (position !== "whole" && position !== "url-origin") return undefined;
    const anchor = sinkAnchor(f.src, call, t.hit.offset);
    const whole = position === "whole";
    return makeFinding({
      category: "injection",
      ruleId: "injection/ssrf-user-controlled-url",
      title: "Server Fetches a URL Chosen by the User",
      severity: "high",
      confidence: whole ? t.confidence : "medium",
      file: f.file,
      line: anchor.line,
      endLine: anchor.endLine,
      evidence: anchor.evidence,
      discriminator: `${call.start}`,
      plainEnglishProblem: whole
        ? `The server makes an HTTP request to a URL taken from the ${t.hit.source.label}, with no allowlist of destinations. An attacker can point it at internal services, localhost or the cloud metadata endpoint.`
        : `The server makes an HTTP request to a URL whose host part comes from the ${t.hit.source.label}, so an attacker can redirect the request to a host of their choice (for example with \`@evil.com\` or an internal hostname).`,
      whyItMatters:
        "Server-side request forgery reaches what only your server can reach: internal admin APIs, databases' HTTP ports and cloud metadata (169.254.169.254), which can hand out cloud credentials. Responses echoed back to the user leak that data directly.",
      fixSteps: [
        "Parse the URL with `new URL()` and only allow `https:` and a fixed set of hostnames (`ALLOWED_HOSTS.has(url.hostname)`).",
        'If arbitrary public URLs are required, resolve the host and block private, loopback, link-local and metadata IP ranges, disable automatic redirects (`redirect: "manual"`) and re-check each hop.',
        "Add a timeout and a response size limit, and avoid returning raw upstream responses to the caller.",
      ],
      aiFixPrompt: AI_PROMPT,
      learnMoreUrl: "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
    });
  }
}
