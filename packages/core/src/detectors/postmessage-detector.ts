import type {
  Confidence,
  Detector,
  Finding,
  ScanContext,
  Severity,
} from "@talaljaber/vibesafe-shared";
import {
  callArgs,
  capPerFile,
  inServerOnlyFunction,
  lineOf,
  literalText,
  loadClientFile,
  memberChain,
  type ClientFile,
} from "./utils/client-source.js";
import { makeFinding } from "./utils/finding.js";
import type { FunctionSpan } from "./utils/js-functions.js";

/**
 * `xss/postmessage-no-origin-check`: a window `message` listener that uses `event.data`
 * without checking `event.origin` (or `event.source`). Any page that frames or opens
 * this one can post messages to it.
 *
 * Handlers are inline functions or resolved by name within the file
 * (`function onMessage(e)`, `const onMessage = (e) => ...`, `useCallback(...)`).
 * Severity `high` when the handler navigates, evaluates code or writes HTML; `medium`
 * when it otherwise acts on the data. Listeners on workers, ports, sockets and other
 * non-window targets are skipped.
 */

const MAX_PER_FILE = 25;
const LISTENER_RE =
  /(?<![\w$])(?:(window|globalThis|self|top|[A-Za-z_$][\w$]*)\s*\.\s*)?addEventListener\s*\(/g;
const ONMESSAGE_RE = /(?<![\w$.])(?:(window|globalThis)\s*\.\s*)?onmessage\s*=(?![=>])/g;
const PREFILTER = /addEventListener|onmessage/;

const NAVIGATES_RE =
  /\blocation(?:\s*\.\s*href)?\s*=(?![=>])|\blocation\s*\.\s*(?:assign|replace)\s*\(|\bwindow\s*\.\s*open\s*\(|\b(?:router|navigate|history)\b\s*(?:\.\s*(?:push|replace)\s*)?\(/;
const EVALS_RE = /(?<![\w$.])eval\s*\(|\bnew\s+Function\s*\(|(?<![\w$.])Function\s*\(/;
const WRITES_HTML_RE =
  /\.\s*(?:innerHTML|outerHTML)\s*\+?=(?!=)|\binsertAdjacentHTML\s*\(|\bdocument\s*\.\s*write(?:ln)?\s*\(|\bdangerouslySetInnerHTML\b|\bcreateContextualFragment\s*\(/;

export class PostMessageDetector implements Detector {
  id = "postmessage-detector";
  name = "postMessage Listener Origin Check";
  category = "xss" as const;
  description =
    "Detects window message listeners that act on event.data without checking event.origin.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of context.files) {
      try {
        const cf = await loadClientFile(context, file, { prefilter: (t) => PREFILTER.test(t) });
        if (cf === undefined) continue;
        findings.push(...capPerFile(this.scan(cf), MAX_PER_FILE, (n, f) => summary(f, n)));
      } catch {
        // never throw from a detector
      }
    }
    return findings;
  }

  private scan(cf: ClientFile): Finding[] {
    const { src } = cf;
    const code = src.code;
    const out: Finding[] = [];
    const seen = new Set<number>();
    const consider = (at: number, handler: FunctionSpan | undefined): void => {
      if (handler === undefined || inServerOnlyFunction(cf, at)) return;
      const line = src.lineAt(at);
      if (seen.has(line)) return;
      const verdict = judgeHandler(cf, handler);
      if (verdict === undefined) return;
      seen.add(line);
      out.push(this.finding(cf, at, verdict));
    };

    LISTENER_RE.lastIndex = 0;
    for (let m = LISTENER_RE.exec(code); m !== null; m = LISTENER_RE.exec(code)) {
      const target = m[1];
      if (target !== undefined && target !== "window" && target !== "globalThis") continue;
      const args = callArgs(src, m.index + m[0].length - 1);
      if (args.length < 2) continue;
      if (literalText(src, args[0]!.start)?.trim() !== "message") continue;
      consider(m.index, resolveHandler(cf, args[1]!.start, args[1]!.end));
    }
    ONMESSAGE_RE.lastIndex = 0;
    for (let m = ONMESSAGE_RE.exec(code); m !== null; m = ONMESSAGE_RE.exec(code)) {
      let s = m.index + m[0].length;
      while (s < code.length && /\s/.test(code[s]!)) s++;
      let e = s;
      while (e < code.length && /[\w$.]/.test(code[e]!)) e++;
      consider(m.index, resolveHandler(cf, s, e));
    }
    return out;
  }

  private finding(
    cf: ClientFile,
    at: number,
    verdict: { severity: Severity; confidence: Confidence; action: string | undefined },
  ): Finding {
    const { line, text } = lineOf(cf.src, at);
    const action =
      verdict.action === undefined
        ? "acts on the message data"
        : `uses the message data and ${verdict.action}`;
    return makeFinding({
      category: "xss",
      ruleId: "xss/postmessage-no-origin-check",
      title: "postMessage listener does not check the sender's origin",
      severity: verdict.severity,
      confidence: verdict.confidence,
      file: cf.file,
      line,
      evidence: text,
      plainEnglishProblem: `This window "message" listener ${action}, but never checks event.origin. Any website that frames or opens this page can send it messages.`,
      whyItMatters:
        "An attacker page can drive the handler with its own data: navigate the user to a javascript: or phishing URL, inject HTML, or trigger actions (add to cart, change settings) in the victim's session.",
      fixSteps: [
        "At the top of the handler, return unless event.origin is in an explicit allowlist of trusted origins.",
        "Validate the shape of event.data (type and fields) before acting on it.",
        "Never navigate to, evaluate or render HTML from message data without checking it (for URLs, allow only http(s) or same-site paths).",
      ],
      aiFixPrompt:
        "This browser code registers a window 'message' event listener that uses event.data without verifying the sender. Add an allowlist of trusted origins and make the handler return immediately when event.origin is not in it (compare exact origins, not substrings). Then validate event.data's shape before use, and if the handler navigates, only allow http(s) URLs or same-site relative paths. Keep the existing message handling for trusted senders.",
    });
  }
}

/** The handler function for the listener argument in `[start, end)`. */
function resolveHandler(cf: ClientFile, start: number, end: number): FunctionSpan | undefined {
  const inline = cf.spans.find((s) => s.start === start);
  if (inline !== undefined) return inline;
  const chain = memberChain(cf.src.code, start, end);
  if (chain === undefined || chain.length !== 1) return undefined;
  const name = chain[0]!;
  const named = cf.spans.filter((s) => s.name === name);
  if (named.length > 0) {
    // Prefer the declaration nearest before the registration (same component).
    const before = named.filter((s) => s.start < start);
    return before[before.length - 1] ?? named[0];
  }
  // `const onMessage = useCallback((e) => {...}, [])`: the span bound inside the wrapper.
  const decl = new RegExp(
    String.raw`\b(?:const|let|var)\s+${name.replace(/\$/g, "\\$")}\s*=\s*(?:React\s*\.\s*)?use(?:Callback|EffectEvent)\s*\(\s*`,
  ).exec(cf.src.code);
  if (decl === null) return undefined;
  const at = decl.index + decl[0].length;
  return cf.spans.find((s) => s.start === at);
}

/** Verdict for a handler, or undefined when it checks the origin or ignores the data. */
function judgeHandler(
  cf: ClientFile,
  fn: FunctionSpan,
): { severity: Severity; confidence: Confidence; action: string | undefined } | undefined {
  const body = cf.src.code.slice(fn.bodyStart, fn.bodyEnd);
  const params = cf.src.code.slice(fn.paramsStart, fn.paramsEnd);
  if (/origin/i.test(body) || /origin/i.test(params)) return undefined;
  if (/\.\s*source\s*[!=]==?|[!=]==?\s*[\w$.]*\.\s*source\b/.test(body)) return undefined;
  const p0 = fn.params[0];
  if (p0 === undefined) return undefined;
  let usesData: boolean;
  if (p0.names.length === 1 && p0.pattern === p0.names[0]) {
    const esc = p0.names[0]!.replace(/\$/g, "\\$");
    usesData = new RegExp(String.raw`(?<![\w$.])${esc}\s*\??\.\s*data\b`).test(body);
  } else {
    usesData = p0.names.includes("data");
  }
  if (!usesData) return undefined;
  const confidence: Confidence = fn.truncated ? "medium" : "high";
  if (NAVIGATES_RE.test(body))
    return { severity: "high", confidence, action: "navigates the page" };
  if (EVALS_RE.test(body)) return { severity: "high", confidence, action: "evaluates code" };
  if (WRITES_HTML_RE.test(body)) return { severity: "high", confidence, action: "writes HTML" };
  return { severity: "medium", confidence: "medium", action: undefined };
}

function summary(first: Finding, dropped: number): Finding {
  return makeFinding({
    category: "xss",
    ruleId: "xss/postmessage-no-origin-check",
    title: `${dropped} more message listener(s) without an origin check in this file`,
    severity: first.severity,
    confidence: "medium",
    file: first.file,
    discriminator: `summary:${dropped}`,
    plainEnglishProblem: `${first.plainEnglishProblem} The same pattern appears ${dropped} more time(s) in this file.`,
    whyItMatters: first.whyItMatters,
    fixSteps: first.fixSteps,
    aiFixPrompt: first.aiFixPrompt ?? "",
  });
}
