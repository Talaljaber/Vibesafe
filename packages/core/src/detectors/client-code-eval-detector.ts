import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import {
  callArgs,
  capPerFile,
  clientTaint,
  isSelfUrlTaint,
  findDeclaration,
  inServerOnlyFunction,
  leadingOperands,
  lineOf,
  loadClientFile,
  namesFromHooks,
  outermostSpan,
  parseImports,
  resolveImport,
  type ArgRange,
  type ClientFile,
} from "./utils/client-source.js";
import { makeFinding } from "./utils/finding.js";
import { expressionEnd, extractFunctions } from "./utils/js-functions.js";
import { getJsSource, type JsSource } from "./utils/js-source.js";
import { analyzeTaint, taintConfidence, type TaintHit } from "./utils/taint.js";

/**
 * Client-runtime code execution and navigation fed by the page URL:
 * - `injection/client-dynamic-code`: `eval`, `new Function`, `Function(...)` and string
 *   `setTimeout`/`setInterval` on URL-derived data (DOM XSS).
 * - `injection/client-open-redirect`: `router.push|replace`, `navigate(...)`,
 *   `location(.href) =`, `location.assign|replace(...)` and `window.open(...)` fed by a
 *   `next`/`redirect`/`returnTo`/`callbackUrl`/`url`-style parameter without a relative-path
 *   check.
 *
 * Runs only on client-runtime files (server-side sinks belong to the injection group).
 * `postMessage` data is left to the postmessage detector, which reports the listener.
 */

const MAX_PER_RULE_PER_FILE = 25;

const EVAL_RE =
  /(?<![\w$.])eval\s*\(|\b(?:window|globalThis|self)\s*\.\s*eval\s*\(|\bnew\s+Function\s*\(|(?<![\w$.])Function\s*\(|(?<![\w$.])(?:(?:window|globalThis|self)\s*\.\s*)?set(?:Timeout|Interval)\s*\(/g;
const EVAL_PREFILTER = /\beval\b|\bFunction\s*\(|\bset(?:Timeout|Interval)\b/;

const LOCATION_ASSIGN_RE =
  /(?<![\w$.])(?:(?:window|document|globalThis|self|top)\s*\.\s*)?location(?:\s*\.\s*href)?\s*=(?![=>])/g;
const LOCATION_CALL_RE =
  /(?<![\w$.])(?:(?:window|document|globalThis|self|top)\s*\.\s*)?location\s*\.\s*(?:assign|replace)\s*\(|\bwindow\s*\.\s*open\s*\(/g;
const ROUTER_CALL_RE = /(?<![\w$.])([A-Za-z_$][\w$]*)\s*\.\s*(?:push|replace)\s*\(/g;
const NAVIGATE_CALL_RE = /(?<![\w$.])([A-Za-z_$][\w$]*)\s*\(/g;
const REDIRECT_PREFILTER =
  /\blocation\b|\bwindow\s*\.\s*open\b|\.\s*(?:push|replace)\s*\(|\bnavigate\b/;

/** Binding or parameter names that carry a post-login / return destination. */
const REDIRECT_NAME_RE =
  /^(?:next|nexturl|nextpath|redirect|redirectto|redirecturl|redirecturi|redirectpath|returnto|returnurl|returnpath|callbackurl|callback|continue|continueurl|url|dest|destination|goto|target|targeturl)$/;
/** The same names as a query key literal or member (`get("next")`, `query.returnTo`). */
const REDIRECT_KEY_RE =
  /["'`][?&]?(?:next|redirect[\w-]*|return[\w-]*|callback[\w-]*|continue|url|dest\w*|goto|target)=|["'`](?:next|redirect(?:[_-]?(?:to|url|uri|path))?|return[_-]?(?:to|url|path)|callback[_-]?url|callback|continue|url|dest(?:ination)?|goto|target)["'`]|\.\s*(?:next|redirect(?:To|Url|Uri|_to|_url)?|return(?:To|Url|_to|_url)|callback(?:Url|_url)?|continue|url|dest(?:ination)?|goto)\b/i;

/** A helper that vets a destination (`isSafeRedirect(x)`, `getSafeUrl(x)`, `sanitizeNext(x)`). */
const SAFE_HELPER_NAME = String.raw`(?<![\w$])(?:is|ensure|get|to|make|validate|sanitize|safe|check)\w*(?:Url|Path|Redirect|Href|Link|Next|Destination|Return\w*)`;
const SAFE_HELPER_RE = new RegExp(String.raw`${SAFE_HELPER_NAME}\s*\(`, "i");
/** Files that read the page URL (the taint sources these rules need). */
const URL_SOURCE_HINT =
  /\buse(?:SearchParams|Params)\b|\blocation\s*\.|\brouter\s*\.\s*(?:query|asPath)\b|\bdocument\s*\.\s*(?:URL|documentURI|baseURI|referrer)\b|\bwindow\s*\.\s*name\b/;

function normName(name: string): string {
  return name.toLowerCase().replace(/[_-]/g, "");
}

export class ClientCodeEvalDetector implements Detector {
  id = "client-code-eval-detector";
  name = "Client-Side Code Execution and Redirects";
  category = "injection" as const;
  description =
    "Detects browser code that evaluates URL-derived strings (eval, new Function, string timers) or navigates to a redirect parameter without checking it is a relative path.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of context.files) {
      try {
        const cf = await loadClientFile(context, file, {
          prefilter: (t) => URL_SOURCE_HINT.test(t),
        });
        if (cf === undefined) continue;
        const evals = [...this.dynamicCode(cf), ...(await this.importedEval(context, cf))];
        findings.push(
          ...capPerFile(dedupeByLine(evals), MAX_PER_RULE_PER_FILE, (n, f) => summary(f, n)),
        );
        findings.push(
          ...capPerFile(dedupeByLine(this.openRedirects(cf)), MAX_PER_RULE_PER_FILE, (n, f) =>
            summary(f, n),
          ),
        );
      } catch {
        // never throw from a detector
      }
    }
    return findings;
  }

  // ---- injection/client-dynamic-code ----

  private dynamicCode(cf: ClientFile): Finding[] {
    const { src } = cf;
    if (!EVAL_PREFILTER.test(src.code)) return [];
    const out: Finding[] = [];
    EVAL_RE.lastIndex = 0;
    for (let m = EVAL_RE.exec(src.code); m !== null; m = EVAL_RE.exec(src.code)) {
      const open = m.index + m[0].length - 1;
      if (inServerOnlyFunction(cf, m.index)) continue;
      const args = callArgs(src, open);
      if (args.length === 0) continue;
      const timer = /set(?:Timeout|Interval)/.test(m[0]);
      // A function passed to a timer is code, not a string: only string arguments execute.
      if (timer && cf.spans.some((s) => s.start === args[0]!.start)) continue;
      const ranges = timer ? [args[0]!] : args;
      const hit = strongest(cf, ranges);
      if (hit === undefined) continue;
      const sink = timer ? "a string timer" : /Function/.test(m[0]) ? "new Function" : "eval";
      out.push(this.dynamicCodeFinding(cf, m.index, hit, sink));
    }
    return out;
  }

  private dynamicCodeFinding(cf: ClientFile, at: number, hit: TaintHit, sink: string): Finding {
    const { line, text } = lineOf(cf.src, at);
    return makeFinding({
      category: "injection",
      ruleId: "injection/client-dynamic-code",
      title: "URL data executed as code in the browser",
      severity: "high",
      confidence: taintConfidence(hit),
      file: cf.file,
      line,
      evidence: text,
      plainEnglishProblem: `This browser code passes ${hit.source.label} to ${sink}, which runs it as JavaScript. A crafted link can make the page run any script in the visitor's session.`,
      whyItMatters:
        "This is DOM-based cross-site scripting: whoever writes the link controls code that runs with the user's cookies, tokens and permissions, and can read or change anything the user can.",
      fixSteps: [
        "Stop evaluating strings: parse structured data with JSON.parse and read the fields you expect.",
        "Pass functions, not strings, to setTimeout and setInterval.",
        "Validate the parsed value against an allowlist or schema before using it.",
      ],
      aiFixPrompt:
        "In this browser code, a value from the page URL (query string, hash or route params) reaches eval, new Function or a string setTimeout/setInterval. Remove the dynamic code execution: parse the value with JSON.parse (inside try/catch) or split it into the expected fields, validate the result against an allowlist or schema, and pass functions instead of strings to timers. Do not change unrelated behavior.",
    });
  }

  /**
   * Calls to an imported project function whose parameter reaches `eval`/`new Function`
   * in its own module, with URL data as that argument. Cross-file inference: low confidence.
   */
  private async importedEval(context: ScanContext, cf: ClientFile): Promise<Finding[]> {
    const { src } = cf;
    const out: Finding[] = [];
    const imports = parseImports(src).filter((i) => /^(?:\.\.?\/|@\/)/.test(i.spec));
    let resolved = 0;
    for (const imp of imports) {
      for (const [local, imported] of imp.names) {
        if (imported === "*") continue;
        const re = new RegExp(String.raw`(?<![\w$.])${local.replace(/\$/g, "\\$")}\s*\(`, "g");
        const calls: { open: number; args: ArgRange[] }[] = [];
        for (let m = re.exec(src.code); m !== null; m = re.exec(src.code)) {
          const open = m.index + m[0].length - 1;
          calls.push({ open, args: callArgs(src, open) });
        }
        if (calls.length === 0 || resolved >= 10) continue;
        resolved++;
        const target = await resolveImport(context, cf.file, imp.spec);
        if (target === undefined) continue;
        const targetSrc = await getJsSource(context, target);
        if (!EVAL_PREFILTER.test(targetSrc.code)) continue;
        const evalParams = evalReachingParams(targetSrc, imported);
        if (evalParams.size === 0) continue;
        for (const call of calls) {
          if (inServerOnlyFunction(cf, call.open)) continue;
          for (const idx of evalParams) {
            const arg = call.args[idx];
            if (arg === undefined) continue;
            const hit = clientTaint(cf, arg.start, arg.end);
            if (hit === undefined || hit.source.id === "message-data") continue;
            const { line, text } = lineOf(src, call.open);
            out.push(
              makeFinding({
                category: "injection",
                ruleId: "injection/client-dynamic-code",
                title: "URL data passed to an imported function that evaluates it",
                severity: "medium",
                confidence: "low",
                file: cf.file,
                line,
                evidence: text,
                plainEnglishProblem: `This browser code passes ${hit.source.label} to ${local}() from ${target}, which hands that argument to eval or new Function.`,
                whyItMatters:
                  "If the argument reaches the evaluation unchanged, a crafted link runs arbitrary JavaScript in the visitor's session (DOM-based cross-site scripting).",
                fixSteps: [
                  "Change the imported helper to parse its input (JSON.parse or explicit field parsing) instead of evaluating it.",
                  "Validate URL-derived values against an allowlist or schema before passing them on.",
                ],
                aiFixPrompt:
                  "A browser component passes a value from the page URL to a project helper that evaluates its argument with eval or new Function. Rewrite the helper to parse the input safely (JSON.parse inside try/catch, or explicit parsing of the expected fields) and validate the result against an allowlist or schema. Keep the helper's return type and callers working.",
              }),
            );
            break;
          }
        }
      }
    }
    return out;
  }

  // ---- injection/client-open-redirect ----

  private openRedirects(cf: ClientFile): Finding[] {
    const { src } = cf;
    const code = src.code;
    if (!REDIRECT_PREFILTER.test(code)) return [];
    const out: Finding[] = [];
    const sinks: { at: number; ranges: ArgRange[]; label: string }[] = [];

    LOCATION_ASSIGN_RE.lastIndex = 0;
    for (let m = LOCATION_ASSIGN_RE.exec(code); m !== null; m = LOCATION_ASSIGN_RE.exec(code)) {
      if (/\b(?:const|let|var)\s+$/.test(code.slice(Math.max(0, m.index - 8), m.index))) continue;
      const start = m.index + m[0].length;
      let first = start;
      while (first < code.length && /[ \t]/.test(code[first]!)) first++;
      const end = expressionEnd(src, first);
      sinks.push({ at: m.index, ranges: [{ start, end }], label: "window.location" });
    }
    LOCATION_CALL_RE.lastIndex = 0;
    for (let m = LOCATION_CALL_RE.exec(code); m !== null; m = LOCATION_CALL_RE.exec(code)) {
      const first = callArgs(src, m.index + m[0].length - 1)[0];
      if (first !== undefined)
        sinks.push({
          at: m.index,
          ranges: [first],
          label: /open/.test(m[0]) ? "window.open" : "location.assign/replace",
        });
    }
    const routers = namesFromHooks(src, /^(?:useRouter|useHistory)$/);
    routers.add("router");
    ROUTER_CALL_RE.lastIndex = 0;
    for (let m = ROUTER_CALL_RE.exec(code); m !== null; m = ROUTER_CALL_RE.exec(code)) {
      if (!routers.has(m[1]!)) continue;
      const first = callArgs(src, m.index + m[0].length - 1)[0];
      if (first !== undefined) sinks.push({ at: m.index, ranges: [first], label: "the router" });
    }
    const navigators = namesFromHooks(src, /^useNavigate$/);
    if (navigators.size > 0) {
      NAVIGATE_CALL_RE.lastIndex = 0;
      for (let m = NAVIGATE_CALL_RE.exec(code); m !== null; m = NAVIGATE_CALL_RE.exec(code)) {
        if (!navigators.has(m[1]!)) continue;
        const first = callArgs(src, m.index + m[0].length - 1)[0];
        if (first !== undefined) sinks.push({ at: m.index, ranges: [first], label: "navigate()" });
      }
    }

    for (const sink of sinks) {
      if (inServerOnlyFunction(cf, sink.at)) continue;
      for (const range of sink.ranges) {
        let reported = false;
        for (const lead of leadingOperands(src, range.start, range.end)) {
          const hit = clientTaint(cf, lead.start, lead.end);
          if (hit === undefined || hit.source.id === "message-data") continue;
          if (isSelfUrlTaint(src, lead, hit.via)) continue;
          if (!this.isRedirectParam(cf, hit, lead)) continue;
          if (this.hasRelativeCheck(cf, hit, lead, sink.at)) continue;
          out.push(this.openRedirectFinding(cf, sink.at, hit, sink.label));
          reported = true;
          break;
        }
        if (reported) break;
      }
    }
    return out;
  }

  private isRedirectParam(cf: ClientFile, hit: TaintHit, lead: ArgRange): boolean {
    const { src } = cf;
    if (hit.via !== undefined && REDIRECT_NAME_RE.test(normName(hit.via))) return true;
    if (REDIRECT_KEY_RE.test(src.text.slice(lead.start, lead.end))) return true;
    if (hit.via !== undefined) {
      const decl = findDeclaration(src, hit.via, lead.start);
      if (decl !== undefined && REDIRECT_KEY_RE.test(src.text.slice(decl.initStart, decl.initEnd)))
        return true;
    }
    return false;
  }

  /** `startsWith("/") && !startsWith("//")`, `new URL(x, origin)` checks or a safe-redirect helper. */
  private hasRelativeCheck(cf: ClientFile, hit: TaintHit, lead: ArgRange, sinkAt: number): boolean {
    const { src } = cf;
    const leadCode = src.code.slice(lead.start, lead.end);
    if (SAFE_HELPER_RE.test(leadCode)) return true;
    const name = hit.via;
    if (name === undefined) return false;
    const outer = outermostSpan(cf, sinkAt);
    const state = analyzeTaint(src, outer, {
      runtime: cf.classification.runtime === "client" ? "client" : "server",
    });
    if (state.guardBefore(name, sinkAt) !== undefined) return true;
    const esc = name.replace(/\$/g, "\\$");
    const body = src.code.slice(outer.start, outer.end);
    const n = String.raw`(?<![\w$.])${esc}(?![\w$])`;
    return (
      new RegExp(String.raw`${n}\s*\??\.\s*startsWith\s*\(`).test(body) ||
      new RegExp(String.raw`\.\s*test\s*\(\s*${n}`).test(body) ||
      new RegExp(String.raw`\bnew\s+URL\s*\(\s*${n}`).test(body) ||
      new RegExp(String.raw`${SAFE_HELPER_NAME}\s*\(\s*${n}`, "i").test(body)
    );
  }

  private openRedirectFinding(cf: ClientFile, at: number, hit: TaintHit, label: string): Finding {
    const { line, text } = lineOf(cf.src, at);
    return makeFinding({
      category: "injection",
      ruleId: "injection/client-open-redirect",
      title: "Redirect parameter used for navigation without a relative-path check",
      severity: "medium",
      confidence: taintConfidence(hit),
      file: cf.file,
      line,
      evidence: text,
      plainEnglishProblem: `This browser code sends the user to a destination taken from ${hit.source.label} via ${label}, without checking that it is a path on this site.`,
      whyItMatters:
        "A link like ?next=https://evil.example sends users to a phishing page right after a real login, and ?next=javascript:... runs script in your origin when assigned to location.",
      fixSteps: [
        'Only follow relative paths: accept the value when it starts with "/" and not with "//" or "/\\", otherwise use a default page.',
        "Or resolve it with new URL(value, window.location.origin) and require the resulting origin to equal window.location.origin.",
        "Never navigate to a value with a scheme such as javascript: or data:.",
      ],
      aiFixPrompt:
        'This browser code navigates (router.push/replace, location.href/assign/replace or window.open) to a destination read from the URL, such as ?next= or ?returnTo=. Add a helper that returns the value only when it is a same-site relative path (starts with "/" and not "//" or "/\\", no scheme), otherwise a safe default like "/", and use it before navigating. Keep existing behavior for valid relative paths.',
    });
  }
}

/** Strongest taint over several ranges, ignoring postMessage data (owned by the postmessage rule). */
function strongest(cf: ClientFile, ranges: ArgRange[]): TaintHit | undefined {
  let best: TaintHit | undefined;
  for (const r of ranges) {
    const hit = clientTaint(cf, r.start, r.end);
    if (hit === undefined || hit.source.id === "message-data") continue;
    if (best === undefined || rank(hit) < rank(best)) best = hit;
  }
  return best;
}

function rank(h: TaintHit): number {
  return h.path === "direct" ? 0 : h.path === "binding" ? 1 : 2;
}

/** Parameter indexes of the exported function `name` (or default) that reach eval/new Function. */
function evalReachingParams(src: JsSource, name: string): Set<number> {
  const out = new Set<number>();
  const spans = extractFunctions(src);
  const fn = spans.find(
    (s) => s.exported && (s.exportNames.includes(name) || (name !== "default" && s.name === name)),
  );
  if (fn === undefined) return out;
  const re =
    /(?<![\w$.])eval\s*\(|\bnew\s+Function\s*\(|(?<![\w$.])Function\s*\(|\b(?:window|globalThis|self)\s*\.\s*eval\s*\(/g;
  re.lastIndex = fn.bodyStart;
  for (let m = re.exec(src.code); m !== null && m.index < fn.bodyEnd; m = re.exec(src.code)) {
    const args = callArgs(src, m.index + m[0].length - 1);
    for (let idx = 0; idx < Math.min(fn.params.length, 4); idx++) {
      const state = analyzeTaint(src, fn, { runtime: "client", seedParams: [idx] });
      if (args.some((a) => state.exprTaint(a.start, a.end) !== undefined)) out.add(idx);
    }
  }
  return out;
}

function dedupeByLine(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const k = `${f.ruleId}:${f.line ?? ""}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

function summary(first: Finding, dropped: number): Finding {
  return makeFinding({
    category: "injection",
    ruleId: first.ruleId,
    title: `${dropped} more occurrence(s) of this issue in the file`,
    severity: first.severity,
    confidence: "medium",
    file: first.file,
    discriminator: `summary:${dropped}`,
    plainEnglishProblem: `${first.plainEnglishProblem} The same pattern appears ${dropped} more time(s) in this file; only the first occurrences are listed.`,
    whyItMatters: first.whyItMatters,
    fixSteps: first.fixSteps,
    aiFixPrompt: first.aiFixPrompt ?? "",
  });
}
