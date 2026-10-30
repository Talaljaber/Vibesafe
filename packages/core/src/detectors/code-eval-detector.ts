import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { SINK_NEEDLES, sinkPatternsOf } from "./patterns/sink-patterns.js";
import { PARAMETER_SOURCE } from "./patterns/taint-sources.js";
import { makeFinding } from "./utils/finding.js";
import { enclosingFunction } from "./utils/js-functions.js";
import {
  SinkAnalyzer,
  capPerRule,
  isQueueHit,
  queueSourcesOf,
  findSinkCalls,
  loadSinkFile,
  callKey,
  sinkAnchor,
  sinkArgs,
  type ArgTaint,
  type Range,
  type SinkCall,
  type SinkFile,
} from "./utils/sinks.js";
import { capSeverityForTrust } from "./utils/taint.js";

const AI_PROMPT =
  "This server code runs a string built from untrusted input as JavaScript (eval, new Function, the vm module, or a string passed to setTimeout/setInterval). That is remote code execution: the input can call `process.mainModule.require(\"child_process\")`, read environment secrets or touch every tenant's data. Remove the dynamic evaluation. If users choose between transformations, map their choice to fixed functions you write (an allowlist object of named functions); if they supply data, parse it with JSON.parse; if they supply expressions, use a small purpose-built parser or a sandboxed expression library that cannot reach Node globals (the vm module is not a security sandbox). Keep the feature's behaviour for legitimate input.";

const PARAM_AI_PROMPT =
  "This exported function builds JavaScript from one of its parameters and runs it (eval, new Function, or the vm module). Any caller that passes request data turns this into remote code execution, and vm is not a security sandbox. Remove the dynamic evaluation: map the parameter to a fixed set of functions in an allowlist object, parse data with JSON.parse, or use a purpose-built expression parser that cannot reach Node globals. Keep the function's signature and legitimate behaviour unchanged.";

/**
 * Untrusted input evaluated as code on the server (`injection/dynamic-code-eval`): `eval`,
 * `new Function(...)`/`Function(...)`, `vm.runIn*Context`/`new vm.Script`, and string
 * `setTimeout`/`setInterval`. Same-file seeding follows a tainted value into callbacks
 * (`Object.entries(input).map(([k, expr]) => new Function(expr))`) and into helper
 * functions called with it (depth ≤ 2, ≤ 50 analyses per file). Literal-only code,
 * `redis.eval` and `page.evaluate` are not this sink.
 */
export class CodeEvalDetector implements Detector {
  id = "code-eval-detector";
  name = "Dynamic Code Evaluation";
  category = "injection" as const;
  description =
    "Detects server code that evaluates request data or command-line arguments as JavaScript (eval, new Function, vm).";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const patterns = sinkPatternsOf("eval");
    for (const file of context.files) {
      const f = await loadSinkFile(context, file, SINK_NEEDLES.eval);
      if (f === undefined) continue;
      const calls = findSinkCalls(f.src, patterns, f.aliases);
      if (calls.length === 0) continue;
      const an = new SinkAnalyzer(f, "eval", { extraSources: queueSourcesOf(f) });
      const out: Finding[] = [];
      for (const call of calls) {
        try {
          const t = this.taintOf(f, an, call);
          if (t !== undefined) out.push(this.finding(f, call, t));
          else {
            const p = this.parameterFinding(f, an, call);
            if (p !== undefined) out.push(p);
          }
        } catch {
          // a detector never throws
        }
      }
      findings.push(...capPerRule(out));
    }
    return findings;
  }

  private taintOf(f: SinkFile, an: SinkAnalyzer, call: SinkCall): ArgTaint | undefined {
    for (const arg of sinkArgs(call)) {
      if (this.isFunctionValue(f, arg)) continue;
      const t = an.argTaint(arg, call.start);
      if (t !== undefined) return t;
    }
    return undefined;
  }

  /**
   * Code built from a parameter of an exported function (`injection/code-eval-from-parameter`).
   * Only reached when the call is not already reported as `injection/dynamic-code-eval`.
   */
  private parameterFinding(f: SinkFile, an: SinkAnalyzer, call: SinkCall): Finding | undefined {
    if (call.pattern.id === "string-timer") return undefined;
    let top = enclosingFunction(f.spans, call.start);
    while (top?.parent !== undefined) top = top.parent;
    if (top === undefined || !top.exported || top.role !== "other") return undefined;
    const indexes = top.params
      .map((p, i) => ({ p, i }))
      .filter(({ p }) => !/:\s*(?:number|boolean|bigint)\s*(?:=|$)/.test(p.text))
      .map(({ i }) => i);
    const state = an.seededState(top, indexes, PARAMETER_SOURCE);
    if (state === undefined) return undefined;
    for (const arg of sinkArgs(call)) {
      if (this.isFunctionValue(f, arg)) continue;
      const hit = an
        .hitsIn(state, arg, call.start, true)
        .find((e) => e.hit.source.id === PARAMETER_SOURCE.id);
      if (hit === undefined) continue;
      const anchor = sinkAnchor(f.src, call, hit.hit.offset);
      return makeFinding({
        category: "injection",
        ruleId: "injection/code-eval-from-parameter",
        title: "Exported Helper Evaluates Its Parameter as Code",
        severity: "high",
        confidence: "medium",
        file: f.file,
        line: anchor.line,
        endLine: anchor.endLine,
        evidence: anchor.evidence,
        discriminator: callKey(f.src, call.start, call.callee),
        plainEnglishProblem:
          "This exported function builds JavaScript from one of its parameters and runs it (eval, new Function or vm). Whether that is exploitable depends on the callers: as soon as one of them passes request data, whoever controls it can run any code on the server.",
        whyItMatters:
          "Helpers like this hide remote code execution from the routes that call them, and the vm module is not a security sandbox: code in a vm context can usually escape to the host process and its environment secrets.",
        fixSteps: [
          "Do not run strings as code. Map the parameter to a fixed set of functions you write (an allowlist object) or parse it as data with JSON.parse.",
          "If expressions are required, use a purpose-built expression parser with no access to Node globals instead of eval, new Function or vm.",
        ],
        aiFixPrompt: PARAM_AI_PROMPT,
        learnMoreUrl: "https://owasp.org/www-community/attacks/Code_Injection",
      });
    }
    return undefined;
  }

  /** A function passed as the argument (`setTimeout(() => ..., 10)`) is code, not a string. */
  private isFunctionValue(f: SinkFile, arg: Range): boolean {
    if (f.spans.some((s) => s.start === arg.start)) return true;
    return /^(?:async\s+)?function\b/.test(f.src.code.slice(arg.start, arg.start + 20));
  }

  private finding(f: SinkFile, call: SinkCall, t: ArgTaint): Finding {
    const anchor = sinkAnchor(f.src, call, t.hit.offset);
    const queue = isQueueHit(t);
    const severity = capSeverityForTrust(
      t.confidence === "high" && t.hit.trust === "remote" && !queue ? "critical" : "high",
      t.hit.trust,
    );
    return makeFinding({
      category: "injection",
      ruleId: "injection/dynamic-code-eval",
      title: queue ? "Dynamic Code Built From Queue Job Data" : "Untrusted Input Evaluated as Code",
      severity,
      confidence: t.confidence,
      file: f.file,
      line: anchor.line,
      endLine: anchor.endLine,
      evidence: anchor.evidence,
      discriminator: callKey(f.src, call.start, call.callee),
      plainEnglishProblem: `Data from the ${t.hit.source.label} is turned into JavaScript and executed on the server (eval, new Function or vm). Whoever controls that value can run any code they like.`,
      whyItMatters:
        "This is remote code execution: an attacker can read your environment secrets (database URL, service-role and payment keys), run shell commands through child_process, and reach every tenant's data.",
      fixSteps: [
        "Remove eval/new Function/vm on user input. Map user choices to fixed functions in an allowlist object instead.",
        "Parse data with JSON.parse, never with eval.",
        "If users must write expressions, use a purpose-built expression parser with no access to Node globals; the vm module is not a sandbox.",
      ],
      aiFixPrompt: AI_PROMPT,
      learnMoreUrl: "https://owasp.org/www-community/attacks/Code_Injection",
    });
  }
}
