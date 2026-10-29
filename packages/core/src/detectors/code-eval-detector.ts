import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { SINK_NEEDLES, sinkPatternsOf } from "./patterns/sink-patterns.js";
import { makeFinding } from "./utils/finding.js";
import {
  SinkAnalyzer,
  capPerRule,
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
      const an = new SinkAnalyzer(f, "eval");
      const out: Finding[] = [];
      for (const call of calls) {
        try {
          const t = this.taintOf(f, an, call);
          if (t !== undefined) out.push(this.finding(f, call, t));
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

  /** A function passed as the argument (`setTimeout(() => ..., 10)`) is code, not a string. */
  private isFunctionValue(f: SinkFile, arg: Range): boolean {
    if (f.spans.some((s) => s.start === arg.start)) return true;
    return /^(?:async\s+)?function\b/.test(f.src.code.slice(arg.start, arg.start + 20));
  }

  private finding(f: SinkFile, call: SinkCall, t: ArgTaint): Finding {
    const anchor = sinkAnchor(f.src, call, t.hit.offset);
    const severity = capSeverityForTrust(
      t.confidence === "high" && t.hit.trust === "remote" ? "critical" : "high",
      t.hit.trust,
    );
    return makeFinding({
      category: "injection",
      ruleId: "injection/dynamic-code-eval",
      title: "Untrusted Input Evaluated as Code",
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
