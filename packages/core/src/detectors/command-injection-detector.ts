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
  splitTopLevel,
  type ArgTaint,
  type Range,
  type SinkCall,
  type SinkFile,
} from "./utils/sinks.js";
import { capSeverityForTrust } from "./utils/taint.js";

const SHELL_PROGRAM_RE =
  /^(?:\/(?:usr\/)?bin\/)?(?:sh|bash|zsh|dash|cmd|cmd\.exe|powershell|pwsh)$/i;

const AI_PROMPT =
  'This code runs a shell command built from untrusted input (request data or command-line arguments) with child_process.exec/execSync (or spawn with `shell: true`), so shell metacharacters such as `;`, `|`, `$(...)` or a stray quote run extra commands. Replace it with `execFile`/`spawn` and an argument array, with `shell` left off, for example `execFile("curl", ["-fsSL", url, "-o", dest])`, so the input is passed as a single argument and never parsed by a shell. If the input selects an operation, map it through a fixed allowlist. If a value must start with something (a URL scheme, a file extension), validate it before the call, and pass `--` before positional arguments so the input cannot be read as an option. Keep the command\'s behaviour otherwise unchanged.';

/**
 * Shell commands built from untrusted input (`injection/command-exec-interpolation`):
 * `child_process.exec`/`execSync` (aliases, `promisify(exec)` and namespace imports
 * included) or `shelljs.exec` with tainted text, and `spawn`/`execFile`/`execa` when the
 * program itself is tainted, `shell: true` is set, or the program is a shell run with
 * `-c`. Array arguments without a shell are safe; zx templates are not calls.
 * Critical in request handlers, high for command-line arguments in scripts.
 */
export class CommandInjectionDetector implements Detector {
  id = "command-injection-detector";
  name = "Command Injection";
  category = "injection" as const;
  description =
    "Detects shell commands (child_process.exec, spawn with shell: true) built from request data or command-line arguments.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const patterns = sinkPatternsOf("command");
    for (const file of context.files) {
      const f = await loadSinkFile(context, file, SINK_NEEDLES.command);
      if (f === undefined) continue;
      const calls = findSinkCalls(f.src, patterns, f.aliases);
      if (calls.length === 0) continue;
      const an = new SinkAnalyzer(f, "command");
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
    const [program, list] = call.args;
    if (program === undefined) return undefined;
    if (call.pattern.argvStyle !== true) return an.argTaint(program, call.start);
    // spawn/execFile/execa: the program itself, or the argument list when a shell parses it
    const prog = an.argTaint(program, call.start);
    if (prog !== undefined) return prog;
    if (list === undefined || !this.shellParses(f, call, program, list)) return undefined;
    return an.argTaint(list, call.start);
  }

  /** `shell: true` in an options object, or a shell program run with `-c`/`/c`. */
  private shellParses(f: SinkFile, call: SinkCall, program: Range, list: Range): boolean {
    const code = f.src.code;
    for (const a of call.args.slice(1)) {
      if (
        code[a.start] === "{" &&
        /\bshell\s*:\s*(?!false\b|undefined\b|null\b)/.test(code.slice(a.start, a.end))
      )
        return true;
    }
    const prog = f.src.text.slice(program.start, program.end);
    const literal = /^(["'`])([^"'`]*)\1$/.exec(prog);
    if (literal === null || !SHELL_PROGRAM_RE.test(literal[2]!)) return false;
    if (code[list.start] !== "[") return false;
    const close = f.src.matchOf(list.start);
    if (close < 0) return false;
    const first = splitTopLevel(f.src, { start: list.start + 1, end: close }, ",")[0];
    if (first === undefined) return false;
    return /^["'`](?:-c|\/c|-Command)["'`]$/i.test(f.src.text.slice(first.start, first.end));
  }

  private finding(f: SinkFile, call: SinkCall, t: ArgTaint): Finding {
    const anchor = sinkAnchor(f.src, call, t.hit.offset);
    const severity = capSeverityForTrust(
      t.confidence === "high" && t.hit.trust === "remote" ? "critical" : "high",
      t.hit.trust,
    );
    const fromArgv = t.hit.trust === "local";
    return makeFinding({
      category: "injection",
      ruleId: "injection/command-exec-interpolation",
      title: fromArgv
        ? "Shell Command Built From Command-Line Arguments"
        : "Shell Command Built From Request Data",
      severity,
      confidence: t.confidence,
      file: f.file,
      line: anchor.line,
      endLine: anchor.endLine,
      evidence: anchor.evidence,
      discriminator: callKey(f.src, call.start, call.callee),
      plainEnglishProblem: `Data from the ${t.hit.source.label} is pasted into a command that a shell parses. Quotes do not help: \`$(...)\`, backticks or a closing quote inside the value run extra commands on the machine.`,
      whyItMatters: fromArgv
        ? "Whoever controls the argument (a CI job, a cron entry, a teammate pasting a URL or file name) gets arbitrary command execution with this script's permissions and environment secrets."
        : "Anyone who can send this request can run arbitrary commands on your server: read environment secrets, dump the database, or install malware.",
      fixSteps: [
        'Use `execFile`/`spawn` with an argument array and no `shell: true`, e.g. `execFile("curl", ["-fsSL", url, "-o", dest])`, so the value is one argument and never parsed by a shell.',
        "Validate the value against what you expect (an allowlist of operations, a URL scheme, a file name pattern) before running the command, and pass `--` before positional arguments.",
        "Avoid shelling out entirely where a Node API exists (fetch instead of curl, fs instead of cp/mv).",
      ],
      aiFixPrompt: AI_PROMPT,
      learnMoreUrl: "https://owasp.org/www-community/attacks/Command_Injection",
    });
  }
}
