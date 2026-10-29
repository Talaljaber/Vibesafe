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
  type SinkCall,
  type SinkFile,
} from "./utils/sinks.js";

const AI_PROMPT =
  "This server code reads or writes a file whose path is built from request data (fs.readFile/createReadStream/writeFile/unlink, res.sendFile, often through path.join), so `../` segments or an absolute path escape the intended folder (path traversal) and expose files such as `.env` or other tenants' uploads. Fix it by never using the raw input as a path: prefer looking the file up by an id in the database (scoped to the current user or organisation) and using the stored server-generated name. If a name from the request is unavoidable, reduce it with `path.basename()`, resolve it with `const target = path.resolve(root, name)`, and reject the request unless `target.startsWith(root + path.sep)`. Keep the endpoint's behaviour for valid files.";

/**
 * Filesystem access with a path built from request data (`injection/path-traversal`):
 * `fs`/`fs/promises`/`fs-extra` read, write, delete and copy calls and Express
 * `res.sendFile`/`res.download`, including paths built with `path.join`/`path.resolve`.
 * `path.basename(...)`, allowlist lookups, a `startsWith(root)`/`..` check before the
 * call, and `sendFile(name, { root })` are safe.
 */
export class PathTraversalDetector implements Detector {
  id = "path-traversal-detector";
  name = "Path Traversal";
  category = "injection" as const;
  description =
    "Detects server code that reads, writes or sends files using a path built from request data without confining it to a base folder.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const patterns = sinkPatternsOf("path");
    for (const file of context.files) {
      const f = await loadSinkFile(context, file, SINK_NEEDLES.path);
      if (f === undefined) continue;
      const calls = findSinkCalls(f.src, patterns, f.aliases);
      if (calls.length === 0) continue;
      const an = new SinkAnalyzer(f, "path");
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
    if (call.pattern.id === "send-file" && this.hasRootOption(f, call)) return undefined;
    for (const arg of sinkArgs(call)) {
      const t = an.argTaint(arg, call.start);
      if (t === undefined) continue;
      const anchor = sinkAnchor(f.src, call, t.hit.offset);
      return makeFinding({
        category: "injection",
        ruleId: "injection/path-traversal",
        title: "File Path Built From Request Data",
        severity: "high",
        confidence: t.confidence,
        file: f.file,
        line: anchor.line,
        endLine: anchor.endLine,
        evidence: anchor.evidence,
        discriminator: callKey(f.src, call.start, call.callee),
        plainEnglishProblem: `A file path is built from the ${t.hit.source.label} and used to access the filesystem. Values such as \`../../.env\` or \`../<other-tenant>/file\` step out of the folder you meant to serve.`,
        whyItMatters:
          "Path traversal lets anyone read (or overwrite) files the server can access: environment files with secrets, source code, or other customers' uploads.",
        fixSteps: [
          "Look files up by id in the database (scoped to the current user/organisation) and use the stored, server-generated file name.",
          "If you must accept a name, take `path.basename(name)`, resolve it with `path.resolve(root, name)` and reject it unless the result starts with `root + path.sep`.",
          "For Express, `res.sendFile(name, { root })` also refuses paths outside `root`.",
        ],
        aiFixPrompt: AI_PROMPT,
        learnMoreUrl: "https://owasp.org/www-community/attacks/Path_Traversal",
      });
    }
    return undefined;
  }

  /** `res.sendFile(name, { root: dir })`: Express confines the path to `root`. */
  private hasRootOption(f: SinkFile, call: SinkCall): boolean {
    const opts = call.args[1];
    if (opts === undefined || f.src.code[opts.start] !== "{") return false;
    return /\broot\s*[:,}]/.test(f.src.code.slice(opts.start, opts.end));
  }
}
