import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { makeFinding } from "./utils/finding.js";
import { classifyPath, isTestOrFixturePath } from "./utils/file-kind.js";
import { pythonStatements, scanPythonLines } from "./utils/python-source.js";
import {
  analyzeFunction,
  MAX_FUNCTION_STATEMENTS,
  hasRequestSource,
  functionAt,
  maskPython,
  pythonFunctions,
  splitCallArgs,
  type FunctionTaint,
  type PythonFunction,
} from "./utils/python-taint.js";
import { capPerRule } from "./utils/sinks.js";

/*
 * Python injection and unsafe-deserialization sinks (line based, no AST, by design):
 * shell commands, SQL text, unsafe YAML/pickle loads, XXE-prone lxml parsers and request
 * paths opened as files. "Request-tainted" means the value comes from a Django/DRF/Flask
 * request source inside the same function (see utils/python-taint.ts); other non-constant
 * values are reported at lower severity/confidence. Known limits: values returned from
 * helper functions, class attributes and URL path kwargs are not followed.
 */

const PREFILTER =
  /subprocess|os\s*\.\s*(?:system|popen|remove|unlink)|execute|\.raw\s*\(|RawSQL|\.extra\s*\(|yaml|pickle|marshal|shelve|dill|XMLParser|setFeature|open\s*\(|send_file|send_from_directory/;

const SHELL_RE =
  /(?<![\w.])(?:subprocess\s*\.\s*(run|call|check_call|check_output|Popen)|os\s*\.\s*(system|popen))\s*\(/g;
const EXECUTE_RE =
  /(?<!\w)(?:\w*(?:cursor|conn|connection)\w*|(?:\w*_)?session|(?:db_|sql_|sa_|async_)?engine|db|cur|con|cursor\s*\(\s*\))\s*\.\s*(?:execute|executemany)\s*\(/gi;
const RAW_RE = /\.\s*objects\s*\.\s*raw\s*\(|(?<![\w.])RawSQL\s*\(/g;
const EXTRA_RE = /\.\s*extra\s*\(/g;
const YAML_RE = /(?<![\w.])yaml\s*\.\s*(load_all|load|unsafe_load_all|unsafe_load)\s*\(/g;
const DESER_RE =
  /(?<![\w.])(?:(?:c?[Pp]ickle|_pickle|dill|cloudpickle)\s*\.\s*loads?|jsonpickle\s*\.\s*decode|marshal\s*\.\s*loads?|shelve\s*\.\s*open)\s*\(/g;
const XML_PARSER_RE = /(?<![\w.])(?:etree\s*\.\s*)?XMLParser\s*\(/g;
const SAX_FEATURE_RE = /\.\s*setFeature\s*\(/g;
const FILE_SINK_RE =
  /(?<![\w.])(?:(open)|(send_file)|(send_from_directory)|os\s*\.\s*(?:remove|unlink))\s*\(/g;

interface RuleText {
  title: string;
  problem: string;
  why: string;
  fix: string[];
  prompt: string;
}

const TEXT: Record<string, RuleText> = {
  shell: {
    title: "Python Shell Command Built From Dynamic Input",
    problem:
      "A shell command string is built from a variable (f-string, %, format or +) and run through a shell (shell=True, os.system or os.popen).",
    why: "A value containing `;`, `&&`, backticks or `$(...)` runs extra commands on your server. When the value comes from a request or an uploaded file name this is remote code execution.",
    fix: [
      "Pass the command as a list and drop shell=True: subprocess.run([binary, arg1, arg2], check=True).",
      "If a shell is unavoidable, wrap every interpolated value in shlex.quote().",
      "Validate file names and options against an allowlist before using them.",
    ],
    prompt:
      "This Python code runs a shell command built from a variable (subprocess with shell=True, os.system or os.popen). Rewrite it to use subprocess.run with an argument list and no shell, validate or allowlist every dynamic value, and wrap any value that must stay in a shell string with shlex.quote(). Keep the command's behaviour for valid input.",
  },
  sql: {
    title: "Python SQL Built From Dynamic Input",
    problem:
      "SQL text is built with an f-string, %, .format() or + and passed to a raw query API (cursor.execute, objects.raw, RawSQL, extra).",
    why: "Values pasted into SQL text are parsed as SQL. A crafted value reads or changes any table (SQL injection), including other tenants' data.",
    fix: [
      'Use placeholders and pass values separately: cursor.execute("... WHERE id = %s", [value]).',
      "For extra(), keep the clause constant and pass values through params=[...].",
      "Identifiers (columns, tables, sort fields) must come from a fixed allowlist, never from the request.",
    ],
    prompt:
      "This Python code builds SQL text from variables (f-string, %, format or +) and runs it through cursor.execute, objects.raw, RawSQL or queryset.extra. Rewrite it to use parameterized queries (placeholders plus a params list), use the ORM where possible, and restrict any dynamic column or table name to an allowlist. Keep the results identical.",
  },
  yaml: {
    title: "Unsafe YAML Load",
    problem:
      "yaml.load / yaml.load_all is called with an unsafe loader (or no loader), or yaml.unsafe_load is used.",
    why: "The unsafe loaders construct arbitrary Python objects from the document. A crafted YAML file runs code on your server when it is parsed.",
    fix: [
      "Use yaml.safe_load (or yaml.load(data, Loader=yaml.SafeLoader)).",
      "If custom tags are needed, register them on a SafeLoader subclass.",
    ],
    prompt:
      "This Python code parses YAML with an unsafe loader (yaml.load without SafeLoader, Loader=yaml.Loader/UnsafeLoader/FullLoader, or yaml.unsafe_load). Switch it to yaml.safe_load, and if custom tags are needed register them on a SafeLoader subclass. Keep the parsed structure the same for valid input.",
  },
  deser: {
    title: "Unsafe Deserialization",
    problem:
      "Data is deserialized with pickle, dill, jsonpickle, marshal or shelve from a value that is not a fixed local file.",
    why: "Unpickling executes code chosen by whoever produced the bytes. If the bytes can come from a user, a cache or a queue an attacker can write to, this is remote code execution.",
    fix: [
      "Use a data-only format such as JSON for anything that crosses a trust boundary.",
      "If pickle must stay, only load bytes your own server wrote and sign them (hmac) before loading.",
    ],
    prompt:
      "This Python code deserializes with pickle, dill, jsonpickle, marshal or shelve from a non-literal source. Replace it with JSON (or another data-only format), or if the bytes are server-written add an HMAC signature check before loading. Keep the data shape the same.",
  },
  xxe: {
    title: "XML Parser Resolves External Entities",
    problem:
      "An lxml/SAX XML parser is configured to resolve entities, load DTDs, allow network access or read external general entities.",
    why: "A crafted XML document can read local files (such as secrets) or make your server call internal URLs (XXE), and expand entities to exhaust memory.",
    fix: [
      "Use defusedxml for untrusted XML.",
      "Or construct etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False).",
      "Never enable the external-entity SAX features for untrusted input.",
    ],
    prompt:
      "This Python code configures an XML parser to resolve external entities (resolve_entities=True, load_dtd=True, no_network=False or SAX external-ges). Switch to defusedxml, or set resolve_entities=False, no_network=True and load_dtd=False. Keep the parsed output the same for valid documents.",
  },
  path: {
    title: "Python Path Traversal From Request Input",
    problem:
      "A file path built from request data is opened, sent or deleted without reducing it to a file name or confining it to a base folder.",
    why: "`../` segments or an absolute path escape the intended folder, so an attacker can read or delete other tenants' files, source code or secrets.",
    fix: [
      "Look the file up by id in the database and use the stored server-generated name.",
      "If a name from the request is unavoidable, reduce it with os.path.basename().",
      "Resolve the final path with os.path.realpath and reject it unless it startswith the base directory.",
    ],
    prompt:
      "This Python code opens, sends or deletes a file whose path is built from request data. Reduce the name with os.path.basename (or look the file up by id), resolve the final path with os.path.realpath and reject it unless it starts with the intended base directory. Keep the behaviour for valid files.",
  },
};

const MAX_EVIDENCE = 200;

export class PythonInjectionDetector implements Detector {
  id = "python-injection-detector";
  name = "Python Injection";
  category = "injection" as const;
  description =
    "Detects Python shell, SQL, YAML, pickle, XML and file-path sinks fed by dynamic or request-derived data.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of context.files) {
      try {
        if (classifyPath(file) !== "python") continue;
        const norm = file.replace(/\\/g, "/");
        if (isTestOrFixturePath(norm) || /(?:^|\/)migrations\//.test(norm)) continue;
        const content = await context.readFile(file);
        if (!content || !PREFILTER.test(content)) continue;
        findings.push(...capPerRule(this.scanFile(file, content)));
      } catch {
        // a detector never throws
      }
    }
    return findings;
  }

  private scanFile(file: string, content: string): Finding[] {
    const lines = scanPythonLines(content);
    const stmts = pythonStatements(lines);
    const funcs = pythonFunctions(stmts);
    const taints = new Map<PythonFunction | undefined, FunctionTaint>();
    const confinedCache = new Map<PythonFunction | undefined, boolean>();
    const hasLxml = content.includes("lxml");
    // `from yaml import CSafeLoader as Loader` makes a bare `Loader` safe.
    const safeLoaderAlias = [...content.matchAll(/from\s+yaml\s+import\s+([^\n]+)/g)].some((im) =>
      [...im[1]!.matchAll(/\b(\w+)\s+as\s+Loader\b/g)].some(
        (a) => !/^C?(?:Unsafe|Full)?Loader$/.test(a[1]!),
      ),
    );
    const out: Finding[] = [];

    const taintOf = (fn: PythonFunction | undefined): FunctionTaint => {
      let t = taints.get(fn);
      if (!t) {
        t = analyzeFunction(fn);
        taints.set(fn, t);
      }
      return t;
    };
    const confined = (fn: PythonFunction | undefined): boolean => {
      if (!fn) return false;
      let c = confinedCache.get(fn);
      if (c === undefined) {
        const body = fn.statements
          .slice(0, MAX_FUNCTION_STATEMENTS)
          .map((s) => maskPython(s.stmt))
          .join("\n");
        c =
          /(?:realpath|abspath|resolve|commonpath|is_relative_to|safe_join)/.test(body) &&
          /(?:startswith|is_relative_to|commonpath|safe_join)/.test(body);
        confinedCache.set(fn, c);
      }
      return c;
    };

    for (const st of stmts) {
      const raw = st.stmt;
      if (!PREFILTER.test(raw)) continue;
      const mask = maskPython(raw);
      const fn = functionAt(funcs, st.start);
      const ft = (): FunctionTaint => taintOf(fn);
      const evidence = st.head.trim().slice(0, MAX_EVIDENCE);
      const emit = (
        ruleId:
          | "injection/python-shell-command"
          | "injection/python-sql-interpolation"
          | "injection/python-unsafe-yaml-load"
          | "injection/python-unsafe-deserialization"
          | "injection/python-xxe-parser"
          | "injection/python-path-traversal",
        key: keyof typeof TEXT,
        index: number,
        severity: "critical" | "high",
        confidence: "high" | "medium",
        anchor?: number,
      ): void => {
        const t = TEXT[key]!;
        out.push(
          makeFinding({
            category: "injection",
            ruleId,
            title: t.title,
            severity,
            confidence,
            file,
            line: (anchor ?? st.start) + 1,
            ...(st.end > (anchor ?? st.start) ? { endLine: st.end + 1 } : {}),
            evidence,
            discriminator: `${index}:${st.start}:${ruleId}`,
            plainEnglishProblem: t.problem,
            whyItMatters: t.why,
            fixSteps: t.fix,
            aiFixPrompt: t.prompt,
          }),
        );
      };
      const taintedSev = (tainted: boolean) =>
        tainted
          ? ({ severity: "critical", confidence: "high" } as const)
          : ({ severity: "high", confidence: "medium" } as const);
      /** Dynamic text: built from a non-constant value, or itself a request value. */
      const dynamic = (arg: string): { dyn: boolean; tainted: boolean } => {
        const t = ft();
        const tainted = t.isTainted(arg, st.start);
        // Taint alone only counts for a bare variable or request value (an alias of a request
        // string); other tainted arguments (ORM statements) are dynamic only when text is built.
        const direct = /^\(?\s*[A-Za-z_]\w*\s*\)?$/.test(arg.trim()) || hasRequestSource(arg);
        return { dyn: (tainted && direct) || t.nonConstant(arg, st.start), tainted };
      };

      // 1. shell commands
      for (const m of mask.matchAll(SHELL_RE)) {
        const open = m.index + m[0].length - 1;
        const args = splitCallArgs(mask, open);
        const first = args.find((a) => !/^[A-Za-z_]\w*\s*=(?!=)/.test(a));
        if (first === undefined || first.startsWith("[") || first.startsWith("*")) continue;
        const isOs = m[2] !== undefined;
        if (!isOs && !args.some((a) => /^shell\s*=\s*True$/.test(a))) continue;
        const { dyn, tainted } = dynamic(first);
        if (!dyn) continue;
        const s = taintedSev(tainted);
        emit("injection/python-shell-command", "shell", m.index, s.severity, s.confidence);
      }

      // 2. SQL text
      for (const re of [EXECUTE_RE, RAW_RE]) {
        for (const m of mask.matchAll(re)) {
          const open = m.index + m[0].length - 1;
          const first = splitCallArgs(mask, open)[0];
          if (first === undefined || /^[A-Za-z_]\w*\s*=(?!=)/.test(first)) continue;
          const { dyn, tainted } = dynamic(first);
          if (!dyn) continue;
          const s = taintedSev(tainted);
          emit("injection/python-sql-interpolation", "sql", m.index, s.severity, s.confidence);
        }
      }
      for (const m of mask.matchAll(EXTRA_RE)) {
        const open = m.index + m[0].length - 1;
        for (const a of splitCallArgs(mask, open)) {
          const kw = /^(?:where|select|tables)\s*=\s*([\s\S]+)$/.exec(a);
          if (!kw) continue;
          const { dyn, tainted } = dynamic(kw[1]!);
          if (!dyn) continue;
          const s = taintedSev(tainted);
          emit("injection/python-sql-interpolation", "sql", m.index, s.severity, s.confidence);
          break;
        }
      }

      // 3. unsafe YAML
      for (const m of mask.matchAll(YAML_RE)) {
        const open = m.index + m[0].length - 1;
        const args = splitCallArgs(mask, open);
        const fnName = m[1]!;
        let unsafe: boolean;
        if (fnName === "unsafe_load" || fnName === "unsafe_load_all") unsafe = true;
        else {
          const kw = args.find((a) => /^Loader\s*=/.test(a));
          const loader = kw ? kw.replace(/^Loader\s*=\s*/, "") : args[1];
          if (loader === undefined) unsafe = true;
          else {
            const l = loader.trim();
            unsafe =
              /(?:^|\.)C?(?:Unsafe|Full)?Loader$/.test(l) && !(l === "Loader" && safeLoaderAlias);
          }
        }
        if (!unsafe) continue;
        const tainted = args[0] !== undefined && ft().isTainted(args[0], st.start);
        emit(
          "injection/python-unsafe-yaml-load",
          "yaml",
          m.index,
          tainted ? "critical" : "high",
          "high",
        );
      }

      // 4. unsafe deserialization
      for (const m of mask.matchAll(DESER_RE)) {
        const open = m.index + m[0].length - 1;
        const first = splitCallArgs(mask, open)[0];
        if (first === undefined) continue;
        if (/^[rbuRBU]{0,2}(["'])~*\1$/.test(first)) continue; // literal bytes/path
        if (/^open\s*\(\s*[rbuRBU]{0,2}(["'])~*\1/.test(first)) continue; // literal file
        const bare = /^([A-Za-z_]\w*)$/.exec(first);
        if (bare && ft().isLiteralHandle(bare[1]!)) continue;
        const tainted = ft().isTainted(first, st.start);
        const s = taintedSev(tainted);
        emit(
          "injection/python-unsafe-deserialization",
          "deser",
          m.index,
          s.severity,
          tainted ? "high" : "medium",
        );
      }

      // 5. XXE
      if (hasLxml) {
        for (const m of mask.matchAll(XML_PARSER_RE)) {
          const open = m.index + m[0].length - 1;
          const args = splitCallArgs(mask, open);
          if (
            args.some(
              (a) =>
                /^resolve_entities\s*=\s*True$/.test(a) ||
                /^load_dtd\s*=\s*True$/.test(a) ||
                /^no_network\s*=\s*False$/.test(a),
            )
          ) {
            emit("injection/python-xxe-parser", "xxe", m.index, "high", "high");
          }
        }
      }
      if (
        /setFeature\s*\(/.test(mask) &&
        /feature_external_(?:ges|pes)|external-(?:general|parameter)-entities/.test(raw)
      ) {
        for (const m of mask.matchAll(SAX_FEATURE_RE)) {
          const open = m.index + m[0].length - 1;
          const args = splitCallArgs(raw, open);
          if (
            args.length >= 2 &&
            /feature_external_(?:ges|pes)|external-(?:general|parameter)-entities/.test(args[0]!) &&
            /^(?:True|1)$/.test(args[1]!)
          ) {
            emit("injection/python-xxe-parser", "xxe", m.index, "high", "high");
          }
        }
      }

      // 6. path traversal
      if (fn && !confined(fn)) {
        for (const m of mask.matchAll(FILE_SINK_RE)) {
          const open = m.index + m[0].length - 1;
          const args = splitCallArgs(mask, open);
          const pathArgs = m[3] !== undefined ? args.slice(1) : args.slice(0, 1);
          if (pathArgs.length === 0) continue;
          const bad = pathArgs.find((a) => ft().isTainted(a, st.start));
          if (bad !== undefined) {
            // Anchor where the request value was turned into the path; the sink is the end line.
            const origin = ft().taintOrigin(bad, st.start);
            emit(
              "injection/python-path-traversal",
              "path",
              m.index,
              "high",
              m[3] !== undefined ? "medium" : "high",
              origin,
            );
          }
        }
      }
    }
    return out;
  }
}
