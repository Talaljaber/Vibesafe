import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { classifyPath, isTestOrFixturePath } from "./utils/file-kind.js";
import { makeFinding } from "./utils/finding.js";
import { capFindingsPerRule } from "./utils/infra-common.js";

/** Lines longer than this are generated or embedded data, not hand-written commands. */
const MAX_LINE_LENGTH = 10_000;
const MAX_FILE_LINES = 20_000;

const DL = String.raw`(?:curl|wget)\b`;
/** Remote content evaluated or sourced by the current shell (pipe forms belong to shell-script-detector). */
const EVAL_REMOTE_RES: readonly RegExp[] = [
  new RegExp(String.raw`\beval\s+["']?(?:\$\(|\x60)\s*${DL}`),
  new RegExp(String.raw`(?:^|[;&|(]|\bthen\b|\bdo\b)\s*(?:source|\.)\s+<\(\s*${DL}`),
  new RegExp(
    String.raw`(?:^|[;&|(]|\bthen\b|\bdo\b)\s*(?:source|\.)\s+/dev/stdin\s*<<<\s*["']?\$\(\s*${DL}`,
  ),
];

const SQL_CLIENT_RE = /(?:^|[\s;&|(`])(?:psql|mysql|sqlite3|clickhouse-client|cqlsh)(?=\s|$)/g;
// Which flag carries the SQL text depends on the client; flags such as `psql -e` or
// `sqlite3 -table` take no argument, so a generic "ends in c or e" match misreads the DB URL.
const SQL_FLAG_BY_CLIENT: Record<string, RegExp | null> = {
  psql: /\s(?:-[A-Za-z]*c|--command)(?:=|\s*)(["'])/,
  mysql: /\s(?:-[A-Za-z]*e|--execute)(?:=|\s*)(["'])/,
  cqlsh: /\s(?:-[A-Za-z]*e|--execute)(?:=|\s*)(["'])/,
  "clickhouse-client": /\s(?:-q|--query)(?:=|\s*)(["'])/,
  sqlite3: null,
};
const SINGLE_POSITIONAL_RE = /^\s*\$(?:[1-9@*]|\{[1-9@*]\})\s*$/;
const HEREDOC_RE = /(?<!<)<<(-?)[ \t]*([A-Za-z_][A-Za-z0-9_]*)(?=\s|$|[|;&)])/;
const EXPANSION_RE =
  /(?<!\\)\$(?:\{([A-Za-z_][A-Za-z0-9_]*|[0-9@*])[^}]*\}|([A-Za-z_][A-Za-z0-9_]*|[0-9@*]))/g;
const POSITIONAL_RE = /^[1-9@*]$/;
const FN_START_RE = /^\s*(?:function\s+[\w:.-]+|[\w:.-]+\s*\(\s*\))/;
/** Text before a command that still leaves it in command position (separator plus wrappers). */
const COMMAND_POSITION_RE =
  /(?:^|[;&|(`]|\$\(|\b(?:then|do)\b)\s*(?:(?:sudo(?:\s+-\S+)*|env|time|nohup|command|exec|[A-Za-z_]\w*=\S*)\s+)*$/;
const ARG_NAME_RE = /^(?:[1-9@*]|OPTARG)$/;
const ASSIGN_RE =
  /^\s*(?:[^=\s()'"]*\)\s*)?(?:export\s+|local\s+|readonly\s+|declare\s+(?:-\w+\s+)?)?([A-Za-z_][A-Za-z0-9_]*)\+?=(.*)$/;
const NUMERIC_CHECK_RE =
  /\[\[\s*!?\s*["']?\$\{?(\w+|[@*])\}?["']?\s*=~\s*["']?\^\(?\[([^\]'"\\;$ ^][^\]'"\\;$ ]*)\](?:\+|\*|\{\d+(?:,\d*)?\})\)?\$["']?\s*\]\]/;
const CASE_RE = /\bcase\s+["']?\$\{?(\w+|[@*])\}?["']?\s+in\b/;

/** Removes a trailing `# comment` outside quotes (a `#` must start a word). */
function stripShellComment(line: string): string {
  let quote: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quote) {
      if (ch === quote) quote = null;
      else if (ch === "\\" && quote === '"') i++;
    } else if (ch === "\\") i++;
    else if (ch === '"' || ch === "'") quote = ch;
    else if (ch === "#" && (i === 0 || /\s/.test(line[i - 1] ?? ""))) return line.slice(0, i);
  }
  return line;
}

/** True when index `at` of `s` sits inside a quoted string (`$(` inside double quotes opens an unquoted context). */
function insideQuotes(s: string, at: number): boolean {
  // Open contexts: '"' and "'" quotes, "(" for a command substitution.
  const stack: string[] = [];
  for (let i = 0; i < at; i++) {
    const ch = s[i];
    const top = stack[stack.length - 1];
    if (top === "'") {
      if (ch === "'") stack.pop();
    } else if (ch === "\\") i++;
    else if (ch === "$" && s[i + 1] === "(") {
      stack.push("(");
      i++;
    } else if (top === '"') {
      if (ch === '"') stack.pop();
    } else if (ch === '"' || ch === "'") stack.push(ch);
    else if (top === "(" && ch === ")") stack.pop();
  }
  const top = stack[stack.length - 1];
  return top === '"' || top === "'";
}

/** Cuts an assignment value at the first `;`, `&` or `|` outside quotes. */
function cutValue(v: string): string {
  let quote: string | null = null;
  for (let i = 0; i < v.length; i++) {
    const ch = v[i];
    if (quote) {
      if (ch === quote) quote = null;
      else if (ch === "\\" && quote === '"') i++;
    } else if (ch === "\\") i++;
    else if (ch === '"' || ch === "'") quote = ch;
    else if (ch === ";" || ch === "&" || ch === "|") return v.slice(0, i);
  }
  return v;
}

/** Removes single-quoted segments that sit outside double quotes (no expansion happens there). */
function dropSingleQuoted(v: string): string {
  let out = "";
  let quote: string | null = null;
  for (let i = 0; i < v.length; i++) {
    const ch = v[i] ?? "";
    if (quote === "'") {
      if (ch === "'") quote = null;
    } else if (quote === '"') {
      if (ch === "\\") out += ch + (v[++i] ?? "");
      else {
        if (ch === '"') quote = null;
        out += ch;
      }
    } else if (ch === "'" || ch === '"') quote = ch;
    else out += ch;
  }
  return out;
}

/** Variables derived from script arguments, with the line from which each is validated. */
class ArgTaint {
  private readonly vars = new Set<string>();
  private readonly validatedFrom = new Map<string, number>();
  /** Line ranges of shell function bodies, where $1..$9/$@/$* are function parameters. */
  private readonly fnRanges: Array<[number, number]> = [];

  constructor(lines: readonly string[]) {
    this.findFunctions(lines);
    for (let i = 0; i < lines.length; i++) this.scanValidation(lines, i);
    for (let pass = 0; pass < 2; pass++) {
      for (let i = 0; i < lines.length; i++) this.scanAssignment(lines[i] ?? "", i);
    }
  }

  private findFunctions(lines: readonly string[]): void {
    for (let i = 0; i < lines.length; i++) {
      if (!FN_START_RE.test(lines[i] ?? "")) continue;
      let depth = 0;
      let opened = false;
      for (let k = i; k < lines.length && k - i < 500; k++) {
        const l = dropSingleQuoted(stripShellComment(lines[k] ?? ""));
        for (const ch of l) {
          if (ch === "{") {
            depth++;
            opened = true;
          } else if (ch === "}") depth--;
        }
        if (opened && depth <= 0) {
          this.fnRanges.push([i, k]);
          break;
        }
        if (!opened && k > i) break;
      }
    }
  }

  private scanValidation(lines: readonly string[], i: number): void {
    const line = lines[i] ?? "";
    if (!line.includes("[[") && !line.includes("case")) return;
    const m = NUMERIC_CHECK_RE.exec(line);
    if (m && m[1]) this.validate(m[1], i);
    const c = CASE_RE.exec(line);
    if (c && c[1]) {
      const near = [line, lines[i + 1] ?? "", lines[i + 2] ?? ""].join("\n");
      if (/\*\[!(?:0-9|a-zA-Z0-9[^\]]*)\]\*/.test(near)) this.validate(c[1], i);
    }
  }

  private validate(name: string, line: number): void {
    const prev = this.validatedFrom.get(name);
    if (prev === undefined || line < prev) this.validatedFrom.set(name, line);
  }

  /** True when `name`, referenced on line index `at`, holds script-argument data. */
  isTainted(name: string, at: number): boolean {
    if (!ARG_NAME_RE.test(name) && !this.vars.has(name)) return false;
    if (POSITIONAL_RE.test(name) && this.fnRanges.some(([s, e]) => at >= s && at <= e))
      return false;
    const v = this.validatedFrom.get(name);
    return v === undefined || v >= at;
  }

  /** True when `text` (on line index `at`) expands a tainted variable. */
  expandsTainted(text: string, at: number): boolean {
    for (const m of text.matchAll(EXPANSION_RE)) {
      if (this.isTainted(m[1] ?? m[2] ?? "", at)) return true;
    }
    return false;
  }

  private scanAssignment(line: string, i: number): void {
    const a = ASSIGN_RE.exec(line);
    if (a && a[1] && !line.includes("$((")) {
      const value = dropSingleQuoted(cutValue(a[2] ?? ""));
      if (!/\/\/\[\^/.test(value) && this.expandsTainted(value, i)) this.vars.add(a[1]);
    }
    const rd = /(?:^|[;&|]|\bdo\b|\bthen\b)\s*read\b([^;&|]*)/.exec(line);
    if (rd) {
      const toks = (rd[1] ?? "").trim().split(/\s+/);
      for (let t = 0; t < toks.length; t++) {
        const tok = toks[t] ?? "";
        if (/^-[pndtuNi]$/.test(tok)) t++;
        else if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(tok)) this.vars.add(tok);
      }
    }
    const f = /\bfor\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s+([^;]*)/.exec(line);
    if (f && f[1] && this.expandsTainted(f[2] ?? "", i)) this.vars.add(f[1]);
  }
}

/**
 * Shell script injection rules: evaluating or sourcing downloaded content in the
 * current shell, and SQL built from script arguments by shell expansion.
 */
export class ShellInjectionDetector implements Detector {
  id = "shell-injection-detector";
  name = "Shell Injection";
  category = "injection" as const;
  description =
    "Detects eval/source of downloaded content and SQL built from script arguments in shell scripts.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (classifyPath(file) !== "shell") continue;
      if (isTestOrFixturePath(file) && context.config.includeTests !== true) continue;
      try {
        const text = await context.readFile(file);
        if (text.trim() === "") continue;
        const raw = text.split(/\r?\n/);
        if (raw.length > MAX_FILE_LINES) continue;
        const lines = raw.map((l) => (l.length > MAX_LINE_LENGTH ? "" : stripShellComment(l)));
        this.evalRemote(file, raw, lines, findings);
        if (/psql|mysql|sqlite3|clickhouse-client|cqlsh/.test(text)) {
          this.sqlInterpolation(file, raw, lines, findings);
        }
      } catch {
        // Never throw from a detector.
      }
    }
    return capFindingsPerRule(findings);
  }

  private evalRemote(file: string, raw: string[], lines: string[], out: Finding[]): void {
    for (let i = 0; i < lines.length; i++) {
      const code = lines[i] ?? "";
      if (!code.includes("curl") && !code.includes("wget")) continue;
      for (const re of EVAL_REMOTE_RES) {
        const m = re.exec(code);
        if (!m || insideQuotes(code, m.index + m[0].search(/\S/))) continue;
        out.push(
          makeFinding({
            category: "injection",
            ruleId: "injection/shell-eval-remote-content",
            title: "Script evaluates content downloaded at run time",
            severity: "high",
            confidence: "high",
            file,
            line: i + 1,
            evidence: raw[i] ?? code,
            plainEnglishProblem:
              "This line downloads text from the network and evaluates or sources it in the running shell, so whatever the remote server returns runs as part of this script, with its environment and secrets.",
            whyItMatters:
              "The content is not reviewed, pinned or verified. A compromised host, a moved branch or a hijacked domain turns this into remote code execution on the machine or CI runner that runs the script, often right where credentials are loaded.",
            fixSteps: [
              "Vendor the helper into the repository, or fetch a pinned release and verify its SHA-256 checksum before using it.",
              "Never eval or source downloaded text; run a verified file instead.",
            ],
            aiFixPrompt:
              'My shell script evaluates or sources content downloaded with curl/wget (eval "$(curl ...)" or source <(curl ...)). Replace it by committing the helper into the repository, or download a pinned versioned release to a file, verify its SHA-256 checksum, and only then source it.',
          }),
        );
        break;
      }
    }
  }

  private sqlInterpolation(file: string, raw: string[], lines: string[], out: Finding[]): void {
    const taint = new ArgTaint(lines);
    const starts: number[] = [];
    let offset = 0;
    for (const l of lines) {
      starts.push(offset);
      offset += l.length + 1;
    }
    const joined = lines.join("\n");
    const lineOf = (at: number): number => {
      let lo = 0;
      let hi = starts.length - 1;
      while (lo < hi) {
        const mid = (lo + hi + 1) >> 1;
        if ((starts[mid] ?? 0) <= at) lo = mid;
        else hi = mid - 1;
      }
      return lo;
    };
    for (let i = 0; i < lines.length; i++) {
      const code = lines[i] ?? "";
      if (!/psql|mysql|sqlite3|clickhouse-client|cqlsh/.test(code)) continue;
      SQL_CLIENT_RE.lastIndex = 0;
      let client: RegExpExecArray | null = null;
      for (let m = SQL_CLIENT_RE.exec(code); m; m = SQL_CLIENT_RE.exec(code)) {
        if (!insideQuotes(code, m.index + m[0].search(/\S/))) {
          client = m;
          break;
        }
      }
      if (!client) continue;
      // The command, with backslash-newline continuations.
      let last = i;
      while ((lines[last] ?? "").trimEnd().endsWith("\\") && last + 1 < lines.length) last++;
      const from = (starts[i] ?? 0) + client.index + client[0].search(/[a-z]/);
      if (!COMMAND_POSITION_RE.test(code.slice(0, client.index + client[0].search(/[a-z]/))))
        continue;
      const cmdText = cutValue(
        joined.slice(from, (starts[last] ?? 0) + (lines[last] ?? "").length),
      );
      let sqlFrom = -1;
      let sqlTo = -1;
      let endLine = last;
      const clientName = client[0].replace(/^[^a-z]+/, "");
      const flagRe = SQL_FLAG_BY_CLIENT[clientName] ?? null;
      const flag = flagRe ? flagRe.exec(cmdText) : null;
      if (flag) {
        if (flag[1] === '"') {
          sqlFrom = from + flag.index + flag[0].length;
          sqlTo = sqlFrom;
          while (sqlTo < joined.length && joined[sqlTo] !== '"') {
            if (joined[sqlTo] === "\\") sqlTo++;
            sqlTo++;
          }
          endLine = lineOf(Math.min(sqlTo, joined.length - 1));
        }
      } else {
        const h = HEREDOC_RE.exec(cmdText);
        if (h && h[2]) {
          const delim = h[2];
          let end = -1;
          for (let k = last + 1; k < lines.length && k - last < 2000; k++) {
            const body = h[1] === "-" ? (raw[k] ?? "").replace(/^\t+/, "") : (raw[k] ?? "");
            if (body.trimEnd() === delim) {
              end = k;
              break;
            }
          }
          if (end !== -1) {
            sqlFrom = starts[last + 1] ?? 0;
            sqlTo = (starts[end] ?? 0) - 1;
            endLine = end;
          }
        }
      }
      if (sqlFrom < 0) continue;
      const sql = joined.slice(sqlFrom, Math.max(sqlFrom, sqlTo));
      let hit = -1;
      for (const m of sql.matchAll(EXPANSION_RE)) {
        const at = lineOf(sqlFrom + m.index);
        if (taint.isTainted(m[1] ?? m[2] ?? "", at)) {
          hit = at;
          break;
        }
      }
      if (hit >= 0) {
        out.push(
          makeFinding({
            category: "injection",
            ruleId: "injection/shell-sql-interpolation",
            title: "SQL built from script arguments by shell expansion",
            severity: "high",
            confidence: SINGLE_POSITIONAL_RE.test(sql) ? "medium" : "high",
            file,
            line: hit + 1,
            endLine: endLine + 1,
            evidence: raw[hit] ?? "",
            plainEnglishProblem:
              "A command-line argument (or a value read from input) is expanded straight into the SQL text passed to the database client, so the argument can contain quotes and SQL of its own.",
            whyItMatters:
              "Anyone or anything that controls the argument (an operator typo, a CI variable, a webhook that triggers the script) can change what the statement does: read other tenants' rows, update everything, or drop tables, with the database credentials the script already holds.",
            fixSteps: [
              'Pass values as client variables and reference them quoted: `psql -v org="$1" -c "... WHERE slug = :\'org\'"` (psql), or use the client\'s parameter mechanism.',
              "Validate arguments before use: `[[ $1 =~ ^[0-9]+$ ]] || exit 1` for ids, an allow-list for names.",
              "Use a quoted heredoc delimiter (`<<'SQL'`) so the shell never expands text inside the SQL.",
            ],
            aiFixPrompt:
              "My shell script interpolates script arguments into SQL passed to psql/mysql/sqlite3 (inside -c or an unquoted heredoc). Rewrite it so the SQL text is constant (quoted heredoc delimiter) and values are passed as client variables (psql -v name=\"$1\" with :'name' in the SQL), and validate numeric or enumerated arguments before use.",
          }),
        );
      }
      i = Math.max(i, last, endLine);
    }
  }
}
