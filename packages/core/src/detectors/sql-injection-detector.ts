import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import {
  POSTGREST_FILTER_RE,
  SINK_NEEDLES,
  SQL_TEXT_RE,
  sinkPatternsOf,
} from "./patterns/sink-patterns.js";
import { PARAMETER_SOURCE } from "./patterns/taint-sources.js";
import { makeFinding } from "./utils/finding.js";
import { enclosingFunction, expressionEnd } from "./utils/js-functions.js";
import {
  SinkAnalyzer,
  capPerRule,
  findSinkCalls,
  loadSinkFile,
  callKey,
  sinkAnchor,
  splitTopLevel,
  staticText,
  trimRange,
  type Range,
  type SinkCall,
  type SinkFile,
} from "./utils/sinks.js";
import { capSeverityForTrust } from "./utils/taint.js";

const LEARN_MORE = "https://owasp.org/www-community/attacks/SQL_Injection";

const SQL_FIX_STEPS = [
  "Pass user values as bind parameters instead of building the SQL string: `$1`/`$2` (pg), `?` (mysql2, better-sqlite3, knex), or a tagged template such as sql`... ${value}` / Prisma.sql that parameterizes for you.",
  'For identifiers that cannot be parameterized (column names, sort direction), map the user value through a fixed allowlist (`const col = SORT_COLUMNS.get(input) ?? "created_at"`) and never interpolate the raw input.',
  "Replace raw-query escape hatches ($queryRawUnsafe, sql.unsafe, knex.raw with a template string) with their parameterized forms.",
];

const SQL_AI_PROMPT =
  "A SQL query in this code is built by interpolating or concatenating request data into the query string, which allows SQL injection. Rewrite the query so every user-supplied value is passed as a bind parameter (pg: `$1, $2` with a values array; mysql/sqlite/knex: `?` placeholders; Prisma: `$queryRaw` tagged template or `Prisma.sql`; postgres.js: the `sql` tagged template). For dynamic identifiers such as ORDER BY columns or sort direction, map the input through a fixed allowlist (for example a Map from allowed names to column names, defaulting to a safe column) instead of interpolating it. Do not try to fix this with input validation alone, and keep the query's behaviour otherwise unchanged.";

const PARAM_AI_PROMPT =
  "This exported function interpolates one of its parameters directly into a raw SQL string. Any caller that passes request data turns this into SQL injection. Change the function to pass the value as a bind parameter (`$1`/`?` placeholders with a values array, or a parameterizing tagged template such as sql`...` / Prisma.sql) instead of building the SQL text. If the parameter is an identifier (a column or table name), validate it against a fixed allowlist inside the function. Keep the function's signature and results unchanged.";

const POSTGREST_AI_PROMPT =
  'A Supabase/PostgREST filter string (`.or(...)` / `.and(...)`) is built by interpolating request data, so a caller can inject extra filter conditions (for example `,id.neq.0`) and read rows the query was meant to exclude. Replace the interpolated filter with the typed builder methods (`.ilike("name", `%${term}%`)`, `.eq(...)`, `.in(...)`), which encode values for you. If an OR across columns is required, strip or reject the PostgREST control characters `,().:` from the input before building the string, or move the search into a Postgres function called with `.rpc()` and a typed argument.';

/**
 * SQL built from request data (`injection/sql-built-from-input`), Supabase/PostgREST
 * filter strings built from request data (`injection/postgrest-filter-interpolation`),
 * and exported helpers that interpolate a parameter into raw SQL
 * (`injection/sql-built-from-parameter`).
 *
 * Only the SQL text argument is checked, so values passed as bind parameters (`$1`, `?`
 * with a values array) never count; tagged templates (`sql\`...\``, `Prisma.sql`) are not
 * calls and are never sinks. Allowlist lookups (`SORT_COLUMNS.get(x)`), literal ternaries,
 * numeric values and placeholder lists built from indexes are not taint.
 */
/** A statement verb: clause words alone (`where x`) are also ordinary English. */
const SQL_VERB_RE = /\b(?:select|insert|update|delete|merge|create|drop|alter|truncate)\b/i;

export class SqlInjectionDetector implements Detector {
  id = "sql-injection-detector";
  name = "SQL Injection";
  category = "injection" as const;
  description =
    "Detects SQL queries and Supabase filter strings built by interpolating request data instead of using bind parameters.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const needles = [...SINK_NEEDLES.sql, ...SINK_NEEDLES.postgrest];
    const patterns = sinkPatternsOf("sql", "postgrest");
    for (const file of context.files) {
      const f = await loadSinkFile(context, file, needles);
      if (f === undefined) continue;
      const calls = findSinkCalls(f.src, patterns, f.aliases);
      if (calls.length === 0) continue;
      const sql = new SinkAnalyzer(f, "sql");
      const postgrest = new SinkAnalyzer(f, "postgrest");
      const out: Finding[] = [];
      for (const call of calls) {
        try {
          const arg = this.sqlArgument(f, call);
          if (arg === undefined) continue;
          const text = this.queryText(f, arg, call.start);
          if (call.pattern.kind === "postgrest") {
            if (!POSTGREST_FILTER_RE.test(text)) continue;
            const finding = this.postgrestFinding(f, postgrest, call, arg);
            if (finding !== undefined) out.push(finding);
            continue;
          }
          if (
            call.pattern.requiresSqlText === true &&
            !(SQL_TEXT_RE.test(text) && SQL_VERB_RE.test(text))
          )
            continue;
          const finding =
            this.inputFinding(f, sql, call, arg) ?? this.parameterFinding(f, sql, call, arg);
          if (finding !== undefined) out.push(finding);
        } catch {
          // a detector never throws
        }
      }
      findings.push(...capPerRule(out));
    }
    return findings;
  }

  /** The SQL text argument: the first argument, or the `text`/`sql` property of a config object. */
  private sqlArgument(f: SinkFile, call: SinkCall): Range | undefined {
    const arg = call.args[0];
    if (arg === undefined) return undefined;
    const code = f.src.code;
    if (code[arg.start] !== "{") return arg;
    const close = f.src.matchOf(arg.start);
    if (close < 0) return undefined;
    for (const part of splitTopLevel(f.src, { start: arg.start + 1, end: close }, ",")) {
      const m = /^(?:text|sql|query)\s*:\s*/.exec(code.slice(part.start, part.end));
      if (m !== null) return trimRange(f.src, { start: part.start + m[0].length, end: part.end });
    }
    return undefined;
  }

  /**
   * Static SQL text of the argument; for an identifier, the text of its declaration and
   * `+=` appends earlier in the file (bounded).
   */
  private queryText(f: SinkFile, arg: Range, before: number): string {
    const code = f.src.code;
    const seg = code.slice(arg.start, arg.end);
    if (!/^[A-Za-z_$][\w$]*$/.test(seg)) {
      // identifiers inside the argument (`BASE + ` WHERE ...``) contribute their declared text
      const own = staticText(f.src, arg);
      const names = new Set(seg.match(/(?<![\w$.])[A-Za-z_$][\w$]*(?![\w$(])/g) ?? []);
      const extra: string[] = [];
      for (const n of [...names].slice(0, 6)) {
        if (/^(?:const|let|var|new|await|typeof)$/.test(n)) continue;
        const sub = this.declaredText(f, n, before);
        if (sub !== "") extra.push(sub);
      }
      return [own, ...extra].join(" ");
    }
    return this.declaredText(f, seg, before);
  }

  private declaredText(f: SinkFile, seg: string, before: number): string {
    const code = f.src.code;
    const parts: string[] = [];
    const name = seg.replace(/\$/g, "\\$");
    const re = new RegExp(
      String.raw`(?:\b(?:const|let|var)\s+${name}\s*(?::[^=;]{0,120})?=|(?<![\w$.])${name}\s*\+=)\s*`,
      "g",
    );
    for (let m = re.exec(code); m !== null && m.index < before; m = re.exec(code)) {
      const start = m.index + m[0].length;
      const end = expressionEnd(f.src, start);
      parts.push(staticText(f.src, { start, end }));
      if (parts.length >= 8) break;
    }
    return parts.join(" ");
  }

  private inputFinding(
    f: SinkFile,
    an: SinkAnalyzer,
    call: SinkCall,
    arg: Range,
  ): Finding | undefined {
    const t = an.argTaint(arg, call.start);
    if (t === undefined) return undefined;
    const anchor = sinkAnchor(f.src, call, t.hit.offset);
    const severity = capSeverityForTrust(
      t.confidence === "high" && t.hit.trust === "remote" ? "critical" : "high",
      t.hit.trust,
    );
    return makeFinding({
      category: "injection",
      ruleId: "injection/sql-built-from-input",
      title: "SQL Query Built From Request Data",
      severity,
      confidence: t.confidence,
      file: f.file,
      line: anchor.line,
      endLine: anchor.endLine,
      evidence: anchor.evidence,
      discriminator: callKey(f.src, call.start, call.callee),
      plainEnglishProblem: `Data from the ${t.hit.source.label} is pasted into the text of a SQL query instead of being sent as a bind parameter. An attacker can close the quote and append their own SQL (for example \`' OR 1=1 --\` or a UNION SELECT).`,
      whyItMatters:
        "SQL injection lets an attacker read or change any table the database user can reach: other customers' records, password hashes, API keys. A server-side database connection usually bypasses row-level security, so one injectable query exposes everything.",
      fixSteps: SQL_FIX_STEPS,
      aiFixPrompt: SQL_AI_PROMPT,
      learnMoreUrl: LEARN_MORE,
    });
  }

  private parameterFinding(
    f: SinkFile,
    an: SinkAnalyzer,
    call: SinkCall,
    arg: Range,
  ): Finding | undefined {
    let top = enclosingFunction(f.spans, call.start);
    while (top?.parent !== undefined) top = top.parent;
    if (top === undefined || !top.exported || top.role !== "other") return undefined;
    const indexes = top.params
      .map((p, i) => ({ p, i }))
      .filter(({ p }) => !/:\s*(?:number|boolean|bigint)\s*(?:=|$)/.test(p.text))
      .map(({ i }) => i);
    const state = an.seededState(top, indexes, PARAMETER_SOURCE);
    if (state === undefined) return undefined;
    const hit = an
      .hitsIn(state, arg, call.start)
      .find((e) => e.hit.source.id === PARAMETER_SOURCE.id);
    if (hit === undefined) return undefined;
    const anchor = sinkAnchor(f.src, call, hit.hit.offset);
    return makeFinding({
      category: "injection",
      ruleId: "injection/sql-built-from-parameter",
      title: "Exported Helper Builds SQL From Its Parameter",
      severity: "medium",
      confidence: "low",
      file: f.file,
      line: anchor.line,
      endLine: anchor.endLine,
      evidence: anchor.evidence,
      discriminator: callKey(f.src, call.start, call.callee),
      plainEnglishProblem:
        "This exported function pastes one of its parameters into the text of a raw SQL query. Whether that is exploitable depends on the callers: as soon as one of them passes request data, it is SQL injection.",
      whyItMatters:
        "Helpers like this hide SQL injection from the route that calls them, so a later change that passes user input straight through goes unnoticed. Parameterizing inside the helper makes every caller safe.",
      fixSteps: SQL_FIX_STEPS,
      aiFixPrompt: PARAM_AI_PROMPT,
      learnMoreUrl: LEARN_MORE,
    });
  }

  private postgrestFinding(
    f: SinkFile,
    an: SinkAnalyzer,
    call: SinkCall,
    arg: Range,
  ): Finding | undefined {
    const t = an.argTaint(arg, call.start);
    if (t === undefined) return undefined;
    const anchor = sinkAnchor(f.src, call, t.hit.offset);
    return makeFinding({
      category: "injection",
      ruleId: "injection/postgrest-filter-interpolation",
      title: "Supabase Filter String Built From Request Data",
      severity: "medium",
      confidence: t.confidence,
      file: f.file,
      line: anchor.line,
      endLine: anchor.endLine,
      evidence: anchor.evidence,
      discriminator: callKey(f.src, call.start, call.callee),
      plainEnglishProblem: `Data from the ${t.hit.source.label} is pasted into a PostgREST filter string (\`.or(...)\`). Commas, dots and parentheses in the input add filter conditions of the attacker's choosing.`,
      whyItMatters:
        "Injected filter conditions can widen a search to rows the query was meant to exclude. Row-level security still applies, but with a service-role client or permissive policies this leaks other users' data.",
      fixSteps: [
        'Use the typed filter methods (`.ilike("column", pattern)`, `.eq`, `.in`) which encode the value, instead of building the filter string.',
        "If you need an OR across columns, reject or strip `,` `(` `)` `.` `:` from the input first, or move the search into a Postgres function called via `.rpc()`.",
      ],
      aiFixPrompt: POSTGREST_AI_PROMPT,
      learnMoreUrl: "https://supabase.com/docs/reference/javascript/or",
    });
  }
}
