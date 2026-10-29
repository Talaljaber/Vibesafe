import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { makeFinding } from "./utils/finding.js";
import {
  enclosingFunction,
  enclosingOpen,
  extractFunctions,
  patternBindings,
  type FunctionSpan,
} from "./utils/js-functions.js";
import type { JsSource } from "./utils/js-source.js";
import { stripComments } from "./utils/strip-comments.js";
import { calleeText, escapeRegExp, nextNonWs, serverSources } from "./utils/tooling-js.js";

/**
 * `validation/check-then-act-race`: server code reads a record, checks one of its
 * fields, then writes back an absolute value computed from the value it read
 * (`update({ stock: product.stock - qty })`) in a separate query. Concurrent requests
 * pass the same check with the same old value and the last write wins (overselling,
 * double spending, lost updates).
 *
 * All of these are required (masked code, one function and its enclosing functions):
 * 1. `X` is bound by `const|let|var <pattern> = await ...` (a read) before the write;
 * 2. an `if (...)` between the read and the write tests `X.field`;
 * 3. the write sets `field` to `X.field +/- ...` inside an ORM update call
 *    (`update`, `updateOne`, `updateMany`, `upsert`, `findOneAndUpdate`,
 *    `findByIdAndUpdate`, `.set` after `.update(`), directly or through a local
 *    `const next = X.field - n`; or in an `UPDATE ... SET field = ${X.field - n}` SQL
 *    template; or as `X.field -= n` followed by `X.save()`.
 *
 * Not reported: the function uses a transaction or a row lock (`$transaction`,
 * `.transaction(`, `FOR UPDATE`, `BEGIN`, `SERIALIZABLE`, `withTransaction`,
 * `startSession`), the update also filters on the old value or a version
 * (compare-and-swap), atomic increments (`{ decrement: n }`, `$inc`, `stock = stock - 1`),
 * client, build and script files.
 */

const MAX_PER_FILE = 25;

const PREFILTER = /\bawait\b/;

const UPDATE_CALLEE_RE =
  /(?:^|\.)(?:update|updateOne|updateMany|upsert|findOneAndUpdate|findByIdAndUpdate|findAndModify)$/;
const LOCK_RE =
  /\$transaction\b|\.transaction\s*\(|\btransaction\s*\(|\bwithTransaction\b|\bstartSession\b|\bFOR\s+UPDATE\b|\bBEGIN\b|\bSERIALIZABLE\b|\bLOCK\s+TABLE\b|pg_advisory/i;

const OBJECT_WRITE_RE =
  /(?<![\w$.])([A-Za-z_$][\w$]*)\s*:\s*([A-Za-z_$][\w$]*)\s*[?!]?\.\s*([A-Za-z_$][\w$]*)\s*[-+](?![-+=])/g;
const DERIVED_DECL_RE =
  /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;\n]{0,80})?=\s*\(?\s*([A-Za-z_$][\w$]*)\s*[?!]?\.\s*([A-Za-z_$][\w$]*)\s*[-+](?![-+=])/g;
/** Awaited reads that are request input or the caller's identity, not a stored record. */
const NON_RECORD_INIT_RE =
  /^\s*(?::[^=;]{0,120})?=\s*\(?\s*await\s+(?:[\w$.]*\.\s*(?:json|formData|text|arrayBuffer|blob)\s*\(\s*\)|(?:[\w$.]*\.)?(?:auth|getServerSession|getSession|currentUser|getCurrentUser|requireUser|requireAuth|requireSession|getAuth|validateRequest)\s*\(|[\w$.]*\.auth\s*\.\s*\w+\s*\()/;
const WINDOW = 4000;
const SQL_WRITE_RE =
  /\b([A-Za-z_][\w]*)\s*=\s*\$\{\s*([A-Za-z_$][\w$]*)\s*\??\.\s*([A-Za-z_$][\w$]*)\s*[-+](?![-+=])/g;
const MUTATE_RE =
  /(?<![\w$.])([A-Za-z_$][\w$]*)\s*\.\s*([A-Za-z_$][\w$]*)\s*(?:-=|\+=|=\s*\1\s*\.\s*\2\s*[-+](?![-+=]))/g;

interface Write {
  /** Offset reported (the written key / statement). */
  at: number;
  /** Name of the record read earlier. */
  obj: string;
  field: string;
  /** Range searched for a compare-and-swap filter on the old value. */
  stmt: { start: number; end: number };
  /** Offset of the `X.field` read in the written value (excluded from the CAS search). */
  valueRead: number;
}

/** Innermost update-like call around `pos` (up to a few object levels), as [open, close]. */
function updateCall(src: JsSource, pos: number): { open: number; close: number } | undefined {
  const code = src.code;
  let open = enclosingOpen(src, pos);
  for (let guard = 0; guard < 5 && open >= 0; guard++) {
    if (code[open] === "(") {
      const callee = calleeText(code, open);
      const isSet =
        /(?:^|\.)set$/.test(callee) &&
        /\.\s*update\s*\(/.test(code.slice(Math.max(0, open - 300), open));
      if (!UPDATE_CALLEE_RE.test(callee) && !isSet) return undefined;
      const close = src.matchOf(open);
      return close > open ? { open, close } : undefined;
    }
    if (code[open] !== "{") return undefined;
    open = enclosingOpen(src, open);
  }
  return undefined;
}

/** End of a call chain continuing after `close` (`.eq("id", x).select()`). */
function chainEnd(src: JsSource, close: number): number {
  const code = src.code;
  let end = close + 1;
  for (let guard = 0; guard < 12; guard++) {
    const dot = nextNonWs(code, end);
    if (code[dot] !== ".") break;
    const m = /^\.\s*[A-Za-z_$][\w$]*\s*\(/.exec(code.slice(dot, dot + 80));
    if (m === null) break;
    const c = src.matchOf(dot + m[0].length - 1);
    if (c < 0) break;
    end = c + 1;
  }
  return end;
}

function fieldRe(obj: string, field: string): RegExp {
  return new RegExp(
    String.raw`(?<![\w$.])${escapeRegExp(obj)}\s*[?!]?\.\s*${escapeRegExp(field)}(?![\w$])`,
    "g",
  );
}

/** Statement end after `pos`: the next `;` or blank-free line end at depth 0 (bounded). */
function statementEnd(code: string, pos: number): number {
  const semi = code.indexOf(";", pos);
  const nl = code.indexOf("\n", pos);
  const ends = [semi, nl].filter((x) => x >= 0);
  return ends.length === 0 ? code.length : Math.min(...ends);
}

function findWrites(src: JsSource): Write[] {
  const { code, text } = src;
  const out: Write[] = [];
  for (const m of code.matchAll(OBJECT_WRITE_RE)) {
    if (m[1] !== m[3]) continue;
    const call = updateCall(src, m.index);
    if (call === undefined) continue;
    const valueRead = m.index + m[0].indexOf(m[2]!, m[1]!.length);
    out.push({
      at: m.index,
      obj: m[2]!,
      field: m[3]!,
      stmt: { start: call.open, end: chainEnd(src, call.close) },
      valueRead,
    });
  }
  for (const m of code.matchAll(DERIVED_DECL_RE)) {
    const local = m[1]!;
    const obj = m[2]!;
    const field = m[3]!;
    const declEnd = statementEnd(code, m.index + m[0].length);
    const use = new RegExp(
      String.raw`(?<![\w$.])${escapeRegExp(field)}\s*:\s*${escapeRegExp(local)}(?![\w$])` +
        (local === field ? String.raw`|(?<=[{,]\s*)${escapeRegExp(local)}(?=\s*[,}])` : ""),
      "g",
    );
    // only the next WINDOW characters: the write belongs to the same function as the declaration
    const windowEnd = Math.min(code.length, declEnd + WINDOW);
    use.lastIndex = declEnd;
    for (let u = use.exec(code); u !== null && u.index < windowEnd; u = use.exec(code)) {
      const call = updateCall(src, u.index);
      if (call === undefined) continue;
      out.push({
        at: u.index,
        obj,
        field,
        stmt: { start: call.open, end: chainEnd(src, call.close) },
        valueRead: m.index + m[0].lastIndexOf(obj, m[0].length - field.length),
      });
      break;
    }
  }
  for (const m of text.matchAll(SQL_WRITE_RE)) {
    if (m[1] !== m[3]) continue;
    if (code[m.index] !== " ") continue; // must be template text, not code
    const tStart = text.lastIndexOf("`", m.index);
    const tEnd = text.indexOf("`", m.index);
    if (tStart < 0 || tEnd < 0) continue;
    if (!/\bUPDATE\b[\s\S]*\bSET\b/i.test(text.slice(tStart, m.index))) continue;
    out.push({
      at: m.index,
      obj: m[2]!,
      field: m[3]!,
      stmt: { start: tStart, end: tEnd + 1 },
      valueRead: m.index + m[0].indexOf(m[2]!, m[0].indexOf("${")),
    });
  }
  for (const m of code.matchAll(MUTATE_RE)) {
    const obj = m[1]!;
    const save = new RegExp(String.raw`(?<![\w$.])${escapeRegExp(obj)}\s*\.\s*save\s*\(`, "g");
    save.lastIndex = m.index + m[0].length;
    const s = save.exec(code.slice(0, Math.min(code.length, m.index + 2000)));
    if (s === null) continue;
    out.push({
      at: m.index,
      obj,
      field: m[2]!,
      stmt: { start: m.index + m[0].length, end: s.index },
      valueRead: m.index,
    });
  }
  return out.sort((a, b) => a.at - b.at);
}

/** Offset of the latest `const|let|var <pattern> = await ...` binding `obj` in `span` before `before`. */
function awaitedRead(src: JsSource, span: FunctionSpan, obj: string, before: number): number {
  const code = src.code;
  const re = /\b(?:const|let|var)\s+/g;
  re.lastIndex = span.bodyStart;
  let found = -1;
  for (let m = re.exec(code); m !== null && m.index < before; m = re.exec(code)) {
    const patStart = m.index + m[0].length;
    let patEnd: number;
    if (code[patStart] === "{" || code[patStart] === "[") {
      const close = src.matchOf(patStart);
      if (close < 0) continue;
      patEnd = close + 1;
    } else {
      const id = /^[A-Za-z_$][\w$]*/.exec(code.slice(patStart, patStart + 100));
      if (id === null) continue;
      patEnd = patStart + id[0].length;
    }
    if (!patternBindings(code.slice(patStart, patEnd)).includes(obj)) continue;
    const rest = code.slice(patEnd, patEnd + 200);
    if (/^\s*(?::[^=;]{0,120})?=\s*\(?\s*await\b/.test(rest) && !NON_RECORD_INIT_RE.test(rest))
      found = m.index;
  }
  return found;
}

/** An `if (...)` testing `obj.field` between `from` and `to`. */
function checkedBetween(src: JsSource, obj: string, field: string, from: number, to: number) {
  const code = src.code;
  const re = /\bif\s*\(/g;
  re.lastIndex = from;
  const fr = fieldRe(obj, field);
  for (let m = re.exec(code); m !== null && m.index < to; m = re.exec(code)) {
    const open = m.index + m[0].length - 1;
    const close = src.matchOf(open);
    if (close < 0 || close > to) continue;
    const cond = code.slice(open + 1, close);
    fr.lastIndex = 0;
    if (fr.test(cond) && /[<>]|[!=]==?|^\s*!/.test(cond)) return true;
  }
  return false;
}

/** The write's statement also filters on the old value or a version (compare-and-swap). */
function compareAndSwap(src: JsSource, w: Write): boolean {
  const seg = src.text.slice(w.stmt.start, w.stmt.end);
  if (/\bversion\b/i.test(seg)) return true;
  const fr = fieldRe(w.obj, w.field);
  for (const m of seg.matchAll(fr)) {
    if (w.stmt.start + m.index !== w.valueRead) return true;
  }
  return false;
}

/** The write runs inside a transaction/lock call, or its function uses one. */
function locked(src: JsSource, noComments: string, span: FunctionSpan, at: number): boolean {
  // SQL lives in strings, so test the text with comments blanked (a `BEGIN` in a comment is no lock)
  if (LOCK_RE.test(noComments.slice(span.start, span.end))) return true;
  if (span.wrappers.some((w) => /transaction/i.test(w))) return true;
  let open = enclosingOpen(src, at);
  for (let guard = 0; guard < 40 && open >= 0; guard++) {
    if (src.code[open] === "(" && /transaction|lock/i.test(calleeText(src.code, open))) return true;
    open = enclosingOpen(src, open);
  }
  return false;
}

export class CheckThenActDetector implements Detector {
  id = "check-then-act-detector";
  name = "Check-Then-Act Race";
  category = "validation" as const;
  description =
    "Detects server code that reads a record, checks a field such as stock or balance, and writes back a value computed from the old one in a separate query without a transaction or atomic update.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    try {
      for (const { file, src, classification } of await serverSources(context, PREFILTER)) {
        const writes = findWrites(src);
        if (writes.length === 0) continue;
        const spans = extractFunctions(src, classification);
        const noComments = stripComments(src.text);
        const lines = new Set<number>();
        for (const w of writes) {
          if (lines.size >= MAX_PER_FILE) break;
          const line = src.lineAt(w.at);
          if (lines.has(line)) continue;
          let span = enclosingFunction(spans, w.at);
          let read = -1;
          for (let depth = 0; span !== undefined && depth < 3; depth++) {
            read = awaitedRead(src, span, w.obj, w.at);
            if (read >= 0) break;
            span = span.parent;
          }
          if (span === undefined || read < 0) continue;
          if (!checkedBetween(src, w.obj, w.field, read, w.at)) continue;
          if (compareAndSwap(src, w) || locked(src, noComments, span, w.at)) continue;
          lines.add(line);
          findings.push(this.finding(file, src, line));
        }
      }
    } catch {
      // Detectors never throw.
    }
    return findings;
  }

  private finding(file: string, src: JsSource, line: number): Finding {
    return makeFinding({
      category: "validation",
      ruleId: "validation/check-then-act-race",
      title: "Check-then-act race on a stored value",
      severity: "medium",
      confidence: "medium",
      file,
      line,
      evidence: src.lineText(line).trim(),
      plainEnglishProblem:
        "This code reads a record, checks one of its values (such as stock, balance or credits), and then writes back a new value computed from the old one in a separate query. Two requests that run at the same time both pass the check with the same old value, and the last write wins.",
      whyItMatters:
        "Concurrent requests can oversell inventory, spend the same balance or credits twice, or silently lose updates. If the code updates several rows in a loop, a failure halfway also leaves the earlier rows changed.",
      fixSteps: [
        "Make the check and the change one atomic database operation, for example `UPDATE products SET stock = stock - $1 WHERE id = $2 AND stock >= $1`, and treat zero updated rows as a failed check.",
        "With an ORM, use an atomic decrement with the check in the filter (Prisma `updateMany` with `where: { id, stock: { gte: n } }` and `data: { stock: { decrement: n } }`, Mongoose `updateOne` with `$inc`), or a database function called once (Supabase RPC).",
        "When several rows must change together (all items of an order), run the reads and writes in one transaction with row locks (`SELECT ... FOR UPDATE`) so a failure rolls everything back.",
      ],
      aiFixPrompt:
        "This server code reads a record, checks a value such as stock or balance, and then writes back an absolute value computed from the old one (old value minus the requested amount) in a separate query, which is a race condition under concurrent requests. Replace the read-check-write with one atomic conditional update in the database (for example UPDATE ... SET stock = stock - $n WHERE id = $id AND stock >= $n, an ORM atomic decrement with the check in the where clause, or a database function called once), treat zero affected rows as the failed check, and wrap changes to several rows in a single transaction so a failure rolls back the earlier updates. Keep the existing responses for the failed check.",
    });
  }
}
