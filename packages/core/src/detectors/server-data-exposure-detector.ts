// Server code that loads whole rows of a sensitive table (users, profiles, members, ...)
// and hands them to a "use client" component (or Pages Router props). React serializes
// every column of such a prop into the page payload, so internal columns reach the browser.
//
// Covers Supabase (`.from("t").select("*")`), Prisma (`prisma.user.findMany()` without
// `select`/`omit`) and Drizzle (`.select().from(users)`, `db.query.users.findMany()`).
// Static analysis only: one statement per query, binding by `const x = await <query>`.

import path from "node:path";
import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { makeFinding } from "./utils/finding.js";
import { classifyFile, isGenerated, isJsLike } from "./utils/file-kind.js";
import { getJsSource, type JsSource } from "./utils/js-source.js";
import {
  enclosingFunction,
  expressionEnd,
  extractFunctions,
  type FunctionSpan,
} from "./utils/js-functions.js";

const MAX_FINDINGS_PER_FILE = 25;
const WINDOW = 400;
const TAG_WALK_BACK = 1500;

const SENSITIVE = new Set(
  (
    "user users profile profiles account accounts organization organizations org orgs member " +
    "members orgmember orgmembers organizationmember organizationmembers teammember teammembers " +
    "membership memberships customer customers admin admins employee employees tenant tenants " +
    "userprofile userprofiles"
  ).split(" "),
);

const AI_FIX_PROMPT =
  "A server component or getServerSideProps loads whole rows of a sensitive table (select('*') " +
  "or a Prisma/Drizzle query without a column list) and passes them to a client component or " +
  "to page props, so every column is serialized into the browser. Select only the columns the " +
  "component needs, or map the row to a small DTO before passing it, and keep data access in " +
  "server-only helpers (`import 'server-only'`). Do not change what the page shows.";

function normalizeName(raw: string): string {
  const stripped = raw.replace(/["'`]/g, "").trim();
  const last = stripped.slice(stripped.lastIndexOf(".") + 1);
  return last.replace(/_/g, "").toLowerCase();
}

const isSensitive = (raw: string): boolean => SENSITIVE.has(normalizeName(raw));

/** Splits `code[from,to)` on commas at bracket depth 0; returns absolute offset ranges. */
function splitTop(code: string, from: number, to: number): Array<[number, number]> {
  const out: Array<[number, number]> = [];
  let depth = 0;
  let start = from;
  for (let i = from; i < to; i++) {
    const c = code[i];
    if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") depth--;
    else if (c === "," && depth === 0) {
      out.push([start, i]);
      start = i + 1;
    }
  }
  if (code.slice(start, to).trim() !== "") out.push([start, to]);
  return out;
}

/** Split a Supabase select string on top-level commas. */
function splitSelect(s: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let cur = "";
  for (const c of s) {
    if (c === "(") depth++;
    else if (c === ")") depth--;
    if (c === "," && depth === 0) {
      out.push(cur.trim());
      cur = "";
    } else cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

const REL_RE = /^(?:[\w$]+\s*:\s*)?([\w$]+)\s*(?:![\w$]+\s*)*\(/;

/** True when a select string pulls every column of a sensitive table (directly or nested). */
function selectHasSensitiveStar(select: string, tableSensitive: boolean): boolean {
  for (const item of splitSelect(select)) {
    if (item === "*" && tableSensitive) return true;
    const m = REL_RE.exec(item);
    if (m?.[1] !== undefined) {
      const inner = item.slice(item.indexOf("(") + 1, item.lastIndexOf(")"));
      if (selectHasSensitiveStar(inner, isSensitive(m[1]))) return true;
    }
  }
  return false;
}

interface Query {
  /** Offset where the query expression starts (root identifier or `.from`). */
  start: number;
  /** Offset of the `(` of `.select(` / `.findX(` / `.select()`; its line is reported. */
  at: number;
  shape: "supabase" | "orm";
}

interface Binding {
  pattern: string;
  initStart: number;
  initEnd: number;
  /** Elements of `Promise.all([...])`, as offset ranges; undefined for a plain `await q`. */
  elements?: Array<[number, number]>;
  patternItems?: string[];
}

const BINDING_RE =
  /\b(?:const|let)\s+(\{[^=;]*\}|\[[^=;]*\]|[A-Za-z_$][\w$]*)\s*(?::\s*[^=;]+?)?\s*=\s*await\s+/g;
const PROMISE_ALL_RE = /^Promise\s*\.\s*all\s*\(\s*\[/;

function findBindings(src: JsSource): Binding[] {
  const out: Binding[] = [];
  const code = src.code;
  BINDING_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = BINDING_RE.exec(code)) !== null) {
    const initStart = m.index + m[0].length;
    const patStart = m.index + (/^(?:const|let)\s+/.exec(m[0])?.[0].length ?? 0);
    const pattern = src.text.slice(patStart, patStart + (m[1] ?? "").length);
    const all = PROMISE_ALL_RE.exec(code.slice(initStart, initStart + 40));
    if (all) {
      const open = initStart + all[0].length - 1;
      const close = src.matchOf(open);
      if (close < 0) continue;
      const elements = splitTop(code, open + 1, close);
      const p = pattern.trim();
      if (!p.startsWith("[")) continue;
      const items = splitTop(code, patStart + 1, patStart + p.length - 1).map(([a, b]) =>
        src.text.slice(a, b).trim(),
      );
      if (items.length !== elements.length) continue;
      out.push({ pattern, initStart, initEnd: close + 1, elements, patternItems: items });
    } else {
      out.push({ pattern, initStart, initEnd: expressionEnd(src, initStart) });
    }
  }
  return out;
}

/** Name the bound value goes by, or undefined when the pattern is not understood. */
function boundName(pattern: string, shape: "supabase" | "orm"): string | undefined {
  const p = pattern.trim();
  if (/^[A-Za-z_$][\w$]*$/.test(p)) return shape === "supabase" ? `${p}.data` : p;
  if (shape === "orm" || !p.startsWith("{")) return undefined;
  const renamed = /\bdata\s*:\s*([A-Za-z_$][\w$]*)\s*(?:[,}]|$)/.exec(p);
  if (renamed?.[1] !== undefined) return renamed[1];
  if (/[{,]\s*data\s*(?:[,}])/.test(p)) return "data";
  return undefined;
}

function collectQueries(src: JsSource): Array<Query & { table: string; full: boolean }> {
  const { code, text } = src;
  const out: Array<Query & { table: string; full: boolean }> = [];

  // Supabase
  const fromRe = /\.from\s*\(\s*(["'`])/g;
  let m: RegExpExecArray | null;
  while ((m = fromRe.exec(code)) !== null) {
    const litStart = m.index + m[0].length;
    const q = m[1] ?? '"';
    const litEnd = text.indexOf(q, litStart);
    if (litEnd < 0 || litEnd - litStart > 80) continue;
    const table = text.slice(litStart, litEnd);
    if (/[$\n]/.test(table)) continue;
    const win = code.slice(litEnd, litEnd + WINDOW);
    const stop = win.indexOf(";");
    const chain = stop >= 0 ? win.slice(0, stop) : win;
    const sel = /\.select\s*\(/.exec(chain);
    if (!sel) continue;
    const open = litEnd + sel.index + sel[0].length - 1;
    const close = src.matchOf(open);
    if (close < 0) continue;
    const argsCode = code.slice(open + 1, close);
    let full = false;
    if (argsCode.trim() === "") full = true;
    else {
      const first = /^\s*(["'`])/.exec(argsCode);
      if (!first) continue; // non-literal select argument
      const aStart = open + 1 + first[0].length;
      const aEnd = text.indexOf(first[1] ?? '"', aStart);
      if (aEnd < 0 || aEnd > close) continue;
      const argText = text.slice(aStart, aEnd);
      if (argText.includes("${")) continue;
      full = selectHasSensitiveStar(argText, isSensitive(table));
    }
    if (!full) continue;
    // The no-argument form only counts for a sensitive base table; nested relations need args.
    if (argsCode.trim() === "" && !isSensitive(table)) continue;
    out.push({ start: m.index, at: open, shape: "supabase", table, full });
  }

  // Prisma
  const prismaRe =
    /\b([A-Za-z_$][\w$]*)\s*\.\s*([A-Za-z_$][\w$]*)\s*\.\s*(?:findUniqueOrThrow|findUnique|findFirstOrThrow|findFirst|findMany)\s*\(/g;
  while ((m = prismaRe.exec(code)) !== null) {
    const model = m[2] ?? "";
    if (m[1] === "query") continue; // Drizzle relational API, handled below
    if (!isSensitive(model)) continue;
    const open = m.index + m[0].length - 1;
    const close = src.matchOf(open);
    if (close < 0) continue;
    const args = code.slice(open + 1, close).trim();
    if (args !== "" && !args.startsWith("{")) continue;
    if (
      args !== "" &&
      hasTopLevelKey(src, open + 1 + code.slice(open + 1).indexOf("{"), ["select", "omit"])
    )
      continue;
    out.push({ start: m.index, at: open, shape: "orm", table: model, full: true });
  }

  // Drizzle
  const dSelect = /\.select\s*\(\s*\)\s*\.from\s*\(\s*([A-Za-z_$][\w$]*)\s*\)/g;
  while ((m = dSelect.exec(code)) !== null) {
    if (!isSensitive(m[1] ?? "")) continue;
    out.push({
      start: m.index,
      at: m.index + m[0].indexOf("("),
      shape: "orm",
      table: m[1] ?? "",
      full: true,
    });
  }
  const dQuery = /\.query\s*\.\s*([A-Za-z_$][\w$]*)\s*\.\s*(?:findFirst|findMany)\s*\(/g;
  while ((m = dQuery.exec(code)) !== null) {
    if (!isSensitive(m[1] ?? "")) continue;
    const open = m.index + m[0].length - 1;
    const close = src.matchOf(open);
    if (close < 0) continue;
    const args = code.slice(open + 1, close).trim();
    if (args !== "" && !args.startsWith("{")) continue;
    if (
      args !== "" &&
      hasTopLevelKey(src, open + 1 + code.slice(open + 1).indexOf("{"), ["columns"])
    )
      continue;
    out.push({ start: m.index, at: open, shape: "orm", table: m[1] ?? "", full: true });
  }
  return out;
}

/** True when the object literal at `brace` has a top-level key in `keys` (or a spread). */
function hasTopLevelKey(src: JsSource, brace: number, keys: string[]): boolean {
  const close = src.matchOf(brace);
  if (close < 0) return true; // unknown shape: do not report
  for (const [a, b] of splitTop(src.code, brace + 1, close)) {
    const item = src.text.slice(a, b).trim();
    if (item.startsWith("...")) return true;
    const k = /^["'`]?([\w$]+)["'`]?\s*(?::|$)/.exec(item);
    if (k?.[1] !== undefined && keys.includes(k[1])) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Imports and component resolution
// ---------------------------------------------------------------------------

function importMap(src: JsSource): Map<string, string> {
  const map = new Map<string, string>();
  const re = /\bimport\s+(?!type\b)([^;]*?)\s*\bfrom\s*(["'])/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src.code)) !== null) {
    const specStart = m.index + m[0].length;
    const specEnd = src.text.indexOf(m[2] ?? '"', specStart);
    if (specEnd < 0) continue;
    const spec = src.text.slice(specStart, specEnd);
    const clauseStart = m.index + (/^import\s+/.exec(m[0])?.[0].length ?? 0);
    const clause = src.text.slice(clauseStart, clauseStart + (m[1] ?? "").length);
    const braceAt = clause.indexOf("{");
    const head = braceAt >= 0 ? clause.slice(0, braceAt) : clause;
    const def = /^\s*([A-Za-z_$][\w$]*)\s*,?\s*$/.exec(head);
    if (def?.[1] !== undefined) map.set(def[1], spec);
    if (braceAt >= 0) {
      const inner = clause.slice(braceAt + 1, clause.lastIndexOf("}"));
      for (const item of inner.split(",")) {
        const it = item.trim();
        if (!it || /^type\s/.test(it)) continue;
        const parts = /^(?:[\w$]+\s+as\s+)?([\w$]+)$/.exec(it);
        if (parts?.[1] !== undefined) map.set(parts[1], spec);
      }
    }
  }
  return map;
}

const SUFFIXES = [
  "",
  ".tsx",
  ".ts",
  ".jsx",
  ".js",
  "/index.tsx",
  "/index.ts",
  "/index.jsx",
  "/index.js",
];
const USE_CLIENT_RE = /^﻿?(?:\s|\/\/[^\n]*(?:\n|$)|\/\*[\s\S]*?\*\/)*["']use client["']/;

async function isClientComponent(
  context: ScanContext,
  fromFile: string,
  spec: string,
): Promise<boolean> {
  const bases: string[] = [];
  if (spec.startsWith("./") || spec.startsWith("../")) {
    bases.push(path.posix.normalize(path.posix.join(path.posix.dirname(fromFile), spec)));
  } else if (spec.startsWith("@/") || spec.startsWith("~/")) {
    const rest = spec.slice(2);
    bases.push(rest, `src/${rest}`);
  } else return false;
  for (const base of bases) {
    for (const suffix of SUFFIXES) {
      let content = "";
      try {
        content = await context.readFile(base + suffix);
      } catch {
        content = "";
      }
      if (content.trim() !== "") return USE_CLIENT_RE.test(content);
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Hand-off search
// ---------------------------------------------------------------------------

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Tag names (capitalised components) that receive `name` as an attribute value or spread. */
function jsxTargets(src: JsSource, name: string, from: number, to: number): string[] {
  const n = escapeRe(name);
  const re = new RegExp(
    String.raw`=\s*\{\s*${n}\s*(?:\?\?\s*null\s*|!\s*)?\}|\{\s*\.\.\.\s*${n}\s*\}`,
    "g",
  );
  const region = src.code.slice(from, to);
  const found: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(region)) !== null) {
    const at = from + m.index;
    const tag = owningTag(src, at);
    if (tag !== undefined && !found.includes(tag)) found.push(tag);
  }
  return found;
}

function owningTag(src: JsSource, attrAt: number): string | undefined {
  const code = src.code;
  const lowest = Math.max(0, attrAt - TAG_WALK_BACK);
  for (let i = attrAt - 1; i >= lowest; i--) {
    const c = code[i];
    if (c === "}") {
      const open = src.matchOf(i);
      if (open < 0) return undefined;
      i = open;
      continue;
    }
    if (c === ">") return undefined; // the tag closed before the attribute
    if (c === "<") {
      const m = /^<([A-Za-z_$][\w$]*)/.exec(code.slice(i, i + 80));
      if (!m?.[1]) return undefined;
      return /^[A-Z]/.test(m[1]) ? m[1] : undefined;
    }
  }
  return undefined;
}

/** True when `return { props: { ... } }` inside [from,to) carries `name` as a whole value. */
function propsCarry(src: JsSource, name: string, from: number, to: number): boolean {
  const re = /\bprops\s*:\s*\{/g;
  const region = src.code.slice(from, to);
  let m: RegExpExecArray | null;
  while ((m = re.exec(region)) !== null) {
    const open = from + m.index + m[0].length - 1;
    const close = src.matchOf(open);
    if (close < 0) continue;
    for (const [a, b] of splitTop(src.code, open + 1, close)) {
      const entry = src.code.slice(a, b).trim();
      const rhs = entry.includes(":") ? entry.slice(entry.indexOf(":") + 1).trim() : entry;
      const clean = rhs
        .replace(/\s*\?\?\s*null\s*$/, "")
        .replace(/!\s*$/, "")
        .trim();
      if (clean === name) return true;
    }
  }
  return false;
}

export class ServerDataExposureDetector implements Detector {
  id = "server-data-exposure-detector";
  name = "Server Data Exposure";
  category = "frontend_exposure" as const;
  description =
    "Detects whole rows of sensitive tables (users, profiles, members) loaded on the server and passed to client components or page props.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of context.files) {
      try {
        if (!isJsLike(file)) continue;
        const src = await getJsSource(context, file);
        const text = src.text;
        if (!text) continue;
        if (!(text.includes(".from(") || text.includes(".find") || text.includes(".query.")))
          continue;
        if (!(text.includes("<") || text.includes("props"))) continue;
        if (isGenerated(file, text)) continue;
        const cls = classifyFile(file, text, context.projectContext);
        if (cls.kind !== "next-server-component" && cls.kind !== "next-pages-page") continue;
        findings.push(...(await this.scanFile(context, file, src, cls.kind)));
      } catch {
        // Never throw from a detector.
      }
    }
    return findings;
  }

  private async scanFile(
    context: ScanContext,
    file: string,
    src: JsSource,
    kind: "next-server-component" | "next-pages-page",
  ): Promise<Finding[]> {
    const out: Finding[] = [];
    const seen = new Set<string>();
    const spans = extractFunctions(src, { kind });
    const bindings = findBindings(src);
    const imports = kind === "next-server-component" ? importMap(src) : new Map<string, string>();
    const clientCache = new Map<string, boolean>();

    for (const q of collectQueries(src)) {
      if (out.length >= MAX_FINDINGS_PER_FILE) break;
      const owner = enclosingFunction(spans, q.start);
      if (kind === "next-pages-page" && !inPropsFetcher(owner)) continue;

      // Bind the result.
      let name: string | undefined;
      let initEnd = q.start;
      for (const b of bindings) {
        if (q.start < b.initStart || q.start >= b.initEnd) continue;
        if (b.elements && b.patternItems) {
          const idx = b.elements.findIndex(([a, e]) => q.start >= a && q.start < e);
          const item = b.patternItems[idx];
          if (idx < 0 || item === undefined) continue;
          name = boundName(item, q.shape);
        } else {
          const prefix = src.code.slice(b.initStart, q.start);
          const opens = (prefix.match(/\(/g) ?? []).length;
          const closes = (prefix.match(/\)/g) ?? []).length;
          if (opens !== closes || /[;{}]/.test(prefix)) continue;
          name = boundName(b.pattern, q.shape);
        }
        initEnd = b.initEnd;
        break;
      }
      if (name === undefined) continue;

      const limit = owner?.end ?? src.text.length;
      const targets: string[] = [];
      if (kind === "next-pages-page") {
        if (propsCarry(src, name, initEnd, limit)) targets.push("props");
      } else {
        for (const tag of jsxTargets(src, name, initEnd, limit)) {
          const spec = imports.get(tag);
          if (spec === undefined) continue;
          const key = `${file}|${spec}`;
          let client = clientCache.get(key);
          if (client === undefined) {
            client = await isClientComponent(context, file, spec);
            clientCache.set(key, client);
          }
          if (client) targets.push(tag);
        }
      }

      const line = src.lineAt(q.at);
      for (const target of targets) {
        const key = `${line}|${name}->${target}`;
        if (seen.has(key) || out.length >= MAX_FINDINGS_PER_FILE) continue;
        seen.add(key);
        out.push(this.finding(file, line, src.lineText(line), q.table, name, target));
      }
    }
    return out;
  }

  private finding(
    file: string,
    line: number,
    evidence: string,
    table: string,
    name: string,
    target: string,
  ): Finding {
    const to = target === "props" ? "the page props" : `the client component <${target}>`;
    return makeFinding({
      category: "frontend_exposure",
      ruleId: "frontend_exposure/full-row-client-prop",
      title: "Whole database rows are passed to the browser",
      severity: "medium",
      confidence: "medium",
      file,
      line,
      evidence,
      discriminator: `${name}->${target}`,
      plainEnglishProblem: `Every column of "${normalizeName(table)}" rows (loaded as \`${name}\`) is passed to ${to}, because the query selects all columns instead of the few that are needed.`,
      whyItMatters:
        "React serializes every prop of a client component into the page payload, so internal columns (admin flags, billing ids, columns added later) become visible to anyone in the browser.",
      fixSteps: [
        "Select only the columns the component renders (for example `select('id, name')`, a Prisma `select`, or Drizzle `columns`).",
        "Or map the row to a small object (DTO) before passing it down.",
        "Keep data access in server-only helpers (`import 'server-only'`) so full rows cannot be passed by accident.",
      ],
      aiFixPrompt: AI_FIX_PROMPT,
    });
  }
}

function inPropsFetcher(span: FunctionSpan | undefined): boolean {
  for (let s = span; s !== undefined; s = s.parent) {
    const names = [s.name, ...s.exportNames];
    if (names.some((n) => n === "getServerSideProps" || n === "getStaticProps")) return true;
  }
  return false;
}
