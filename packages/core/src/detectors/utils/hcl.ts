/**
 * A tolerant, line-based HCL (Terraform) reader. It is not a full HCL parser: it finds
 * blocks and `name = value` attributes with their line numbers, keeps attribute values
 * as raw text and offers a few helpers to read literals and IAM policy statements.
 * Strings (including `${...}`), `#`, `//` and block comments and heredocs are skipped
 * when tracking brace depth. Nothing here throws, and every loop advances the cursor.
 */

export interface HclAttr {
  name: string;
  /** Raw value text (not interpreted), capped at {@link MAX_VALUE_CHARS}. */
  value: string;
  /** 1-based line of the attribute name. */
  line: number;
  /** 1-based line where the value ends. */
  endLine: number;
}

export interface HclBlock {
  type: string;
  labels: string[];
  /** 1-based line of the block type. */
  line: number;
  /** 1-based line of the closing brace (or the last line when unterminated). */
  endLine: number;
  attrs: HclAttr[];
  blocks: HclBlock[];
}

const MAX_VALUE_CHARS = 16000;
const MAX_DEPTH = 24;
const MAX_INPUT_CHARS = 2_000_000;

function lineStartsOf(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
  return starts;
}

function lineAtOffset(starts: readonly number[], offset: number): number {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if ((starts[mid] ?? 0) <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

const IDENT_START_RE = /[A-Za-z_]/;
const IDENT_RE = /[A-Za-z0-9_.-]/;

class Reader {
  pos = 0;
  readonly starts: number[];
  constructor(readonly src: string) {
    this.starts = lineStartsOf(src);
  }

  line(offset: number): number {
    return lineAtOffset(this.starts, offset);
  }

  /** Skips spaces, tabs and comments on the current line; returns false at a newline or EOF. */
  skipInline(): void {
    const s = this.src;
    for (;;) {
      const c = s[this.pos];
      if (c === " " || c === "\t" || c === "\r") this.pos++;
      else if (c === "/" && s[this.pos + 1] === "*") this.skipBlockComment();
      else break;
    }
  }

  skipBlockComment(): void {
    const end = this.src.indexOf("*/", this.pos + 2);
    this.pos = end === -1 ? this.src.length : end + 2;
  }

  skipLineComment(): void {
    const nl = this.src.indexOf("\n", this.pos);
    this.pos = nl === -1 ? this.src.length : nl;
  }

  /** Skips whitespace, newlines and comments between statements. */
  skipTrivia(): void {
    const s = this.src;
    while (this.pos < s.length) {
      const c = s[this.pos];
      if (c === " " || c === "\t" || c === "\r" || c === "\n" || c === ",") this.pos++;
      else if (c === "#" || (c === "/" && s[this.pos + 1] === "/")) this.skipLineComment();
      else if (c === "/" && s[this.pos + 1] === "*") this.skipBlockComment();
      else break;
    }
  }

  /** Skips a quoted string starting at pos (on the opening quote), honouring `${...}`. */
  skipString(): void {
    const s = this.src;
    this.pos++;
    while (this.pos < s.length) {
      const c = s[this.pos];
      if (c === "\\") this.pos += 2;
      else if (c === '"') {
        this.pos++;
        return;
      } else if (c === "\n") {
        // Unterminated string: stop at the end of the line.
        return;
      } else if ((c === "$" || c === "%") && s[this.pos + 1] === "{") {
        this.pos += 2;
        this.skipInterpolation();
      } else this.pos++;
    }
  }

  /** Skips to the matching `}` of an interpolation (pos is just after `${`). */
  skipInterpolation(): void {
    const s = this.src;
    let depth = 1;
    while (this.pos < s.length && depth > 0) {
      const c = s[this.pos];
      if (c === '"') this.skipString();
      else {
        if (c === "{") depth++;
        else if (c === "}") depth--;
        this.pos++;
      }
    }
  }

  /** Heredoc start at pos (`<<EOF`, `<<-EOT`)? Returns the delimiter or undefined. */
  heredocDelimiter(): string | undefined {
    const m = /^<<-?\s*([A-Za-z_][A-Za-z0-9_]*)[ \t]*\r?$/m.exec(
      this.src.slice(this.pos, this.pos + 200),
    );
    return m && m.index === 0 ? m[1] : undefined;
  }

  /** Skips a heredoc whose `<<` is at pos, through the closing delimiter line. */
  skipHeredoc(delimiter: string): void {
    const s = this.src;
    let nl = s.indexOf("\n", this.pos);
    while (nl !== -1) {
      const lineStart = nl + 1;
      let lineEnd = s.indexOf("\n", lineStart);
      if (lineEnd === -1) lineEnd = s.length;
      if (s.slice(lineStart, lineEnd).trim() === delimiter) {
        this.pos = lineEnd;
        return;
      }
      nl = s.indexOf("\n", lineStart);
    }
    this.pos = s.length;
  }

  /** Reads an attribute value starting at pos; stops at the end of the statement. */
  readValue(): { raw: string; start: number; end: number } {
    const s = this.src;
    this.skipInline();
    const start = this.pos;
    let depth = 0;
    while (this.pos < s.length) {
      const c = s[this.pos];
      if (c === '"') this.skipString();
      else if (c === "#" || (c === "/" && s[this.pos + 1] === "/")) {
        this.skipLineComment();
      } else if (c === "/" && s[this.pos + 1] === "*") this.skipBlockComment();
      else if (c === "<" && s[this.pos + 1] === "<") {
        const delim = this.heredocDelimiter();
        if (delim !== undefined) this.skipHeredoc(delim);
        else this.pos += 2;
        if (depth === 0) break;
      } else if (c === "{" || c === "[" || c === "(") {
        depth++;
        this.pos++;
      } else if (c === "}" || c === "]" || c === ")") {
        if (depth === 0) break; // closes the parent block (single-line block body)
        depth--;
        this.pos++;
      } else if (c === "\n") {
        if (depth <= 0) break;
        this.pos++;
      } else this.pos++;
    }
    const end = this.pos;
    let raw = s.slice(start, end);
    // A trailing comment is not part of the value.
    raw = raw.replace(/\s+$/, "");
    if (raw.length > MAX_VALUE_CHARS) raw = raw.slice(0, MAX_VALUE_CHARS);
    return { raw, start, end: start + raw.length };
  }
}

/** Reads a quoted label or bare identifier at pos. */
function readWord(r: Reader): string | undefined {
  const s = r.src;
  const c = s[r.pos];
  if (c === '"') {
    const start = r.pos + 1;
    r.skipString();
    const end = s[r.pos - 1] === '"' ? r.pos - 1 : r.pos;
    return s.slice(start, end);
  }
  if (c !== undefined && IDENT_START_RE.test(c)) {
    const start = r.pos;
    while (r.pos < s.length && IDENT_RE.test(s[r.pos] ?? "")) r.pos++;
    return s.slice(start, r.pos);
  }
  return undefined;
}

function parseBody(r: Reader, depth: number): { attrs: HclAttr[]; blocks: HclBlock[] } {
  const attrs: HclAttr[] = [];
  const blocks: HclBlock[] = [];
  const s = r.src;
  while (r.pos < s.length) {
    r.skipTrivia();
    if (r.pos >= s.length) break;
    if (s[r.pos] === "}") {
      return { attrs, blocks };
    }
    const startPos = r.pos;
    const first = readWord(r);
    if (first === undefined) {
      // Stray token: skip to the end of the line.
      const nl = s.indexOf("\n", r.pos);
      r.pos = nl === -1 ? s.length : nl;
      if (r.pos === startPos) r.pos++;
      continue;
    }
    const line = r.line(startPos);
    r.skipInline();
    if (s[r.pos] === "=" && s[r.pos + 1] !== "=" && s[r.pos + 1] !== ">") {
      r.pos++;
      const v = r.readValue();
      attrs.push({
        name: first,
        value: v.raw,
        line,
        endLine: r.line(Math.max(startPos, v.end > 0 ? v.end - 1 : 0)),
      });
      continue;
    }
    // Block: labels until `{`.
    const labels: string[] = [];
    for (;;) {
      r.skipInline();
      const c = s[r.pos];
      if (c === "{" || c === undefined || c === "\n") break;
      const w = readWord(r);
      if (w === undefined) break;
      labels.push(w);
    }
    if (s[r.pos] !== "{") {
      const nl = s.indexOf("\n", r.pos);
      r.pos = nl === -1 ? s.length : nl;
      continue;
    }
    r.pos++;
    if (depth >= MAX_DEPTH) {
      // Too deep: skip the body without interpreting it.
      let d = 1;
      while (r.pos < s.length && d > 0) {
        const c = s[r.pos];
        if (c === '"') r.skipString();
        else {
          if (c === "{") d++;
          else if (c === "}") d--;
          r.pos++;
        }
      }
      continue;
    }
    const body = parseBody(r, depth + 1);
    const closeAt = s[r.pos] === "}" ? r.pos : Math.max(0, s.length - 1);
    if (s[r.pos] === "}") r.pos++;
    blocks.push({
      type: first,
      labels,
      line,
      endLine: r.line(closeAt),
      attrs: body.attrs,
      blocks: body.blocks,
    });
  }
  return { attrs, blocks };
}

/** Parses HCL text into its top-level blocks (and nested blocks/attributes). Never throws. */
export function parseHcl(text: string): HclBlock[] {
  try {
    const src = text.length > MAX_INPUT_CHARS ? text.slice(0, MAX_INPUT_CHARS) : text;
    const r = new Reader(src);
    const top: HclBlock[] = [];
    // Top-level attributes are wrapped in a pseudo block so `.tfvars` can be read too.
    const pseudo: HclBlock = {
      type: "",
      labels: [],
      line: 1,
      endLine: r.starts.length,
      attrs: [],
      blocks: [],
    };
    while (r.pos < src.length) {
      const body = parseBody(r, 0);
      pseudo.attrs.push(...body.attrs);
      top.push(...body.blocks);
      if (r.pos < src.length) r.pos++; // stray `}` at top level
    }
    return pseudo.attrs.length > 0 ? [pseudo, ...top] : top;
  } catch {
    return [];
  }
}

/** The top-level `name = value` attributes of a file (`.tfvars`), from {@link parseHcl}. */
export function topLevelAttrs(blocks: readonly HclBlock[]): HclAttr[] {
  return blocks.filter((b) => b.type === "").flatMap((b) => b.attrs);
}

/** Every attribute of a block and its nested blocks, depth first. */
export function allAttrs(block: HclBlock): HclAttr[] {
  const out: HclAttr[] = [...block.attrs];
  for (const b of block.blocks) out.push(...allAttrs(b));
  return out;
}

export function attrOf(block: HclBlock, name: string): HclAttr | undefined {
  return block.attrs.find((a) => a.name === name);
}

// ─── Literals ────────────────────────────────────────────────────────────────

function unescapeHcl(inner: string): string {
  return inner.replace(/\\(["\\nt])/g, (_m, c: string) =>
    c === "n" ? "\n" : c === "t" ? "\t" : c,
  );
}

/** Splits a quoted string at the start of `v` and returns its inner text, or undefined. */
function quotedInner(v: string): string | undefined {
  if (!v.startsWith('"')) return undefined;
  for (let i = 1; i < v.length; i++) {
    const c = v[i];
    if (c === "\\") i++;
    else if (c === '"') return i === v.length - 1 ? v.slice(1, i) : undefined;
  }
  return undefined;
}

/**
 * The value of a pure string literal, or undefined when the value is an expression,
 * contains `${...}` / `%{...}` interpolation, or is not a quoted string.
 */
export function hclString(value: string): string | undefined {
  const inner = quotedInner(value.trim());
  if (inner === undefined) return undefined;
  if (inner.includes("${") || inner.includes("%{")) return undefined;
  return unescapeHcl(inner);
}

/**
 * Like {@link hclString} but keeps interpolations, replacing each `${...}` with `placeholder`.
 * Used where the shape of the value matters more than the interpolated part.
 */
export function hclStringShape(value: string, placeholder = "ORG"): string | undefined {
  const inner = quotedInner(value.trim());
  if (inner === undefined) return undefined;
  let out = "";
  for (let i = 0; i < inner.length; i++) {
    const c = inner[i] ?? "";
    if ((c === "$" || c === "%") && inner[i + 1] === "{") {
      let depth = 1;
      i += 2;
      while (i < inner.length && depth > 0) {
        if (inner[i] === "{") depth++;
        else if (inner[i] === "}") depth--;
        i++;
      }
      i--;
      out += placeholder;
    } else out += c;
  }
  return unescapeHcl(out);
}

/** `true` / `false` literals only. */
export function hclBool(value: string): boolean | undefined {
  const v = value.trim();
  if (v === "true") return true;
  if (v === "false") return false;
  return undefined;
}

/**
 * The string literals of a `[...]` list (non-literal elements are dropped), or undefined
 * when the value is not a list. A lone string literal is returned as a one-item list.
 */
export function hclStringList(value: string): string[] | undefined {
  const v = value.trim();
  if (v.startsWith('"')) {
    const one = hclString(v);
    return one === undefined ? undefined : [one];
  }
  if (!v.startsWith("[")) return undefined;
  const nodes = parseExpr(v, 0);
  if (nodes.kind !== "list") return undefined;
  const out: string[] = [];
  for (const item of nodes.items) {
    if (item.kind === "str" && !item.text.includes("${")) out.push(item.text);
  }
  return out;
}

/**
 * Like {@link hclStringList} but keeps interpolated strings and non-literal items
 * (references) as their raw text, so callers can still see what a list refers to.
 */
export function hclStringListLoose(value: string): string[] {
  const v = value.trim();
  if (v.startsWith('"')) return [hclStringShape(v, "${x}") ?? v];
  if (!v.startsWith("[")) return v === "" ? [] : [v];
  const nodes = parseExpr(v, 0);
  if (nodes.kind !== "list") return [v];
  const out: string[] = [];
  for (const item of nodes.items) {
    if (item.kind === "str" || item.kind === "raw") out.push(item.text);
  }
  return out;
}

// ─── Expression mini parser (objects, lists, strings) ───────────────────────

export type HNode =
  | { kind: "str"; text: string; start: number; end: number }
  | { kind: "obj"; entries: HEntry[]; start: number; end: number }
  | { kind: "list"; items: HNode[]; start: number; end: number }
  | { kind: "raw"; text: string; start: number; end: number };

export interface HEntry {
  key: string;
  node: HNode;
  /** Offset of the key in the parsed text. */
  keyStart: number;
}

const EMPTY_NODE: HNode = { kind: "raw", text: "", start: 0, end: 0 };

class ExprParser {
  pos = 0;
  steps = 0;
  constructor(readonly s: string) {}

  trivia(): void {
    const s = this.s;
    while (this.pos < s.length) {
      const c = s[this.pos];
      if (c === " " || c === "\t" || c === "\r" || c === "\n" || c === ",") this.pos++;
      else if (c === "#" || (c === "/" && s[this.pos + 1] === "/")) {
        const nl = s.indexOf("\n", this.pos);
        this.pos = nl === -1 ? s.length : nl;
      } else if (c === "/" && s[this.pos + 1] === "*") {
        const e = s.indexOf("*/", this.pos + 2);
        this.pos = e === -1 ? s.length : e + 2;
      } else break;
    }
  }

  str(): HNode {
    const s = this.s;
    const start = this.pos;
    this.pos++;
    let text = "";
    while (this.pos < s.length) {
      const c = s[this.pos];
      if (c === "\\") {
        const n = s[this.pos + 1] ?? "";
        text += n === "n" ? "\n" : n === "t" ? "\t" : n;
        this.pos += 2;
      } else if (c === '"') {
        this.pos++;
        break;
      } else if ((c === "$" || c === "%") && s[this.pos + 1] === "{") {
        let depth = 1;
        const from = this.pos;
        this.pos += 2;
        while (this.pos < s.length && depth > 0) {
          if (s[this.pos] === "{") depth++;
          else if (s[this.pos] === "}") depth--;
          this.pos++;
        }
        text += s.slice(from, this.pos);
      } else {
        text += c;
        this.pos++;
      }
    }
    return { kind: "str", text, start, end: this.pos };
  }

  /** Reads an unparsed token (reference, number, function call) to the end of the element. */
  raw(): HNode {
    const s = this.s;
    const start = this.pos;
    let depth = 0;
    while (this.pos < s.length) {
      const c = s[this.pos];
      if (c === '"') this.str();
      else if (c === "(" || c === "[" || c === "{") {
        depth++;
        this.pos++;
      } else if (c === ")" || c === "]" || c === "}") {
        if (depth === 0) break;
        depth--;
        this.pos++;
      } else if ((c === "," || c === "\n") && depth === 0) break;
      else this.pos++;
    }
    return { kind: "raw", text: s.slice(start, this.pos).trim(), start, end: this.pos };
  }

  value(depth: number): HNode {
    this.trivia();
    const s = this.s;
    if (this.pos >= s.length || ++this.steps > 20000 || depth > 20) return EMPTY_NODE;
    const c = s[this.pos];
    const start = this.pos;
    if (c === '"') return this.str();
    if (c === "{") return this.obj(depth);
    if (c === "[") {
      this.pos++;
      const items: HNode[] = [];
      for (;;) {
        this.trivia();
        if (this.pos >= s.length) break;
        if (s[this.pos] === "]") {
          this.pos++;
          break;
        }
        const before = this.pos;
        items.push(this.value(depth + 1));
        if (this.pos === before) this.pos++;
      }
      return { kind: "list", items, start, end: this.pos };
    }
    const callee = /^[A-Za-z_][\w]*\(/.exec(s.slice(this.pos, this.pos + 64));
    if (
      callee &&
      (callee[0] === "jsonencode(" || callee[0] === "tolist(" || callee[0] === "tomap(")
    ) {
      this.pos += callee[0].length;
      const inner = this.value(depth + 1);
      this.trivia();
      if (s[this.pos] === ")") this.pos++;
      return inner;
    }
    return this.raw();
  }

  obj(depth: number): HNode {
    const s = this.s;
    const start = this.pos;
    this.pos++;
    const entries: HEntry[] = [];
    for (;;) {
      this.trivia();
      if (this.pos >= s.length) break;
      if (s[this.pos] === "}") {
        this.pos++;
        break;
      }
      const before = this.pos;
      const keyStart = this.pos;
      let key: string;
      if (s[this.pos] === '"') {
        const k = this.str();
        key = k.kind === "str" ? k.text : "";
      } else {
        const m = /^[A-Za-z_(][\w.\-:*()]*/.exec(s.slice(this.pos, this.pos + 200));
        key = m ? m[0] : "";
        this.pos += m ? m[0].length : 0;
      }
      while (s[this.pos] === " " || s[this.pos] === "\t") this.pos++;
      if (s[this.pos] === "=" || s[this.pos] === ":") {
        this.pos++;
        entries.push({ key, node: this.value(depth + 1), keyStart });
      } else if (this.pos === before) this.pos++;
    }
    return { kind: "obj", entries, start, end: this.pos };
  }
}

/** Parses an HCL/JSON value (object, list, string) found at `text`. Never throws. */
export function parseExpr(text: string, depth = 0): HNode {
  try {
    return new ExprParser(text).value(depth);
  } catch {
    return EMPTY_NODE;
  }
}

function lines(text: string, offset: number, baseLine: number): number {
  let n = baseLine;
  const stop = Math.min(offset, text.length);
  for (let i = 0; i < stop; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
}

// ─── IAM policy statements ──────────────────────────────────────────────────

export interface PolicyCondition {
  operator: string;
  key: string;
  values: string[];
  line: number;
}

export interface PolicyStatement {
  /** `Allow` / `Deny` (capitalised as written; empty when absent). */
  effect: string;
  actions: string[];
  notActions: string[];
  resources: string[];
  /** Principal identifiers of every type (`*`, ARNs, service names, references). */
  principals: string[];
  /** Federated principal values (OIDC provider ARNs or references). */
  federated: string[];
  /** Raw text of the condition(s); empty when the statement has none. */
  conditions: string;
  conditionEntries: PolicyCondition[];
  /** Line of the statement start. */
  line: number;
  endLine: number;
  actionLine: number;
  resourceLine: number;
  principalLine: number;
}

function strings(node: HNode | undefined): string[] {
  if (!node) return [];
  if (node.kind === "str") return [node.text];
  if (node.kind === "raw") return node.text === "" ? [] : [node.text];
  if (node.kind === "list") return node.items.flatMap((i) => strings(i));
  return [];
}

function pick(entries: HEntry[], ...names: string[]): HEntry | undefined {
  return entries.find((e) => names.includes(e.key));
}

function statementFromJson(
  node: HNode,
  text: string,
  baseLine: number,
): PolicyStatement | undefined {
  if (node.kind !== "obj") return undefined;
  const e = node.entries;
  const at = (entry: HEntry | undefined): number =>
    lines(text, entry ? entry.keyStart : node.start, baseLine);
  const principalEntry = pick(e, "Principal", "principal");
  const principals: string[] = [];
  const federated: string[] = [];
  if (principalEntry) {
    const p = principalEntry.node;
    if (p.kind === "str" || p.kind === "raw") principals.push(...strings(p));
    else if (p.kind === "obj") {
      for (const sub of p.entries) {
        const vals = strings(sub.node);
        principals.push(...vals);
        if (sub.key === "Federated") federated.push(...vals);
      }
    }
  }
  const conditionEntry = pick(e, "Condition", "condition");
  const conditionEntries: PolicyCondition[] = [];
  let conditions = "";
  if (conditionEntry && conditionEntry.node.kind === "obj") {
    conditions = text.slice(conditionEntry.node.start, conditionEntry.node.end);
    for (const op of conditionEntry.node.entries) {
      if (op.node.kind !== "obj") continue;
      for (const k of op.node.entries) {
        conditionEntries.push({
          operator: op.key,
          key: k.key,
          values: strings(k.node),
          line: lines(text, k.keyStart, baseLine),
        });
      }
    }
  }
  const actionEntry = pick(e, "Action", "action");
  const resourceEntry = pick(e, "Resource", "resource");
  return {
    effect: strings(pick(e, "Effect", "effect")?.node)[0] ?? "",
    actions: strings(actionEntry?.node),
    notActions: strings(pick(e, "NotAction", "notAction")?.node),
    resources: strings(resourceEntry?.node),
    principals,
    federated,
    conditions,
    conditionEntries,
    line: lines(text, node.start, baseLine),
    endLine: lines(text, node.end, baseLine),
    actionLine: at(actionEntry ?? pick(e, "NotAction", "notAction")),
    resourceLine: at(resourceEntry),
    principalLine: at(principalEntry),
  };
}

/** Extracts the JSON/HCL policy text of an attribute (jsonencode, quoted JSON or heredoc). */
function policyText(attr: HclAttr): { text: string; baseLine: number } {
  const v = attr.value.trim();
  const heredoc = /^<<-?\s*([A-Za-z_]\w*)[ \t]*\r?\n([\s\S]*?)\r?\n[ \t]*\1[ \t]*$/.exec(v);
  if (heredoc) return { text: heredoc[2] ?? "", baseLine: attr.line + 1 };
  return { text: v, baseLine: attr.line };
}

/** Policy statements of a `policy`/`assume_role_policy` attribute value. */
function statementsOfAttr(attr: HclAttr): PolicyStatement[] {
  const { text, baseLine } = policyText(attr);
  let root = parseExpr(text);
  if (root.kind === "str") {
    // Quoted JSON string: parse its content.
    const inner = root.text;
    root = parseExpr(inner);
    return collect(root, inner, baseLine);
  }
  return collect(root, text, baseLine);
}

function collect(root: HNode, text: string, baseLine: number): PolicyStatement[] {
  if (root.kind !== "obj") return [];
  const stmtEntry = pick(root.entries, "Statement", "statement");
  if (!stmtEntry) return [];
  const nodes = stmtEntry.node.kind === "list" ? stmtEntry.node.items : [stmtEntry.node];
  const out: PolicyStatement[] = [];
  for (const n of nodes) {
    const st = statementFromJson(n, text, baseLine);
    if (st) out.push(st);
  }
  return out;
}

function statementsOfDocument(block: HclBlock): PolicyStatement[] {
  const out: PolicyStatement[] = [];
  for (const st of block.blocks.filter((b) => b.type === "statement")) {
    const val = (name: string): string =>
      hclString(attrOf(st, name)?.value ?? "") ?? attrOf(st, name)?.value.trim() ?? "";
    const list = (name: string): string[] => {
      const a = attrOf(st, name);
      return a ? (hclStringList(a.value) ?? [a.value.trim()]) : [];
    };
    const principals: string[] = [];
    const federated: string[] = [];
    let principalLine = st.line;
    for (const p of st.blocks.filter((b) => b.type === "principals")) {
      const ids = attrOf(p, "identifiers");
      const vals = ids ? hclStringListLoose(ids.value) : [];
      principals.push(...vals);
      if (hclString(attrOf(p, "type")?.value ?? "") === "Federated") federated.push(...vals);
      principalLine = ids?.line ?? p.line;
    }
    const conditionEntries: PolicyCondition[] = [];
    for (const c of st.blocks.filter((b) => b.type === "condition")) {
      const variable = attrOf(c, "variable");
      conditionEntries.push({
        operator: hclString(attrOf(c, "test")?.value ?? "") ?? "",
        key: hclStringShape(variable?.value ?? "") ?? variable?.value.trim() ?? "",
        values: hclStringListLoose(attrOf(c, "values")?.value ?? ""),
        line: attrOf(c, "values")?.line ?? c.line,
      });
    }
    out.push({
      effect: val("effect") === "" ? "Allow" : val("effect"),
      actions: list("actions"),
      notActions: list("not_actions"),
      resources: list("resources"),
      principals,
      federated,
      conditions: conditionEntries.length > 0 ? "condition" : "",
      conditionEntries,
      line: st.line,
      endLine: st.endLine,
      actionLine: (attrOf(st, "actions") ?? attrOf(st, "not_actions"))?.line ?? st.line,
      resourceLine: attrOf(st, "resources")?.line ?? st.line,
      principalLine,
    });
  }
  return out;
}

/**
 * Policy statements of an attribute (`jsonencode({...})`, a quoted JSON string or a
 * heredoc) or of a `data "aws_iam_policy_document"` block. Each key carries its source
 * line. Never throws.
 */
export function policyStatements(source: HclAttr | HclBlock): PolicyStatement[] {
  try {
    if ("attrs" in source) return statementsOfDocument(source);
    return statementsOfAttr(source);
  } catch {
    return [];
  }
}
