export type TomlValue =
  | { kind: "bool"; value: boolean }
  | { kind: "int"; value: number }
  | { kind: "string"; value: string }
  | { kind: "string-array"; values: string[] }
  | { kind: "other"; raw: string };

export interface TomlEntry {
  /** Dotted table name; "" for top-level keys. */
  table: string;
  key: string;
  value: TomlValue;
  /** 1-based line of the key. */
  line: number;
  /** The key's line, trimmed. */
  text: string;
}

/** Arrays and inline tables are followed over at most this many lines. */
const MAX_VALUE_LINES = 200;

const HEADER_RE = /^\s*\[\[?\s*([^[\]]+?)\s*\]\]?\s*(?:#.*)?$/;
const KEY_RE =
  /^\s*((?:[A-Za-z0-9_-]+|"[^"]*"|'[^']*')(?:\s*\.\s*(?:[A-Za-z0-9_-]+|"[^"]*"|'[^']*'))*)\s*=/;
const INT_RE = /^[+-]?\d(?:_?\d)*$/;

function unquoteKey(raw: string): string {
  return raw
    .split(".")
    .map((p) => p.trim().replace(/^(["'])(.*)\1$/, "$2"))
    .join(".");
}

/** Reads a string starting at `start` (a quote). Returns its value and the index after it, or null when unterminated. */
function readString(line: string, start: number): { value: string; end: number } | null {
  const quote = line[start] ?? "";
  if (line.startsWith(quote + quote + quote, start)) return null; // multi-line strings are skipped
  let out = "";
  for (let i = start + 1; i < line.length; i++) {
    const c = line[i]!;
    if (c === quote) return { value: out, end: i + 1 };
    if (quote === '"' && c === "\\" && i + 1 < line.length) {
      const n = line[i + 1]!;
      out += n === "n" ? "\n" : n === "t" ? "\t" : n;
      i++;
    } else {
      out += c;
    }
  }
  return null;
}

/** Strips a trailing `#` comment that sits outside strings. */
function stripComment(line: string): string {
  let quote = "";
  for (let i = 0; i < line.length; i++) {
    const c = line[i]!;
    if (quote) {
      if (quote === '"' && c === "\\") i++;
      else if (c === quote) quote = "";
    } else if (c === '"' || c === "'") quote = c;
    else if (c === "#") return line.slice(0, i);
  }
  return line;
}

/**
 * Parses the value that starts at `col` of `lines[index]`. Arrays and inline tables may
 * continue on following lines. Returns the value and the index of the last line used.
 */
function readValue(
  lines: readonly string[],
  index: number,
  col: number,
): { value: TomlValue; last: number } {
  const first = stripComment(lines[index] ?? "");
  const rest = first.slice(col).trim();
  if (rest === "") return { value: { kind: "other", raw: "" }, last: index };
  const head = rest[0]!;
  if (head === '"' || head === "'") {
    const s = readString(rest, 0);
    if (s && rest.slice(s.end).trim() === "")
      return { value: { kind: "string", value: s.value }, last: index };
    return { value: { kind: "other", raw: rest }, last: index };
  }
  if (head !== "[" && head !== "{") {
    if (rest === "true") return { value: { kind: "bool", value: true }, last: index };
    if (rest === "false") return { value: { kind: "bool", value: false }, last: index };
    if (INT_RE.test(rest)) {
      return { value: { kind: "int", value: Number(rest.replace(/_/g, "")) }, last: index };
    }
    return { value: { kind: "other", raw: rest }, last: index };
  }
  // Array or inline table: scan across lines, tracking nesting and strings.
  let depth = 0;
  let onlyStrings = head === "[";
  const values: string[] = [];
  const limit = Math.min(lines.length - 1, index + MAX_VALUE_LINES - 1);
  for (let li = index; li <= limit; li++) {
    const text = li === index ? first : stripComment(lines[li] ?? "");
    let i =
      li === index ? col + (first.slice(col).length - first.slice(col).trimStart().length) : 0;
    while (i < text.length) {
      const c = text[i]!;
      if (c === '"' || c === "'") {
        const s = readString(text, i);
        if (!s) {
          onlyStrings = false;
          i = text.length;
          break;
        }
        if (depth === 1) values.push(s.value);
        else onlyStrings = false;
        i = s.end;
        continue;
      }
      if (c === "[" || c === "{") {
        depth++;
        if (depth > 1) onlyStrings = false;
      } else if (c === "]" || c === "}") {
        depth--;
        if (depth === 0) {
          const done = head === "[" && onlyStrings;
          return {
            value: done ? { kind: "string-array", values } : { kind: "other", raw: rest },
            last: li,
          };
        }
      } else if (depth === 1 && c !== "," && c !== " " && c !== "\t" && c !== "\r") {
        onlyStrings = false;
      }
      i++;
    }
  }
  return { value: { kind: "other", raw: rest }, last: limit };
}

/**
 * Line scanner for simple TOML: [table] / [a.b] headers, key = value with bool/int/string;
 * arrays whose elements are all basic or literal strings (single- or multi-line, comments and
 * trailing comma allowed, bounded to 200 lines) become "string-array", other arrays and inline
 * tables become "other" (skipped over, same 200-line bound); comments (#) outside strings are
 * removed. Never throws. Duplicate keys: last wins (see tomlGet).
 */
export function scanTomlLines(content: string): {
  entries: TomlEntry[];
  tables: Map<string, number>;
} {
  const entries: TomlEntry[] = [];
  const tables = new Map<string, number>();
  try {
    const lines = content.split(/\r?\n/);
    let table = "";
    for (let i = 0; i < lines.length; i++) {
      const raw = lines[i] ?? "";
      if (!raw.includes("=") && !raw.includes("[")) continue;
      const header = HEADER_RE.exec(raw);
      if (header && raw.trimStart().startsWith("[")) {
        table = unquoteKey(header[1]!);
        if (!tables.has(table)) tables.set(table, i + 1);
        continue;
      }
      const stripped = stripComment(raw);
      const km = KEY_RE.exec(stripped);
      if (!km) continue;
      const { value, last } = readValue(lines, i, km[0].length);
      entries.push({ table, key: unquoteKey(km[1]!), value, line: i + 1, text: raw.trim() });
      i = last;
    }
  } catch {
    // Never throw: return what was parsed so far.
  }
  return { entries, tables };
}

/** The last entry for `key` under `table` (TOML forbids duplicates; the last one wins here). */
export function tomlGet(
  entries: readonly TomlEntry[],
  table: string,
  key: string,
): TomlEntry | undefined {
  let found: TomlEntry | undefined;
  for (const e of entries) if (e.table === table && e.key === key) found = e;
  return found;
}
