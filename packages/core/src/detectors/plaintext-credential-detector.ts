import {
  redactSecret,
  type Confidence,
  type Detector,
  type Finding,
  type ScanContext,
} from "@talaljaber/vibesafe-shared";
import { makeFinding } from "./utils/finding.js";
import {
  classifyFile,
  isGenerated,
  isJsLike,
  isServerScope,
  isTestOrFixturePath,
} from "./utils/file-kind.js";
import { maskCode, splitTopLevel } from "./utils/route-analyzer.js";

const MAX_PER_RULE_PER_FILE = 25;
const MAX_CALL_LENGTH = 3000;

/** Any hashing in the file means stored keys are probably hashed (or deliberately encrypted). */
const HASHING_RE =
  /\b(?:createHash|createHmac|bcrypt\w*|argon2\w*|scrypt\w*|pbkdf2\w*|digest)\b|[hH]ash\w*\s*\(|\bsubtle\s*\.\s*digest\b/;
/** Columns / properties that hold an issued credential. */
const KEY_COLUMN_RE =
  /^(?:key|api_?key|apikey|api_?token|token|secret|secret_?key|access_?token|refresh_?token|client_?secret|webhook_?secret|personal_?access_?token)$/i;
/** Tables / models that store issued credentials. */
const KEY_TABLE_RE = /(?:api_?keys?|tokens?|secrets?|credentials?|access_?keys?)$/i;
/** Calls that produce a fresh random credential. */
const GENERATOR_RE =
  /(?:random\w*|generate\w*|nanoid|customAlphabet|uuid\w*|randomUUID|randomBytes|createId|cuid\w*|ulid|create\w*(?:Key|Token|Secret))\s*\(/i;
const KEYISH_GENERATOR_RE = /(?:key|token|secret)\w*\s*\(/i;
const HASHED_NAME_RE = /hash|digest|encrypted|cipher|hmac|sealed/i;
const PASSWORD_WORD_RE = /pass(?:word|wd|phrase)?s?\b|\bpwd\b|password/i;
const SEED_PATH_RE =
  /(?:^|\/)(?:seeds?|seeders?|seeding)\/|(?:^|\/)seed[\w.-]*\.[cm]?[jt]sx?$|(?:^|\/)prisma\/seed\./i;

/** Passwords that are obviously local-development placeholders. */
const TRIVIAL_PASSWORD_RE =
  /^(?:password\d*!?|passw0rd|pass(?:word)?123!?|12345\d*|qwerty\d*|test\d*|testing|demo\d*|secret\d*|changeme|change_me|admin\d*|example|letmein|user\d*|dev|development|local|seed|foobar|foo|bar|x+|\*+)$/i;
/** Stored password values that are already hashes. */
const PASSWORD_HASH_RE =
  /^(?:\$2[abxy]?\$\d{2}\$|\$argon2|\$scrypt|\$pbkdf2|pbkdf2_|sha\d+\$|\{(?:SSHA|SHA|bcrypt)|[a-f0-9]{32,}$)/i;
const PASSWORD_COLUMN_RE =
  /^(?:password|passwd|pass|pwd|encrypted_password|password_hash|hashed_password|password_digest)$/i;

/**
 * The single summary finding emitted instead of the findings past the per-rule cap:
 * same rule and text, medium confidence (so at most high severity), a count as evidence.
 */
function summaryOf(first: Finding, more: number): Finding {
  return makeFinding({
    category: first.category,
    ruleId: first.ruleId,
    title: first.title,
    severity: first.severity === "critical" ? "high" : first.severity,
    confidence: "medium",
    file: first.file,
    line: first.line,
    evidence: `${more} more ${first.ruleId} findings in this file`,
    discriminator: "summary",
    plainEnglishProblem: first.plainEnglishProblem,
    whyItMatters: first.whyItMatters,
    fixSteps: first.fixSteps,
    aiFixPrompt: first.aiFixPrompt ?? "",
    learnMoreUrl: first.learnMoreUrl,
  });
}

function lineStartsOf(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
  return starts;
}

function lineIndexAt(starts: readonly number[], offset: number): number {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid]! <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

function closingBracket(code: string, open: number): number {
  let depth = 0;
  const end = Math.min(code.length, open + MAX_CALL_LENGTH);
  for (let i = open; i < end; i++) {
    const c = code[i];
    if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function isTrivialPassword(value: string): boolean {
  const v = value.trim();
  return v === "" || TRIVIAL_PASSWORD_RE.test(v) || /^<[^>]*>$|^\$\{|^\{\{/.test(v);
}

function redactIn(line: string, value: string): string {
  return value.length > 0 ? line.split(value).join(redactSecret(value)) : line;
}

/**
 * Blanks SQL comments (`--`, `/* *\/`) keeping strings, offsets and newlines intact.
 */
export function stripSqlComments(sql: string): string {
  const out = sql.split("");
  const n = sql.length;
  let i = 0;
  while (i < n) {
    const c = sql[i];
    if (c === "'" || c === '"') {
      let j = i + 1;
      while (j < n) {
        if (sql[j] === c) {
          if (sql[j + 1] === c) j += 2;
          else break;
        } else j++;
      }
      i = j + 1;
    } else if (c === "-" && sql[i + 1] === "-") {
      while (i < n && sql[i] !== "\n") out[i++] = " ";
    } else if (c === "/" && sql[i + 1] === "*") {
      const end = sql.indexOf("*/", i + 2);
      const stop = end < 0 ? n : end + 2;
      for (; i < stop; i++) if (out[i] !== "\n") out[i] = " ";
    } else i++;
  }
  return out.join("");
}

/** Index of the `)` closing the `(` at `open` in SQL (string-aware), and top-level comma offsets. */
function sqlGroup(sql: string, open: number): { close: number; commas: number[] } | undefined {
  let depth = 0;
  const commas: number[] = [];
  const end = Math.min(sql.length, open + 200_000);
  for (let i = open; i < end; i++) {
    const c = sql[i];
    if (c === "'" || c === '"') {
      let j = i + 1;
      while (j < end) {
        if (sql[j] === c) {
          if (sql[j + 1] === c) j += 2;
          else break;
        } else j++;
      }
      i = j;
    } else if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth === 0) return { close: i, commas };
    } else if (c === "," && depth === 1) commas.push(i);
  }
  return undefined;
}

/** `[start, end)` spans of the items in a parenthesised SQL list. */
function sqlItems(
  sql: string,
  open: number,
): { spans: Array<[number, number]>; close: number } | undefined {
  const group = sqlGroup(sql, open);
  if (!group) return undefined;
  const bounds = [open, ...group.commas, group.close];
  const spans: Array<[number, number]> = [];
  for (let k = 0; k < bounds.length - 1; k++) spans.push([bounds[k]! + 1, bounds[k + 1]!]);
  return { spans, close: group.close };
}

interface Hit {
  ruleId:
    | "crypto/plaintext-api-key-storage"
    | "crypto/weak-password-hash"
    | "crypto/plaintext-seed-password";
  line: number;
  evidence: string;
  confidence: Confidence;
  lookup?: boolean;
}

/**
 * Flags credentials stored or hashed so that a database read reveals them: issued API keys
 * / tokens written to (or looked up by) a plain column in files that never hash them,
 * md5/sha1 used on passwords, and literal passwords in SQL seeds, migrations and seed
 * scripts.
 */
export class PlaintextCredentialDetector implements Detector {
  id = "plaintext-credential-detector";
  name = "Plaintext Credentials";
  category = "crypto" as const;
  description =
    "Detects API keys and tokens stored without hashing, md5/sha1 password hashes and plaintext passwords in seed data.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (isTestOrFixturePath(file) || isGenerated(file)) continue;
      const isSql = /\.sql$/i.test(file);
      if (!isSql && !isJsLike(file)) continue;
      try {
        const content = await context.readFile(file);
        if (isGenerated(file, content)) continue;
        const hits = isSql ? this.scanSql(content) : this.scanJs(file, content, context);
        const perRule = new Map<string, number>();
        const overflow = new Map<string, { first: Finding; more: number }>();
        for (const hit of hits.sort((a, b) => a.line - b.line)) {
          const n = perRule.get(hit.ruleId) ?? 0;
          if (n >= MAX_PER_RULE_PER_FILE) {
            const o = overflow.get(hit.ruleId);
            if (o) o.more++;
            else overflow.set(hit.ruleId, { first: this.finding(file, hit), more: 1 });
            continue;
          }
          perRule.set(hit.ruleId, n + 1);
          findings.push(this.finding(file, hit));
        }
        for (const { first, more } of overflow.values()) findings.push(summaryOf(first, more));
      } catch {
        // never throw from a detector
      }
    }
    return findings;
  }

  // ---------------------------------------------------------------- SQL

  private scanSql(content: string): Hit[] {
    const lower = content.toLowerCase();
    if (!lower.includes("crypt(") && !lower.includes("pass")) return [];
    const sql = stripSqlComments(content);
    const starts = lineStartsOf(sql);
    const lines = content.split("\n");
    const hits = new Map<number, Hit>();
    const add = (offset: number, value: string): void => {
      const idx = lineIndexAt(starts, offset);
      if (hits.has(idx + 1)) return;
      hits.set(idx + 1, {
        ruleId: "crypto/plaintext-seed-password",
        line: idx + 1,
        evidence: redactIn(lines[idx] ?? "", value),
        confidence: "high",
      });
    };

    // crypt('literal', gen_salt('bf')): the plaintext is in the file even though the DB stores a hash.
    for (const m of sql.matchAll(/\bcrypt\s*\(\s*'((?:[^']|'')*)'\s*,\s*gen_salt\s*\(/gi)) {
      const value = m[1]!.replace(/''/g, "'");
      if (!isTrivialPassword(value)) add(m.index ?? 0, m[1]!);
    }

    // INSERT INTO t (..., password, ...) VALUES (..., 'literal', ...)
    for (const m of sql.matchAll(/\binsert\s+into\s+[\w."]+\s*\(/gi)) {
      const cols = sqlItems(sql, (m.index ?? 0) + m[0].length - 1);
      if (!cols) continue;
      const names = cols.spans.map(([a, b]) => sql.slice(a, b).trim().replace(/"/g, ""));
      const pwIndex = names.findIndex((n) => PASSWORD_COLUMN_RE.test(n));
      if (pwIndex < 0) continue;
      const valuesKw = /^\s*values\s*\(/i.exec(sql.slice(cols.close + 1, cols.close + 200));
      if (!valuesKw) continue;
      let open = cols.close + 1 + valuesKw[0].length - 1;
      for (let tuple = 0; tuple < 1000; tuple++) {
        const vals = sqlItems(sql, open);
        if (!vals) break;
        const span = vals.spans[pwIndex];
        if (span) {
          const raw = sql.slice(span[0], span[1]);
          const lit = /^\s*'((?:[^']|'')*)'\s*$/.exec(raw);
          if (lit) {
            const value = lit[1]!.replace(/''/g, "'");
            if (!PASSWORD_HASH_RE.test(value) && !isTrivialPassword(value)) {
              add(span[0] + raw.indexOf("'"), lit[1]!);
            }
          }
        }
        const next = /^\s*,\s*\(/.exec(sql.slice(vals.close + 1, vals.close + 200));
        if (!next) break;
        open = vals.close + 1 + next[0].length - 1;
      }
    }
    return [...hits.values()];
  }

  // ---------------------------------------------------------------- JS

  private scanJs(file: string, content: string, context: ScanContext): Hit[] {
    const code = maskCode(content);
    const starts = lineStartsOf(code);
    const lines = content.split("\n");
    const hits: Hit[] = [];
    const lineOf = (offset: number): number => lineIndexAt(starts, offset) + 1;

    if (/md5|sha-?1/i.test(content))
      hits.push(...this.weakPasswordHashes(content, code, lines, lineOf));
    if (SEED_PATH_RE.test(file.replace(/\\/g, "/"))) {
      hits.push(...this.seedScriptPasswords(content, code, lines, lineOf));
    }

    const cls = classifyFile(file, content, context.projectContext);
    if (isServerScope(cls) && !HASHING_RE.test(code)) {
      hits.push(...this.plaintextKeyStorage(content, code, lines, lineOf));
    }
    return hits;
  }

  private weakPasswordHashes(
    content: string,
    code: string,
    lines: readonly string[],
    lineOf: (offset: number) => number,
  ): Hit[] {
    const hits: Hit[] = [];
    const seen = new Set<number>();
    const add = (offset: number): void => {
      const line = lineOf(offset);
      if (seen.has(line)) return;
      seen.add(line);
      hits.push({
        ruleId: "crypto/weak-password-hash",
        line,
        evidence: lines[line - 1] ?? "",
        confidence: "high",
      });
    };
    // createHash("md5" | "sha1").update(<password>)
    for (const m of code.matchAll(/\bcreateHash\s*\(/g)) {
      const open = (m.index ?? 0) + m[0].length - 1;
      const close = closingBracket(code, open);
      if (close < 0) continue;
      if (!/^\s*["'`](?:md5|sha-?1)["'`]\s*$/i.test(content.slice(open + 1, close))) continue;
      const rest = code.slice(close + 1, close + 300);
      const upd = /^\s*\.\s*update\s*\(/.exec(rest);
      const stmtStart = Math.max(
        code.lastIndexOf(";", m.index ?? 0),
        code.lastIndexOf("\n", m.index ?? 0),
      );
      const prefix = code.slice(stmtStart + 1, m.index ?? 0);
      let arg = "";
      if (upd) {
        const uOpen = close + 1 + upd[0].length - 1;
        const uClose = closingBracket(code, uOpen);
        if (uClose > 0) arg = code.slice(uOpen + 1, uClose);
      }
      if (PASSWORD_WORD_RE.test(arg) || PASSWORD_WORD_RE.test(prefix)) add(m.index ?? 0);
    }
    // md5(password), sha1(password), CryptoJS.MD5(password)
    for (const m of code.matchAll(/(?<![\w$])(?:CryptoJS\s*\.\s*(?:MD5|SHA1)|md5|sha1)\s*\(/g)) {
      const open = (m.index ?? 0) + m[0].length - 1;
      const close = closingBracket(code, open);
      if (close < 0) continue;
      if (PASSWORD_WORD_RE.test(code.slice(open + 1, close))) add(m.index ?? 0);
    }
    return hits;
  }

  private seedScriptPasswords(
    content: string,
    code: string,
    lines: readonly string[],
    lineOf: (offset: number) => number,
  ): Hit[] {
    const hits: Hit[] = [];
    const seen = new Set<number>();
    const re =
      /(?:\b(?:password|passwd|plainPassword|plain_password)\s*:\s*|\b(?:bcrypt|bcryptjs|argon2)\s*\.\s*hash(?:Sync)?\s*\(\s*|\bhash(?:Password|Sync)?\s*\(\s*)(["'`])/g;
    for (const m of code.matchAll(re)) {
      const open = (m.index ?? 0) + m[0].length - 1;
      const quote = code[open]!;
      const close = code.indexOf(quote, open + 1);
      if (close < 0) continue;
      const value = content.slice(open + 1, close);
      if (value.includes("${") || isTrivialPassword(value) || PASSWORD_HASH_RE.test(value))
        continue;
      const line = lineOf(open);
      if (seen.has(line)) continue;
      seen.add(line);
      hits.push({
        ruleId: "crypto/plaintext-seed-password",
        line,
        evidence: redactIn(lines[line - 1] ?? "", value),
        confidence: "high",
      });
    }
    return hits;
  }

  /** Inserts/updates of generated keys into key-like columns, else `.eq('key', x)` lookups. */
  private plaintextKeyStorage(
    content: string,
    code: string,
    lines: readonly string[],
    lineOf: (offset: number) => number,
  ): Hit[] {
    const writes: Hit[] = [];
    const seen = new Set<number>();
    const writeRe = /\.\s*(?:insert|upsert|update|create|createMany|values)\s*\(/g;
    for (const m of code.matchAll(writeRe)) {
      const open = (m.index ?? 0) + m[0].length - 1;
      const close = closingBracket(code, open);
      if (close < 0) continue;
      const argCode = code.slice(open + 1, close);
      if (!argCode.includes("{")) continue;
      const table = this.tableBefore(content, code, m.index ?? 0);
      for (const prop of this.objectProps(argCode)) {
        if (!KEY_COLUMN_RE.test(prop.name)) continue;
        const generated = this.generatedValue(code, prop.value);
        if (!generated) continue;
        const plainKey = /^key$/i.test(prop.name);
        if (
          plainKey &&
          !(table !== undefined && KEY_TABLE_RE.test(table)) &&
          !KEYISH_GENERATOR_RE.test(generated)
        )
          continue;
        const line = lineOf(open + 1 + prop.offset);
        if (seen.has(line)) continue;
        seen.add(line);
        writes.push({
          ruleId: "crypto/plaintext-api-key-storage",
          line,
          evidence: lines[line - 1] ?? "",
          confidence: "medium",
        });
      }
    }
    if (writes.length > 0) return writes;

    const lookups: Hit[] = [];
    for (const m of code.matchAll(/\.\s*(?:eq|match)\s*\(\s*(["'`])/g)) {
      const open = (m.index ?? 0) + m[0].length - 1;
      const close = code.indexOf(code[open]!, open + 1);
      if (close < 0) continue;
      const column = content.slice(open + 1, close);
      if (!KEY_COLUMN_RE.test(column)) continue;
      const table = this.tableBefore(content, code, m.index ?? 0);
      if (table === undefined || !KEY_TABLE_RE.test(table)) continue;
      const line = lineOf(m.index ?? 0);
      if (seen.has(line)) continue;
      seen.add(line);
      lookups.push({
        ruleId: "crypto/plaintext-api-key-storage",
        line,
        evidence: lines[line - 1] ?? "",
        confidence: "medium",
        lookup: true,
      });
    }
    return lookups;
  }

  /** Supabase `.from("t")`, Prisma `prisma.t.` or Drizzle `insert(t)` shortly before `offset`. */
  private tableBefore(content: string, code: string, offset: number): string | undefined {
    const from = Math.max(0, offset - 400);
    const window = content.slice(from, offset);
    let table: string | undefined;
    for (const m of window.matchAll(/\.from\s*\(\s*["'`]([\w.]+)["'`]\s*\)/g)) {
      if (/^\.from/.test(code.slice(from + (m.index ?? 0), from + (m.index ?? 0) + 5)))
        table = m[1];
    }
    if (table !== undefined) return table;
    const prisma = /\b(?:prisma|db|tx)\s*\.\s*([A-Za-z_]\w*)\s*$/.exec(code.slice(from, offset));
    if (prisma) return prisma[1];
    const drizzle = /\b(?:insert|update)\s*\(\s*([A-Za-z_]\w*)\s*\)\s*$/.exec(
      code.slice(from, offset),
    );
    return drizzle ? drizzle[1] : undefined;
  }

  /** Top-level `name: value` and shorthand `name` properties of the object literals in `argCode`. */
  private objectProps(argCode: string): Array<{ name: string; value: string; offset: number }> {
    const props: Array<{ name: string; value: string; offset: number }> = [];
    for (let i = 0; i < argCode.length; i++) {
      if (argCode[i] !== "{") continue;
      const close = closingBracket(argCode, i);
      if (close < 0) break;
      const body = argCode.slice(i + 1, close);
      let pos = i + 1;
      for (const part of splitTopLevel(body)) {
        const kv = /^(\s*)([A-Za-z_$][\w$]*)\s*(?::\s*([\s\S]*?))?\s*$/.exec(part);
        if (kv) {
          const name = kv[2]!;
          if (kv[3] === "{" || (kv[3] ?? "").startsWith("{")) {
            // nested object (e.g. Prisma `data: { ... }`): scanned by the outer loop
          } else {
            props.push({ name, value: (kv[3] ?? name).trim(), offset: pos + kv[1]!.length });
          }
        }
        pos += part.length + 1;
      }
    }
    return props;
  }

  /** The generator call behind a property value: inline, or via a `const` assigned in the file. */
  private generatedValue(code: string, value: string): string | undefined {
    if (HASHED_NAME_RE.test(value)) return undefined;
    const inline = GENERATOR_RE.exec(value);
    if (inline) return inline[0];
    const ident = /^([A-Za-z_$][\w$]*)$/.exec(value);
    if (!ident) return undefined;
    const decl = new RegExp(
      `\\b(?:const|let|var)\\s+${escapeRe(ident[1]!)}\\s*(?::[^=;\\n]{0,80})?=\\s*(?:await\\s+)?([^;\\n]{1,200})`,
      "g",
    );
    for (const m of code.matchAll(decl)) {
      const rhs = m[1]!;
      if (HASHED_NAME_RE.test(rhs)) continue;
      const gen = GENERATOR_RE.exec(rhs);
      if (gen && rhs.trimStart().indexOf(gen[0]) <= 40) return gen[0];
    }
    return undefined;
  }

  // ---------------------------------------------------------------- findings

  private finding(file: string, hit: Hit): Finding {
    switch (hit.ruleId) {
      case "crypto/plaintext-api-key-storage":
        return makeFinding({
          category: "crypto",
          ruleId: "crypto/plaintext-api-key-storage",
          title: hit.lookup
            ? "API keys or tokens looked up by their plaintext value"
            : "API keys or tokens stored in plaintext",
          severity: "high",
          confidence: hit.confidence,
          file,
          line: hit.line,
          evidence: hit.evidence,
          plainEnglishProblem: hit.lookup
            ? "Issued API keys or tokens are matched against a database column by their raw value, which means the full secret is stored in that column, and nothing in this file hashes it."
            : "A freshly generated API key or token is written to the database as-is, and nothing in this file hashes it.",
          whyItMatters:
            "Anyone who gets read access to that table (a leaked backup, an injection bug, a support tool, an over-broad database policy) gets every customer's working key and can call your API as them.",
          fixSteps: [
            "Store only a hash of the key: sha256(key) is enough for long random keys (use HMAC-SHA256 with a server-side pepper if you want more).",
            "Show the full key to the user once at creation time and never store or return it again; keep a short non-secret prefix for display.",
            "On each request, hash the presented key and look up the hash; compare with a constant-time function if you compare in code.",
            "Migrate existing rows by hashing the stored keys, then drop the plaintext column.",
          ],
          aiFixPrompt:
            "This code stores issued API keys or tokens in plaintext and looks them up by their raw value. Change it to store a hash instead: compute crypto.createHash('sha256').update(key).digest('hex') (from node:crypto) when the key is created, save that in a key_hash column together with a short display prefix, and return the full key to the caller only once. When verifying, hash the presented key the same way and query by key_hash. Do not store, log or return the plaintext key anywhere else, and keep the public function signatures unchanged.",
          learnMoreUrl:
            "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
        });
      case "crypto/weak-password-hash":
        return makeFinding({
          category: "crypto",
          ruleId: "crypto/weak-password-hash",
          title: "Passwords hashed with MD5 or SHA-1",
          severity: "high",
          confidence: hit.confidence,
          file,
          line: hit.line,
          evidence: hit.evidence,
          plainEnglishProblem:
            "Passwords are hashed with MD5 or SHA-1. These are fast, broken general-purpose hashes, not password hashing functions.",
          whyItMatters:
            "If the user table leaks, commodity GPUs and precomputed tables recover most MD5/SHA-1 password hashes in hours, exposing your users' passwords (which many reuse elsewhere).",
          fixSteps: [
            "Hash passwords with a slow, salted password hashing function: argon2id (argon2 package), bcrypt (cost 12+) or scrypt from node:crypto.",
            "Compare with the library's verify function rather than recomputing and comparing strings.",
            "Upgrade existing hashes on the next successful login (verify the old hash once, then store the new one).",
          ],
          aiFixPrompt:
            "This code hashes passwords with MD5 or SHA-1. Replace it with a proper password hashing function: use argon2id via the argon2 package (argon2.hash / argon2.verify) or bcrypt with cost 12 (bcrypt.hash / bcrypt.compare). Update both the code that stores the hash and the code that checks a login, and add a migration path that re-hashes a user's password with the new function the next time they log in successfully. Do not use createHash for passwords.",
          learnMoreUrl:
            "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
        });
      case "crypto/plaintext-seed-password":
        return makeFinding({
          category: "crypto",
          ruleId: "crypto/plaintext-seed-password",
          title: "Plaintext password committed in seed or SQL data",
          severity: "high",
          confidence: hit.confidence,
          file,
          line: hit.line,
          evidence: hit.evidence,
          plainEnglishProblem:
            "A real-looking account password is written in plaintext in seed data or SQL, even if the database ends up storing a hash of it.",
          whyItMatters:
            "Anyone with access to the repository can log in as that account wherever the seed ran (staging, a shared preview, sometimes production), and seeded accounts are often admins.",
          fixSteps: [
            "Remove the literal password from the file and change that account's password wherever the seed has run.",
            "Seed accounts with a password read from an environment variable at seed time, or with a random one that is printed once.",
            "Prefer seeding test users only in local databases, and never mark seeded users as administrators in shared environments.",
          ],
          aiFixPrompt:
            "This seed or SQL file contains a plaintext account password. Remove the literal: in a seed script, read the password from an environment variable (fail if it is missing) or generate a random one with crypto.randomBytes and print it once; in SQL seeds, replace crypt('literal', gen_salt('bf')) with a value supplied at seed time (for example a psql variable) or create the user through the auth API in a script. Keep the rest of the seed unchanged.",
          learnMoreUrl:
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
        });
    }
  }
}
