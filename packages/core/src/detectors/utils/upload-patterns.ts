import type { ScanContext } from "@talaljaber/vibesafe-shared";
import {
  dirOf,
  findLockfile,
  manifestFiles,
  parseManifest,
  type LockfileInfo,
  type Manifest,
} from "./deps-manifest.js";
import type { FunctionSpan } from "./js-functions.js";
import type { JsSource } from "./js-source.js";
import { classifySpec, compareVersions, minVersion, satisfies } from "./semver.js";
import { splitTopLevel } from "./sinks.js";

/**
 * Pattern helpers for the file-upload detector: which upload libraries a file imports,
 * object-literal options, which identifiers hold an uploaded file, whether a stored name
 * is sanitized or made unique, and whether the project pins a pre-busboy-1.0 parser.
 * Matching runs on masked code (`JsSource.code`); literal text is read from `text`.
 */

/** Local names bound to an upload library default/named import in this file. */
export interface UploadBindings {
  multer: string[];
  busboy: string[];
  fileUpload: string[];
  formidable: string[];
  vercelPut: string[];
}

const IDENT = "[A-Za-z_$][\\w$]*";

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** The match starts at code (not inside a comment or a string). */
function isCodeAt(src: JsSource, index: number): boolean {
  return src.code[index] === src.text[index] && src.code[index] !== " ";
}

function defaultBindings(src: JsSource, mod: string): string[] {
  const names: string[] = [];
  const m = escapeRe(mod);
  const importRe = new RegExp(
    `\\bimport\\s+(?:type\\s+)?(?:\\*\\s+as\\s+)?(${IDENT})\\s*(?:,\\s*\\{[^}]*\\})?\\s*from\\s*["']${m}["']`,
    "g",
  );
  const requireRe = new RegExp(
    `\\b(?:const|let|var)\\s+(${IDENT})\\s*=\\s*(?:await\\s+)?require\\s*\\(\\s*["']${m}["']\\s*\\)`,
    "g",
  );
  for (const re of [importRe, requireRe]) {
    for (const match of src.text.matchAll(re)) {
      if (isCodeAt(src, match.index) && match[1] !== undefined) names.push(match[1]);
    }
  }
  return names;
}

/** Names bound to `member` of a named import / destructured require of `mod`. */
function namedBindings(src: JsSource, mod: string, members: readonly string[]): string[] {
  const names: string[] = [];
  const m = escapeRe(mod);
  const importRe = new RegExp(`\\bimport\\s*\\{([^}]*)\\}\\s*from\\s*["']${m}["']`, "g");
  const requireRe = new RegExp(
    `\\b(?:const|let|var)\\s*\\{([^}]*)\\}\\s*=\\s*(?:await\\s+)?require\\s*\\(\\s*["']${m}["']\\s*\\)`,
    "g",
  );
  for (const [re, sep] of [
    [importRe, /\s+as\s+/],
    [requireRe, /\s*:\s*/],
  ] as const) {
    for (const match of src.text.matchAll(re)) {
      if (!isCodeAt(src, match.index)) continue;
      for (const part of (match[1] ?? "").split(",")) {
        const [orig, alias] = part.trim().split(sep);
        if (orig === undefined || !members.includes(orig)) continue;
        const local = (alias ?? orig).trim();
        if (new RegExp(`^${IDENT}$`).test(local)) names.push(local);
      }
    }
  }
  return names;
}

export function uploadBindings(src: JsSource): UploadBindings {
  const out: UploadBindings = {
    multer: [],
    busboy: [],
    fileUpload: [],
    formidable: [],
    vercelPut: [],
  };
  try {
    out.multer = defaultBindings(src, "multer");
    out.busboy = defaultBindings(src, "busboy");
    out.fileUpload = defaultBindings(src, "express-fileupload");
    out.formidable = [
      ...defaultBindings(src, "formidable"),
      ...namedBindings(src, "formidable", ["IncomingForm", "formidable"]),
    ];
    out.vercelPut = namedBindings(src, "@vercel/blob", ["put"]);
  } catch {
    // never throws
  }
  return out;
}

/** Top-level properties of an object literal at `open`: key -> value range, plus spread ranges. */
export interface ObjectProps {
  props: Map<string, { start: number; end: number }>;
  spreads: { start: number; end: number }[];
}

export function objectProps(src: JsSource, open: number): ObjectProps | undefined {
  try {
    if (src.code[open] !== "{") return undefined;
    const close = src.matchOf(open);
    if (close <= open) return undefined;
    const props = new Map<string, { start: number; end: number }>();
    const spreads: { start: number; end: number }[] = [];
    for (const r of splitTopLevel(src, { start: open + 1, end: close }, ",")) {
      if (r.end <= r.start) continue;
      const code = src.code.slice(r.start, r.end);
      if (code.startsWith("...")) {
        spreads.push({ start: r.start + 3, end: r.end });
        continue;
      }
      const quoted = /^["']/.exec(code);
      let key: string | undefined;
      let rest: number;
      if (quoted !== null) {
        const endQuote = code.indexOf(code[0]!, 1);
        if (endQuote < 0) continue;
        key = src.text.slice(r.start + 1, r.start + endQuote);
        rest = endQuote + 1;
      } else {
        const m = new RegExp(`^(?:async\\s+)?(${IDENT})`).exec(code);
        if (m === null || m[1] === undefined) continue;
        key = m[1];
        rest = m[0].length;
      }
      const after = code.slice(rest);
      const colon = /^\s*:\s*/.exec(after);
      if (colon !== null) {
        props.set(key, { start: r.start + rest + colon[0].length, end: r.end });
      } else if (/^\s*\(/.test(after) || /^\s*<[^>]*>\s*\(/.test(after)) {
        props.set(key, { start: r.start, end: r.end }); // method shorthand
      } else if (/^\s*$/.test(after)) {
        props.set(key, { start: r.start, end: r.end }); // shorthand `{ storage }`
      }
    }
    return { props, spreads };
  } catch {
    return undefined;
  }
}

/** Resolves an identifier argument to a same-file `const X = {` object, else undefined. */
export function resolveObjectIdentifier(src: JsSource, name: string): number | undefined {
  try {
    if (!new RegExp(`^${IDENT}$`).test(name)) return undefined;
    const re = new RegExp(
      `\\b(?:const|let|var)\\s+${escapeRe(name)}\\s*(?::[^=\\n]{1,60})?=\\s*(?:\\(\\s*)?\\{`,
    );
    const m = re.exec(src.code);
    if (m === null) return undefined;
    return m.index + m[0].length - 1;
  } catch {
    return undefined;
  }
}

/** Upload-library client filename members: `.originalname` (multer), `.originalFilename` (formidable). */
export const UPLOAD_NAME_MEMBER_RE = /\.\s*(?:originalname|originalFilename)\b/;

const REQ_FILE_NAME_RE = /\breq\s*\.\s*files?\b[^;\n]{0,80}?\.\s*(?:name|originalname)\b/;
const FORM_NAMES = ["formData", "form", "fd", "data"];

const BINDING_CACHE = new WeakMap<JsSource, Map<string, Set<string>>>();

/**
 * Identifiers that hold an uploaded file inside `span`: bound (`const|let|var X =`, optionally
 * `as File`) from an expression containing `.get(` / `.getAll(` on a FormData-like receiver
 * (`formData`, `form`, `fd`, `data`, or any name bound from `await <x>.formData()` or the first
 * parameter of a server-action span), from `req.file` / `req.files.<k>` / `req.files[<k>]`, declared
 * with a `: File` annotation, or used as `X instanceof File|Blob`; plus `for (const X of Y)` where Y
 * is one of those. Masked code only.
 */
export function fileBindings(src: JsSource, span: FunctionSpan): Set<string> {
  let perSource = BINDING_CACHE.get(src);
  if (perSource === undefined) {
    perSource = new Map();
    BINDING_CACHE.set(src, perSource);
  }
  const key = `${span.start}:${span.end}:${span.kind}`;
  const cached = perSource.get(key);
  if (cached !== undefined) return cached;
  const out = new Set<string>();
  perSource.set(key, out);
  try {
    const code = src.code.slice(span.start, span.end);
    const forms = new Set(FORM_NAMES);
    if (span.role === "server-action") {
      const first = span.params[0]?.names[0];
      if (first !== undefined) forms.add(first);
    }
    for (const m of code.matchAll(
      new RegExp(
        `\\b(?:const|let|var)\\s+(${IDENT})\\s*=\\s*await\\s+[\\w$.]+\\s*\\.\\s*formData\\s*\\(`,
        "g",
      ),
    )) {
      if (m[1] !== undefined) forms.add(m[1]);
    }
    const formAlt = [...forms].map(escapeRe).join("|");
    const getRe = new RegExp(`(?<![\\w$.])(?:${formAlt})\\s*\\.\\s*(?:get|getAll)\\s*\\(`);
    const reqFileRe = /(?<![\w$.])req\s*\.\s*files?\b/;
    const bindRe = new RegExp(
      `\\b(?:const|let|var)\\s+(${IDENT})\\s*(?::[^=;\\n]{1,40})?=\\s*([^;\\n]{0,200})`,
      "g",
    );
    for (const m of code.matchAll(bindRe)) {
      if (m[1] === undefined) continue;
      const expr = m[2] ?? "";
      if (reqFileRe.test(expr) || (getRe.test(expr) && fileEvidence(code, m[1], expr))) {
        out.add(m[1]);
      }
    }
    for (const m of code.matchAll(
      /\b(?:const|let|var)\s*\{([^}]{0,200})\}\s*=\s*req\s*\.\s*files\b/g,
    )) {
      for (const part of (m[1] ?? "").split(",")) {
        const alias = part.split(":").pop()?.trim();
        if (alias !== undefined && new RegExp(`^${IDENT}$`).test(alias)) out.add(alias);
      }
    }
    for (const m of code.matchAll(
      new RegExp(`(?<![\\w$.])(${IDENT})\\s*\\??\\s*:\\s*File\\b`, "g"),
    )) {
      if (m[1] !== undefined) out.add(m[1]);
    }
    for (const m of code.matchAll(
      new RegExp(`(?<![\\w$.])(${IDENT})\\s+instanceof\\s+(?:File|Blob)\\b`, "g"),
    )) {
      if (m[1] !== undefined) out.add(m[1]);
    }
    for (const m of code.matchAll(
      new RegExp(
        `\\bfor\\s*(?:await\\s*)?\\(\\s*(?:const|let|var)\\s+(${IDENT})\\s+of\\s+([^)\\n]{0,200})\\)`,
        "g",
      ),
    )) {
      if (m[1] === undefined) continue;
      const iter = m[2] ?? "";
      const root = new RegExp(`^\\s*(${IDENT})`).exec(iter)?.[1];
      const line = code.slice(m.index, m.index + 300).split("\n")[0] ?? "";
      const asFile = /\bas\s+\(?\s*(?:File|Blob)\b/.test(line);
      if (reqFileRe.test(iter) || (root !== undefined && out.has(root))) out.add(m[1]);
      else if (getRe.test(iter) && (asFile || memberEvidence(code, m[1]))) out.add(m[1]);
    }
  } catch {
    // never throws
  }
  return out;
}

const FILE_MEMBER = "(?:arrayBuffer|stream|size|name)";

function memberEvidence(code: string, name: string): boolean {
  const n = escapeRe(name);
  return (
    new RegExp(`(?<![\\w$.])${n}\\s*\\.\\s*${FILE_MEMBER}\\b`).test(code) ||
    new RegExp(`(?<![\\w$.])${n}\\s+instanceof\\s+(?:File|Blob)\\b`).test(code)
  );
}

/** A `.get(` binding counts as a file only with evidence: `as File|Blob`, or file-only member use. Text casts never count. */
function fileEvidence(code: string, name: string, expr: string): boolean {
  if (/\bas\s+\(?\s*(?:File|Blob)\b/.test(expr)) return true;
  if (/\bas\s+string\b|(?<![\w$.])String\s*\(|\.\s*toString\s*\(|\?\?\s*["'`]/.test(expr)) {
    return false;
  }
  return memberEvidence(code, name);
}

/** True when exprText reads the client name: UPLOAD_NAME_MEMBER_RE, `req.file(s)…​.name`, or `X.name` for X in fileVars. */
export function readsClientFileName(exprText: string, fileVars: ReadonlySet<string>): boolean {
  if (UPLOAD_NAME_MEMBER_RE.test(exprText) || REQ_FILE_NAME_RE.test(exprText)) return true;
  for (const v of fileVars) {
    if (new RegExp(`(?<![\\w$.])${escapeRe(v)}\\s*\\.\\s*name\\b`).test(exprText)) return true;
  }
  return false;
}

const SANITIZER_RE =
  /\b(?:path\s*\.\s*)?basename\s*\(|sanitize\w*\s*\(|slugify\s*\(|filenamify\s*\(|\.replace\s*\(\s*\/\[\^/;
const EXTNAME_RE = /\b(?:path\s*\.\s*)?extname\s*\(/;

/** Removes `extname( ... )` spans (balanced parentheses, bounded). */
function withoutExtname(t: string): string {
  let out = "";
  let i = 0;
  while (i < t.length) {
    const m = EXTNAME_RE.exec(t.slice(i));
    if (m === null) {
      out += t.slice(i);
      break;
    }
    out += t.slice(i, i + m.index);
    let j = i + m.index + m[0].length;
    let depth = 1;
    while (j < t.length && depth > 0) {
      if (t[j] === "(") depth++;
      else if (t[j] === ")") depth--;
      j++;
    }
    i = j;
  }
  return out;
}

/** Expression text applies a filename sanitizer; `clientToken` is the token regex the candidate used (for the extname rule). */
export function isSanitizedFilename(exprText: string, clientToken: RegExp): boolean {
  if (SANITIZER_RE.test(exprText)) return true;
  if (EXTNAME_RE.test(exprText)) {
    const rest = withoutExtname(exprText);
    return !new RegExp(clientToken.source, clientToken.flags.replace("g", "")).test(rest);
  }
  return false;
}

const UNIQUE_RE =
  /\b(?:randomUUID|uuid\w*|v4|nanoid|cuid2?|createId|ulid|randomBytes|crypto\s*\.\s*random\w*|Date\s*\.\s*now|Math\s*\.\s*random|hash\w*|uid|session\s*\.\s*user|auth\s*\.\s*uid|req\s*\.\s*user|orgId|org\s*\.\s*id|tenantId|ownerId|accountId)\b|[A-Za-z_$]*[Uu]ser\s*[!?]?\s*\.\s*(?:id|uid|sub)\b|\w*(?:User|Org|Owner|Tenant|Account|Team|Workspace)Id\b|\buserId\b/;

/** Removes member chains rooted in client input (`req.body.ownerId`, `formData.get(..)`), which prove no ownership. */
function stripClientRooted(t: string): string {
  return t
    .replace(/\breq\s*\.\s*(?:body|query|params)\b(?:\s*[!?]?\s*\.\s*[\w$]+|\s*\[[^\]]*\])*/g, " ")
    .replace(/\b(?:formData|form|fd)\s*\.\s*get(?:All)?\s*\([^)]*\)/g, " ");
}

/** Expression text makes the key unique or owner-scoped. */
export function hasUniqueOrOwnerPart(exprText: string): boolean {
  return UNIQUE_RE.test(stripClientRooted(exprText));
}

/** Upload parsers whose filename handling changed with busboy 1.0. */
export type LegacyParserLib = "multer" | "busboy" | "express-fileupload";

/** Result of the version check: `legacy` true only when the installed/declared version predates basename stripping. */
export interface ParserVersionInfo {
  legacy: boolean;
  /** e.g. `multer@^1.4.2` or `multer@1.4.4 (package-lock.json)`; undefined when not legacy. */
  source: string | undefined;
}

const NOT_LEGACY: ParserVersionInfo = { legacy: false, source: undefined };

const FIXED: Record<LegacyParserLib, string> = {
  multer: "1.4.5-lts.1",
  busboy: "1.0.0",
  "express-fileupload": "1.3.0",
};

/** Release versions at or after the fix (prereleases are never used as probes). */
const FIXED_PROBES: Record<LegacyParserLib, string[]> = {
  multer: ["2.0.0", "2.0.2", "2.1.0", "3.0.0"],
  busboy: ["1.0.0", "1.6.0", "2.0.0"],
  "express-fileupload": ["1.3.0", "1.5.1", "2.0.0"],
};

const MANIFEST_CACHE = new WeakMap<ScanContext, Map<string, Manifest | null>>();

async function readManifest(context: ScanContext, file: string): Promise<Manifest | null> {
  let perContext = MANIFEST_CACHE.get(context);
  if (perContext === undefined) {
    perContext = new Map();
    MANIFEST_CACHE.set(context, perContext);
  }
  if (perContext.has(file)) return perContext.get(file) ?? null;
  let manifest: Manifest | null = null;
  try {
    manifest = parseManifest(file, await context.readFile(file));
  } catch {
    manifest = null;
  }
  perContext.set(file, manifest);
  return manifest;
}

/**
 * Whether the project that contains `file` uses a pre-busboy-1.0 version of `lib`.
 * Never throws; `cache` is per detector run (keyed by `<manifest>|<lib>`; lockfiles via `findLockfile`'s cache).
 */
export async function legacyUploadParser(
  context: ScanContext,
  file: string,
  lib: LegacyParserLib,
  manifestCache: Map<string, ParserVersionInfo>,
  lockCache: Map<string, LockfileInfo>,
): Promise<ParserVersionInfo> {
  try {
    const fileDir = dirOf(file);
    const candidates = manifestFiles(context)
      .map((f) => ({ f, dir: dirOf(f) }))
      .filter((c) => c.dir === "" || fileDir === c.dir || fileDir.startsWith(`${c.dir}/`))
      .sort((a, b) => b.dir.length - a.dir.length);
    let manifest: Manifest | null = null;
    let spec: string | undefined;
    for (const c of candidates) {
      const m = await readManifest(context, c.f);
      const dep = m?.deps.find((d) => d.name === lib);
      if (m !== null && dep !== undefined) {
        manifest = m;
        spec = dep.spec;
        break;
      }
    }
    if (manifest === null || spec === undefined) return NOT_LEGACY;
    const cacheKey = `${manifest.file}|${lib}`;
    const cached = manifestCache.get(cacheKey);
    if (cached !== undefined) return cached;
    const result = await versionInfo(context, manifest, spec, lib, lockCache);
    manifestCache.set(cacheKey, result);
    return result;
  } catch {
    return NOT_LEGACY;
  }
}

async function versionInfo(
  context: ScanContext,
  manifest: Manifest,
  spec: string,
  lib: LegacyParserLib,
  lockCache: Map<string, LockfileInfo>,
): Promise<ParserVersionInfo> {
  const fixed = FIXED[lib];
  try {
    const lock = await findLockfile(context, manifest.file, lockCache);
    const entries = lock.versions.get(lib);
    if (lock.state === "ok" && entries !== undefined && entries.length > 0) {
      const old = entries
        .map((e) => e.version)
        .filter((v) => compareVersions(v, fixed) < 0)
        .sort((a, b) => compareVersions(a, b));
      if (old.length === 0) return NOT_LEGACY;
      const lockName = (lock.file ?? "lockfile").split("/").pop() ?? "lockfile";
      return { legacy: true, source: `${lib}@${old[0]} (${lockName})`.slice(0, 60) };
    }
  } catch {
    // an unreadable lockfile falls back to the spec
  }
  const kind = classifySpec(spec);
  let legacy = false;
  if (kind === "exact") {
    legacy = compareVersions(spec, fixed) < 0;
  } else if (kind === "range") {
    const min = minVersion(spec);
    legacy =
      min !== null &&
      compareVersions(min, fixed) < 0 &&
      !FIXED_PROBES[lib].some((p) => satisfies(p, spec));
  }
  return legacy ? { legacy: true, source: `${lib}@${spec}`.slice(0, 60) } : NOT_LEGACY;
}
