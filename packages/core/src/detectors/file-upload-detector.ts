import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { makeFinding } from "./utils/finding.js";
import {
  enclosingFunction,
  expressionEnd,
  moduleSpan,
  type FunctionSpan,
} from "./utils/js-functions.js";
import type { LockfileInfo } from "./utils/deps-manifest.js";
import {
  SinkAnalyzer,
  callKey,
  capPerRule,
  loadSinkFile,
  splitArgs,
  staticText,
  trimRange,
  type Range,
  type SinkFile,
} from "./utils/sinks.js";
import { analyzeTaint } from "./utils/taint.js";
import {
  fileBindings,
  hasUniqueOrOwnerPart,
  isSanitizedFilename,
  legacyUploadParser,
  objectProps,
  readsClientFileName,
  resolveObjectIdentifier,
  uploadBindings,
  type LegacyParserLib,
  type ObjectProps,
  type ParserVersionInfo,
  type UploadBindings,
} from "./utils/upload-patterns.js";

const NEEDLES = [
  "multer",
  "busboy",
  "express-fileupload",
  "formidable",
  "formData",
  "FormData",
  "PutObjectCommand",
  "putObject",
  ".upload(",
  "@vercel/blob",
  "bucket.file",
];

const LEARN_MORE = "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload";

const SIZE_PROMPT =
  "My upload endpoint accepts files without a size limit. Add a per-file size limit and a file count limit to the upload middleware (multer `limits: { fileSize, files }`, busboy `limits`, express-fileupload `limits`/`abortOnLimit`, formidable `maxFileSize`), return 413 when it is exceeded, and keep the existing response shape. Also mention which limit to set at the reverse proxy.";
const TYPE_PROMPT =
  "My upload endpoint stores files without checking their type. Allowlist the MIME types and extensions the feature needs (multer `fileFilter`), verify the real type from the file's magic bytes (for example with `file-type`), store uploads outside `public/`, serve them with `Content-Disposition: attachment` and a fixed `Content-Type`, and keep the existing response shape.";
const NAME_PROMPT =
  "My upload code stores files under the client-supplied file name. Generate the stored name or key on the server (UUID plus an extension from an allowlisted MIME type), prefix it with the owner's id, keep the original name only as metadata, make sure nothing can escape the upload folder, and keep the existing response shape.";

const TYPE_IDENT_RE =
  /\b(?:mimetype|mimeType|fileTypeFromBuffer|fileTypeFromFile|fromBuffer|magicBytes|fileType)\b/;
const PUBLIC_RE = /(?:^|[\s\\/])(?:public|static)(?:[\s\\/]|$)/;
const FS_WRITE_RE =
  /(?<![\w$.])(?:(?:fs|fsp|fse|fsPromises)\s*\.\s*(?:promises\s*\.\s*)?)?(?:createWriteStream|writeFile|writeFileSync|appendFile|appendFileSync|outputFile)\s*\(/g;
const FS_MOVE_RE =
  /(?<![\w$.])(?:(?:fs|fsp|fse|fsPromises)\s*\.\s*(?:promises\s*\.\s*)?)?(?:rename|renameSync|copyFile|copyFileSync)\s*\(/g;
const IDENT_ONLY_RE = /^[A-Za-z_$][\w$]*$/;

interface Call {
  start: number;
  open: number;
  close: number;
  args: Range[];
}

type Cfg = { kind: "none" } | { kind: "obj"; obj: ObjectProps } | { kind: "unknown" };

type LibKey = LegacyParserLib | "formidable";

/** An unsafe disk-name candidate before the dedupe and rating are decided. */
interface DiskCandidate {
  lib: LibKey;
  /** Offset anchoring the finding (line, discriminator). */
  offset: number;
  member: string;
  /** Path argument + call start of an fs sink (dedupe with path traversal). */
  fsSink: { arg: Range; callStart: number } | undefined;
  busboy0x: boolean;
}

interface ProjectFacts {
  staticSegments: Set<string>;
  safeFileNames: boolean;
}

interface RunState {
  manifestCache: Map<string, ParserVersionInfo>;
  lockCache: Map<string, LockfileInfo>;
  facts: Promise<ProjectFacts> | undefined;
}

/**
 * Upload handlers without a size limit or type check, and stored file names or object-storage
 * keys taken from the uploader (`validation/upload-no-size-limit`, `upload-no-type-check`,
 * `upload-unsafe-filename`): multer, busboy, express-fileupload, formidable, Next.js server
 * actions and route handlers writing to S3, Supabase Storage, Google Cloud Storage or Vercel Blob.
 */
export class FileUploadDetector implements Detector {
  id = "file-upload-detector";
  name = "File Upload Safety";
  category = "validation" as const;
  description =
    "Detects upload handlers without size limits or type checks, and stored file names or keys taken from the client.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const run: RunState = { manifestCache: new Map(), lockCache: new Map(), facts: undefined };
    for (const file of context.files) {
      try {
        const f = await loadSinkFile(context, file, NEEDLES);
        if (f === undefined) continue;
        findings.push(...capPerRule(await this.scanFile(context, f, run)));
      } catch {
        // a detector never throws
      }
    }
    return findings;
  }

  private async scanFile(context: ScanContext, f: SinkFile, run: RunState): Promise<Finding[]> {
    const { src } = f;
    const bind = uploadBindings(src);
    const out: Finding[] = [];
    const typeChecked = TYPE_IDENT_RE.test(src.code);
    const publicTexts: string[] = [];

    // --- U1 size limits and U2 (multer) ------------------------------------
    const multerCalls = bind.multer.flatMap((n) => callsOf(src, n));
    let firstNoFilter: Call | undefined;
    for (const call of multerCalls) {
      const cfg = cfgOf(src, call);
      if (cfg.kind !== "unknown") {
        const dest = cfg.kind === "obj" ? cfg.obj.props.get("dest") : undefined;
        if (dest !== undefined) publicTexts.push(staticText(src, dest));
      }
      if (limitsState(src, cfg) === "missing") out.push(this.sizeFinding(f, call.start, "multer"));
      if (firstNoFilter === undefined && filterState(cfg) === "missing") firstNoFilter = call;
    }
    for (const call of allMatches(src.code, /(?<![\w$])diskStorage\s*\(/g, src)) {
      const first = call.args[0];
      const obj =
        first !== undefined && src.code[first.start] === "{"
          ? objectProps(src, first.start)
          : undefined;
      const dest = obj?.props.get("destination") ?? obj?.props.get("dest");
      if (dest !== undefined) publicTexts.push(staticText(src, dest));
    }
    for (const name of bind.busboy) {
      for (const call of callsOf(src, name)) {
        const cfg = cfgOf(src, call);
        if (cfg.kind === "obj" && limitsState(src, cfg) === "missing") {
          out.push(this.sizeFinding(f, call.start, "busboy"));
        }
      }
    }
    for (const name of bind.fileUpload) {
      for (const call of callsOf(src, name)) {
        const cfg = cfgOf(src, call);
        if (limitsState(src, cfg) === "missing") {
          out.push(this.sizeFinding(f, call.start, "express-fileupload"));
        }
      }
    }
    for (const name of bind.formidable) {
      const re = new RegExp(
        `(?<![\\w$.])${escapeRe(name)}(?:\\s*\\.\\s*IncomingForm)?\\s*\\(`,
        "g",
      );
      for (const call of allMatches(src.code, re, src)) {
        const cfg = cfgOf(src, call);
        if (cfg.kind !== "obj") continue;
        const v = cfg.obj.props.get("maxFileSize");
        if (v === undefined) continue;
        const t = src.code.slice(v.start, v.end).trim().replace(/\s+/g, "");
        if (/^(?:Infinity|Number\.MAX_SAFE_INTEGER|Number\.MAX_VALUE)$/.test(t)) {
          out.push(this.sizeFinding(f, call.start, "formidable"));
        }
      }
    }

    // --- U2 type checks -----------------------------------------------------
    if (!typeChecked) {
      if (firstNoFilter !== undefined) {
        const isPublic = await this.isPublic(context, publicTexts, run);
        out.push(this.typeFinding(f, firstNoFilter.start, "multer", isPublic));
      }
      if (bind.fileUpload.length > 0) {
        const m = /(?<![\w$.])req\s*\.\s*files\b/.exec(src.code);
        if (m !== null) {
          const mvTexts: string[] = [];
          for (const mv of allMatches(src.code, /\.\s*mv\s*\(/g, src)) {
            const a = mv.args[0];
            if (a !== undefined) mvTexts.push(staticText(src, a));
          }
          const isPublic = await this.isPublic(context, mvTexts, run);
          out.push(this.typeFinding(f, m.index, "express-fileupload", isPublic));
        }
      }
      if (bind.busboy.length > 0) {
        const on = busboyFileHandlers(src)[0];
        if (on !== undefined) out.push(this.typeFinding(f, on.start, "busboy", false));
      }
    }
    {
      for (const span of f.spans) {
        if (span.role !== "server-action") continue;
        const found = this.serverActionTypeGap(f, span);
        if (found !== undefined) {
          const paths = allMatches(
            src.code.slice(0, span.end),
            /(?<![\w$.])(?:writeFile\w*|createWriteStream|mv)\s*\(/g,
            src,
          )
            .filter((c) => c.start >= span.start)
            .map((c) => (c.args[0] !== undefined ? staticText(src, c.args[0]) : ""));
          const isPublic = await this.isPublic(context, paths, run);
          out.push(this.typeFinding(f, found, "server-action", isPublic));
        }
      }
    }

    // --- U3a disk names -----------------------------------------------------
    out.push(...(await this.diskFindings(context, f, bind, run)));

    // --- U3b object-storage keys ------------------------------------------
    out.push(...this.storageFindings(f, bind));
    return out;
  }

  // ---------------------------------------------------------------------------
  // U2 helpers
  // ---------------------------------------------------------------------------

  /** Offset of the first qualifying `fd.get(` in a server action that handles a file with no type check. */
  private serverActionTypeGap(f: SinkFile, span: FunctionSpan): number | undefined {
    const { src } = f;
    const code = src.code.slice(span.start, span.end);
    if (TYPE_IDENT_RE.test(code)) return undefined;
    const vars = fileBindings(src, span);
    if (vars.size === 0) return undefined;
    const used = [...vars].some((v) => {
      const e = escapeRe(v);
      return (
        new RegExp(`(?<![\\w$.])${e}\\s+instanceof\\s+(?:File|Blob)\\b`).test(code) ||
        new RegExp(`(?<![\\w$.])${e}\\s*\\.\\s*(?:arrayBuffer|stream|size|name)\\b`).test(code) ||
        new RegExp(
          `\\b(?:writeFile\\w*|put|upload\\w*|PutObjectCommand|save)\\s*\\([^)]*(?<![\\w$.])${e}\\b`,
        ).test(code)
      );
    });
    if (!used) return undefined;
    for (const v of vars) {
      if (new RegExp(`(?<![\\w$.])${escapeRe(v)}\\s*\\.\\s*type\\b`).test(code)) return undefined;
    }
    const first = span.params[0]?.names[0];
    const names = ["formData", "form", "fd", "data", ...(first === undefined ? [] : [first])];
    const re = new RegExp(
      `(?<![\\w$.])(?:${names.map(escapeRe).join("|")})\\s*\\.\\s*(?:get|getAll)\\s*\\(`,
    );
    const m = re.exec(code);
    return m === null ? undefined : span.start + m.index;
  }

  private async isPublic(
    context: ScanContext,
    texts: readonly string[],
    run: RunState,
  ): Promise<boolean> {
    if (texts.some((t) => PUBLIC_RE.test(t))) return true;
    if (texts.length === 0) return false;
    const facts = await this.projectFacts(context, run);
    if (facts.staticSegments.size === 0) return false;
    for (const t of texts) {
      for (const seg of t.split(/[\s\\/]+/)) {
        if (seg !== "" && seg !== "X" && seg !== "." && facts.staticSegments.has(seg)) return true;
      }
    }
    return false;
  }

  /** Project-wide facts (express.static directories, `safeFileNames: true`), read once and lazily. */
  private projectFacts(context: ScanContext, run: RunState): Promise<ProjectFacts> {
    run.facts ??= (async () => {
      const facts: ProjectFacts = { staticSegments: new Set(), safeFileNames: false };
      for (const file of context.files) {
        if (!/\.(?:[cm]?js|[jt]sx?|mts|cts)$/i.test(file)) continue;
        try {
          const text = await context.readFile(file);
          if (text.includes("safeFileNames") && /safeFileNames\s*:\s*true/.test(text)) {
            facts.safeFileNames = true;
          }
          if (!text.includes("express.static(")) continue;
          for (const m of text.matchAll(/express\s*\.\s*static\s*\(([^)]{0,300})\)/g)) {
            for (const s of (m[1] ?? "").matchAll(/["'`]([^"'`]+)["'`]/g)) {
              const segs = (s[1] ?? "").split(/[\\/]+/).filter((x) => x !== "" && x !== ".");
              const last = segs[segs.length - 1];
              if (last !== undefined) facts.staticSegments.add(last);
            }
          }
        } catch {
          // skip unreadable files
        }
      }
      return facts;
    })();
    return run.facts;
  }

  // ---------------------------------------------------------------------------
  // U3a
  // ---------------------------------------------------------------------------

  private async diskFindings(
    context: ScanContext,
    f: SinkFile,
    bind: UploadBindings,
    run: RunState,
  ): Promise<Finding[]> {
    const { src } = f;
    const text = src.text;
    const candidates: DiskCandidate[] = [];
    if (text.includes("multer")) this.multerDisk(f, candidates);
    if (text.includes("busboy")) this.busboyDisk(f, candidates);
    if (text.includes("formidable")) this.formidableDisk(f, bind, candidates);
    this.fileUploadDisk(f, bind, candidates);
    if (candidates.length === 0) return [];
    let analyzer: SinkAnalyzer | undefined;
    const out: Finding[] = [];
    for (const c of candidates) {
      try {
        if (c.fsSink !== undefined) {
          analyzer ??= new SinkAnalyzer(f, "path");
          const t = analyzer.argTaint(c.fsSink.arg, c.fsSink.callStart);
          if (t !== undefined && t.hit.trust === "remote") continue; // path-traversal owns it
        }
        if (c.lib === "express-fileupload" && (await this.safeFileNamesOn(context, f, run)))
          continue;
        let high = c.lib === "formidable" || c.busboy0x;
        let source: string | undefined;
        if (!high && c.lib !== "formidable") {
          const info = await legacyUploadParser(
            context,
            f.file,
            c.lib,
            run.manifestCache,
            run.lockCache,
          );
          if (info.legacy) {
            high = true;
            source = info.source;
          }
        }
        out.push(this.diskFinding(f, c, high, source));
      } catch {
        // skip this candidate
      }
    }
    return out;
  }

  private async safeFileNamesOn(
    context: ScanContext,
    f: SinkFile,
    run: RunState,
  ): Promise<boolean> {
    if (/safeFileNames\s*:\s*true/.test(f.src.text)) return true;
    return (await this.projectFacts(context, run)).safeFileNames;
  }

  private multerDisk(f: SinkFile, out: DiskCandidate[]): void {
    const { src } = f;
    for (const call of allMatches(src.code, /(?<![\w$])diskStorage\s*\(/g, src)) {
      const first = call.args[0];
      if (first === undefined || src.code[first.start] !== "{") continue;
      const prop = objectProps(src, first.start)?.props.get("filename");
      if (prop === undefined) continue;
      const span = f.spans.find((s) => s.start >= prop.start && s.end <= prop.end);
      const pName = span?.params[1]?.names[0];
      const cbName = span?.params[2]?.names[0];
      if (span === undefined || pName === undefined || cbName === undefined) continue;
      const token = new RegExp(`\\b${escapeRe(pName)}\\s*\\.\\s*originalname\\b`);
      const body = src.code.slice(span.bodyStart, span.bodyEnd);
      const cb = new RegExp(`(?<![\\w$.])${escapeRe(cbName)}\\s*\\(`, "g");
      for (const m of body.matchAll(cb)) {
        const open = span.bodyStart + m.index + m[0].length - 1;
        const close = src.matchOf(open);
        if (close < 0) continue;
        const args = splitArgs(src, open, close).map((r) => trimRange(src, r));
        const [a0, a1] = args;
        if (a0 === undefined || a1 === undefined) continue;
        if (src.code.slice(a0.start, a0.end).trim() !== "null") continue;
        const expr = resolveHop(src, span, src.code.slice(a1.start, a1.end).trim());
        if (!token.test(expr) || isSanitizedFilename(expr, token)) continue;
        out.push({
          lib: "multer",
          offset: span.bodyStart + m.index,
          member: memberOf(expr, token),
          fsSink: undefined,
          busboy0x: false,
        });
      }
    }
  }

  private fileUploadDisk(f: SinkFile, bind: UploadBindings, out: DiskCandidate[]): void {
    const { src } = f;
    if (bind.fileUpload.length === 0 && !src.text.includes("express-fileupload")) return;
    for (const mv of allMatches(src.code, /\.\s*mv\s*\(/g, src)) {
      const arg = mv.args[0];
      if (arg === undefined) continue;
      const recv = receiverBefore(src.code, mv.start);
      if (recv === undefined) continue;
      const span = enclosingFunction(f.spans, mv.start) ?? moduleSpan(src);
      const vars = fileBindings(src, span);
      const root = /^[A-Za-z_$][\w$]*/.exec(recv)?.[0];
      const isReqFile = /^req\s*\.\s*files\b/.test(recv);
      if (!isReqFile && (root === undefined || !vars.has(root))) continue;
      const expr = resolveHop(src, span, src.code.slice(arg.start, arg.end).trim());
      const token = /\.\s*name\b/;
      if (!readsClientFileName(expr, vars) || isSanitizedFilename(expr, token)) continue;
      out.push({
        lib: "express-fileupload",
        offset: mv.start,
        member: memberOf(expr, token),
        fsSink: undefined,
        busboy0x: false,
      });
    }
  }

  private busboyDisk(f: SinkFile, out: DiskCandidate[]): void {
    const { src } = f;
    for (const on of busboyFileHandlers(src)) {
      const cbRange = on.args[1];
      if (cbRange === undefined) continue;
      const span = f.spans.find((s) => s.start >= cbRange.start && s.end <= cbRange.end);
      const p2 = span?.params[2];
      if (span === undefined || p2 === undefined) continue;
      const names: string[] = [];
      let info: string | undefined;
      let busboy0x = false;
      if (p2.pattern === "filename") {
        names.push("filename");
        busboy0x = true;
      } else if (IDENT_ONLY_RE.test(p2.pattern)) {
        info = p2.pattern;
      } else {
        const alias = filenameAlias(p2.pattern);
        if (alias !== undefined) names.push(alias);
      }
      const body = src.code.slice(span.bodyStart, span.bodyEnd);
      if (info !== undefined) {
        const d = new RegExp(
          `\\b(?:const|let|var)\\s*\\{([^}]*)\\}\\s*=\\s*${escapeRe(info)}\\b`,
        ).exec(body);
        const alias = d?.[1] === undefined ? undefined : filenameAlias(d[1]);
        if (alias !== undefined) names.push(alias);
      }
      const parts: string[] = [];
      if (info !== undefined) parts.push(`\\b${escapeRe(info)}\\s*\\.\\s*filename\\b`);
      for (const n of names) parts.push(`(?<![.\\w$])${escapeRe(n)}\\b`);
      if (parts.length === 0) continue;
      const token = new RegExp(parts.join("|"));
      for (const call of allMatches(body, FS_WRITE_RE, src, span.bodyStart)) {
        const arg = call.args[0];
        if (arg === undefined) continue;
        const expr = resolveHop(src, span, src.code.slice(arg.start, arg.end).trim());
        if (!token.test(expr) || isSanitizedFilename(expr, token)) continue;
        out.push({
          lib: "busboy",
          offset: call.start,
          member: memberOf(expr, token),
          fsSink: { arg, callStart: call.start },
          busboy0x,
        });
      }
    }
  }

  private formidableDisk(f: SinkFile, bind: UploadBindings, out: DiskCandidate[]): void {
    const { src } = f;
    const token = /\.\s*originalFilename\b/;
    for (const name of bind.formidable) {
      const re = new RegExp(
        `(?<![\\w$.])${escapeRe(name)}(?:\\s*\\.\\s*IncomingForm)?\\s*\\(`,
        "g",
      );
      for (const call of allMatches(src.code, re, src)) {
        const first = call.args[0];
        if (first === undefined || src.code[first.start] !== "{") continue;
        const prop = objectProps(src, first.start)?.props.get("filename");
        if (prop === undefined) continue;
        const span = f.spans.find((s) => s.start >= prop.start && s.end <= prop.end);
        const pName = span?.params[2]?.names[0];
        if (span === undefined || pName === undefined) continue;
        const own = new RegExp(`(?<![\\w$.])${escapeRe(pName)}\\s*\\.\\s*originalFilename\\b`);
        const body = src.code.slice(span.bodyStart, span.bodyEnd);
        const m = own.exec(body);
        if (m === null || isSanitizedFilename(body, own)) continue;
        out.push({
          lib: "formidable",
          offset: span.bodyStart + m.index,
          member: memberOf(body, own),
          fsSink: undefined,
          busboy0x: false,
        });
      }
    }
    for (const call of allMatches(src.code, FS_MOVE_RE, src)) {
      const arg = call.args[1];
      if (arg === undefined) continue;
      const span = enclosingFunction(f.spans, call.start) ?? moduleSpan(src);
      const expr = resolveHop(src, span, src.code.slice(arg.start, arg.end).trim());
      if (!token.test(expr) || isSanitizedFilename(expr, token)) continue;
      out.push({
        lib: "formidable",
        offset: call.start,
        member: memberOf(expr, token),
        fsSink: { arg, callStart: call.start },
        busboy0x: false,
      });
    }
  }

  // ---------------------------------------------------------------------------
  // U3b
  // ---------------------------------------------------------------------------

  private storageFindings(f: SinkFile, bind: UploadBindings): Finding[] {
    const { src } = f;
    const out: Finding[] = [];
    const seen = new Set<number>();
    const report = (callStart: number, keyRange: Range, lib: string, publicAcl: boolean): void => {
      if (seen.has(callStart)) return;
      try {
        const span = enclosingFunction(f.spans, callStart) ?? moduleSpan(src);
        const raw = src.code.slice(keyRange.start, keyRange.end).trim();
        const resolved = resolveHop(src, span, raw);
        if (hasUniqueOrOwnerPart(resolved) || hasUniqueOrOwnerPart(raw)) return;
        let client = readsClientFileName(resolved, fileBindings(src, span));
        if (!client) {
          const hit = analyzeTaint(src, span).exprTaint(keyRange.start, keyRange.end);
          client = hit !== undefined && hit.trust === "remote" && hit.source.id !== "parameter";
        }
        if (!client) return;
        seen.add(callStart);
        out.push(this.keyFinding(f, callStart, keyRange.start, lib, publicAcl));
      } catch {
        // skip this call
      }
    };
    const props = (open: number): ObjectProps | undefined =>
      src.code[open] === "{" ? objectProps(src, open) : undefined;
    const aclPublic = (p: ObjectProps): boolean => {
      const a = p.props.get("ACL");
      return (
        a !== undefined && /["']public-read(?:-write)?["']/.test(src.text.slice(a.start, a.end))
      );
    };

    for (const call of allMatches(src.code, /\bnew\s+PutObjectCommand\s*\(/g, src)) {
      const p = call.args[0] === undefined ? undefined : props(call.args[0].start);
      const key = p?.props.get("Key");
      if (p !== undefined && key !== undefined) report(call.start, key, "s3", aclPublic(p));
    }
    if (src.text.includes("@aws-sdk")) {
      for (const call of allMatches(src.code, /\bnew\s+Upload\s*\(/g, src)) {
        const p = call.args[0] === undefined ? undefined : props(call.args[0].start);
        const params = p?.props.get("params");
        const pp = params === undefined ? undefined : props(trimRange(src, params).start);
        const key = pp?.props.get("Key");
        if (pp !== undefined && key !== undefined) report(call.start, key, "s3", aclPublic(pp));
      }
    }
    for (const call of allMatches(src.code, /\.\s*(?:upload|putObject)\s*\(/g, src)) {
      const a0 = call.args[0];
      if (a0 === undefined) continue;
      const p = props(a0.start);
      const key = p?.props.get("Key");
      if (p !== undefined && key !== undefined && p.props.has("Bucket")) {
        report(call.start, key, "s3", aclPublic(p));
      }
    }
    for (const from of allMatches(src.code, /\.\s*storage\s*\.\s*from\s*\(/g, src)) {
      const after = /^\s*\.\s*upload\s*\(/.exec(src.code.slice(from.close + 1, from.close + 40));
      if (after === null) continue;
      const open = from.close + after[0].length;
      const close = src.matchOf(open);
      if (close < 0) continue;
      const args = splitArgs(src, open, close).map((r) => trimRange(src, r));
      const [path, , opts] = args;
      if (path === undefined || opts === undefined) continue;
      const o = props(opts.start);
      const up = o?.props.get("upsert");
      if (up === undefined || src.code.slice(up.start, up.end).trim() !== "true") continue;
      report(from.start, path, "supabase", false);
    }
    for (const fileCall of allMatches(src.code, /\.\s*file\s*\(/g, src)) {
      const before = src.code.slice(Math.max(0, fileCall.start - 60), fileCall.start);
      if (!/bucket/i.test(before)) continue;
      const after = /^\s*\.\s*(?:save|createWriteStream)\s*\(/.exec(
        src.code.slice(fileCall.close + 1, fileCall.close + 40),
      );
      const a0 = fileCall.args[0];
      if (after !== null && a0 !== undefined) report(fileCall.start, a0, "gcs", false);
    }
    for (const call of allMatches(src.code, /\.\s*upload\s*\(/g, src)) {
      const before = src.code.slice(Math.max(0, call.start - 60), call.start);
      if (!/bucket/i.test(before)) continue;
      const a1 = call.args[1];
      const o = a1 === undefined ? undefined : props(a1.start);
      const dest = o?.props.get("destination");
      if (dest !== undefined) report(call.start, dest, "gcs", false);
    }
    for (const name of bind.vercelPut) {
      for (const call of callsOf(src, name)) {
        const [path, , opts] = call.args;
        if (path === undefined || opts === undefined) continue;
        const o = props(opts.start);
        const ow = o?.props.get("allowOverwrite");
        if (ow === undefined || src.code.slice(ow.start, ow.end).trim() !== "true") continue;
        report(call.start, path, "vercel-blob", false);
      }
    }
    return out;
  }

  // ---------------------------------------------------------------------------
  // Finding builders
  // ---------------------------------------------------------------------------

  private sizeFinding(f: SinkFile, offset: number, lib: string): Finding {
    const line = f.src.lineAt(offset);
    return makeFinding({
      category: "validation",
      ruleId: "validation/upload-no-size-limit",
      title: "File upload has no size limit",
      severity: "medium",
      confidence: "high",
      file: f.file,
      line,
      evidence: f.src.lineText(line).trim(),
      discriminator: callKey(f.src, offset, lib),
      plainEnglishProblem:
        "This upload middleware accepts files of any size (`limits.fileSize` is not set), so one request can fill the server's memory or disk.",
      whyItMatters:
        "Without a cap, a single large or repeated upload can exhaust memory or disk (denial of service) and run up storage and bandwidth costs.",
      fixSteps: [
        "Set a per-file limit and a file count, for example `multer({ limits: { fileSize: 5 * 1024 * 1024, files: 1 } })` (busboy: `limits: { fileSize }`, express-fileupload: `limits: { fileSize }, abortOnLimit: true`).",
        "Return 413 when the limit is hit and keep the limit as small as the feature needs.",
        "Also cap the request body size at the reverse proxy or platform.",
      ],
      aiFixPrompt: SIZE_PROMPT,
      learnMoreUrl: LEARN_MORE,
    });
  }

  private typeFinding(f: SinkFile, offset: number, lib: string, isPublic: boolean): Finding {
    const line = f.src.lineAt(offset);
    return makeFinding({
      category: "validation",
      ruleId: "validation/upload-no-type-check",
      title: "Uploaded files are not checked for type",
      severity: isPublic ? "medium" : "low",
      confidence: "medium",
      file: f.file,
      line,
      evidence: f.src.lineText(line).trim(),
      discriminator: `${callKey(f.src, offset, lib)}:u2`,
      plainEnglishProblem:
        "Uploaded files are stored without checking their type, so users can upload HTML, SVG or scripts; served from your domain they run as your site (stored XSS).",
      whyItMatters:
        "An uploaded HTML or SVG file opened from your own domain can run script with your site's cookies and privileges, and unexpected file types can reach other parts of your system.",
      fixSteps: [
        "Allowlist the MIME types and extensions the feature needs (for multer, a `fileFilter`).",
        "Verify the real type from the file's magic bytes (for example with the `file-type` package) instead of trusting the client's `Content-Type`.",
        "Store uploads outside `public/` and serve them with `Content-Disposition: attachment` and a fixed `Content-Type`.",
      ],
      aiFixPrompt: TYPE_PROMPT,
      learnMoreUrl: LEARN_MORE,
    });
  }

  private diskFinding(
    f: SinkFile,
    c: DiskCandidate,
    high: boolean,
    source: string | undefined,
  ): Finding {
    const line = f.src.lineAt(c.offset);
    const member = c.member.slice(0, 60);
    let problem: string;
    if (high) {
      problem = `The file is saved under the name the uploader chose (\`${member}\`). A name like \`../../server.js\` writes outside the upload folder, and equal names overwrite each other.`;
      if (source !== undefined) {
        problem += ` This project uses \`${source}\`, which passes the raw file name through (busboy < 1.0 does not strip directory parts).`;
      }
      if (c.busboy0x) {
        problem +=
          " The `(fieldname, file, filename, ...)` callback is the busboy < 1.0 API, which passes the raw file name through.";
      }
    } else {
      problem = `The file is saved under the name the uploader chose (\`${member}\`). Two uploads with the same name overwrite each other (including other users' files), and the uploader picks the extension and name (\`index.html\`, \`.htaccess\`); with busboy < 1.0 a name like \`../../server.js\` also escapes the upload folder.`;
    }
    return makeFinding({
      category: "validation",
      ruleId: "validation/upload-unsafe-filename",
      title: "Stored file name or key comes from the uploader",
      severity: high ? "high" : "medium",
      confidence: "high",
      file: f.file,
      line,
      evidence: f.src.lineText(line).trim(),
      discriminator: callKey(f.src, c.offset, c.lib),
      plainEnglishProblem: problem,
      whyItMatters:
        "Overwriting lets one user replace another user's file; an uploader-chosen extension turns a stored file into a page or script when the folder is served.",
      fixSteps: [
        "Generate the stored name on the server (`crypto.randomUUID() + allowedExt`) and keep the original name only in the database.",
        "Take the extension from an allowlisted MIME type, not from the uploaded name.",
        "On old multer, busboy or express-fileupload also upgrade (multer `^2`, busboy `^1`, express-fileupload `^1.5`).",
      ],
      aiFixPrompt: NAME_PROMPT,
      learnMoreUrl: LEARN_MORE,
    });
  }

  private keyFinding(
    f: SinkFile,
    callStart: number,
    anchor: number,
    lib: string,
    publicAcl: boolean,
  ): Finding {
    const line = f.src.lineAt(anchor);
    return makeFinding({
      category: "validation",
      ruleId: "validation/upload-unsafe-filename",
      title: "Stored file name or key comes from the uploader",
      severity: publicAcl ? "high" : "medium",
      confidence: "medium",
      file: f.file,
      line,
      evidence: f.src.lineText(line).trim(),
      discriminator: callKey(f.src, callStart, lib),
      plainEnglishProblem: `The storage key is the uploader's file name, so a second upload with the same name replaces the first, including other users' files${publicAcl ? " and, with a public ACL, files everyone downloads" : ""}.`,
      whyItMatters:
        "Overwriting lets one user replace another user's file; an uploader-chosen extension turns a stored file into a page or script when the bucket is served.",
      fixSteps: [
        "Build the key on the server: `${userId}/${crypto.randomUUID()}${ext}`, with the extension taken from an allowlisted MIME type.",
        "Keep the original file name only as metadata in your database.",
        "Use a private bucket and signed URLs instead of public-read objects.",
      ],
      aiFixPrompt: NAME_PROMPT,
      learnMoreUrl: LEARN_MORE,
    });
  }
}

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Calls to the bare identifier `name` (`name(` / `new name(`), with balanced parentheses. */
function callsOf(src: SinkFile["src"], name: string): Call[] {
  return allMatches(src.code, new RegExp(`(?<![\\w$.])${escapeRe(name)}\\s*\\(`, "g"), src);
}

/**
 * Matches of `re` (which must end in `(`) in `code`, as calls with their top-level arguments.
 * `base` is added to match offsets when `code` is a slice of the file.
 */
function allMatches(code: string, re: RegExp, src: SinkFile["src"], base = 0): Call[] {
  const out: Call[] = [];
  for (const m of code.matchAll(re)) {
    const start = base + m.index;
    const open = start + m[0].length - 1;
    const close = src.matchOf(open);
    if (src.code[open] !== "(" || close < 0) continue;
    out.push({
      start,
      open,
      close,
      args: splitArgs(src, open, close).map((r) => trimRange(src, r)),
    });
  }
  return out;
}

/** `X.on("file", ...)` handler calls (the literal is read from the original text). */
function busboyFileHandlers(src: SinkFile["src"]): Call[] {
  return allMatches(src.code, /\.\s*on\s*\(/g, src).filter((c) =>
    /^\s*["']file["']/.test(src.text.slice(c.open + 1, c.open + 20)),
  );
}

function cfgOf(src: SinkFile["src"], call: Call): Cfg {
  const a = call.args[0];
  if (a === undefined || a.end <= a.start) return { kind: "none" };
  const t = src.code.slice(a.start, a.end).trim();
  let open = -1;
  if (t.startsWith("{")) open = a.start + src.code.slice(a.start, a.end).indexOf("{");
  else if (IDENT_ONLY_RE.test(t)) open = resolveObjectIdentifier(src, t) ?? -1;
  if (open < 0) return { kind: "unknown" };
  const obj = objectProps(src, open);
  return obj === undefined ? { kind: "unknown" } : { kind: "obj", obj };
}

/** Whether `limits.fileSize` is set: `ok`, `missing`, or `unknown` (imported or spread config). */
function limitsState(src: SinkFile["src"], cfg: Cfg): "ok" | "missing" | "unknown" {
  if (cfg.kind === "none") return "missing";
  if (cfg.kind === "unknown") return "unknown";
  const limits = cfg.obj.props.get("limits");
  if (limits === undefined) return cfg.obj.spreads.length > 0 ? "unknown" : "missing";
  const r = trimRange(src, limits);
  const t = src.code.slice(r.start, r.end);
  let open = -1;
  if (t.startsWith("{")) open = r.start;
  else if (IDENT_ONLY_RE.test(t)) open = resolveObjectIdentifier(src, t) ?? -1;
  if (open < 0) return "unknown";
  const inner = objectProps(src, open);
  if (inner === undefined) return "unknown";
  if (inner.props.has("fileSize")) return "ok";
  return inner.spreads.length > 0 ? "unknown" : "missing";
}

function filterState(cfg: Cfg): "ok" | "missing" | "unknown" {
  if (cfg.kind === "none") return "missing";
  if (cfg.kind === "unknown") return "unknown";
  if (cfg.obj.props.has("fileFilter")) return "ok";
  return cfg.obj.spreads.length > 0 ? "unknown" : "missing";
}

/** One-hop resolution of a bare identifier to its `const/let/var` initializer inside `span`. */
function resolveHop(src: SinkFile["src"], span: FunctionSpan, text: string): string {
  if (!IDENT_ONLY_RE.test(text)) return text;
  const code = src.code.slice(span.start, span.end);
  const m = new RegExp(
    `\\b(?:const|let|var)\\s+${escapeRe(text)}\\s*(?::[^=\\n]{1,40})?=(?!=)\\s*`,
  ).exec(code);
  if (m === null) return text;
  const start = span.start + m.index + m[0].length;
  const end = expressionEnd(src, start, span.end);
  return src.code.slice(start, Math.max(start, end)).trim() || text;
}

/** The client-name member as written, e.g. `file.originalname` (whitespace removed). */
function memberOf(expr: string, token: RegExp): string {
  const flags = token.flags.replace("g", "");
  const m = new RegExp(token.source, flags).exec(expr);
  if (m === null) return "the client file name";
  let start = m.index;
  while (start > 0 && /[\w$.]/.test(expr[start - 1]!)) start--;
  return expr
    .slice(start, m.index + m[0].length)
    .replace(/\s+/g, "")
    .slice(0, 60);
}

/** Receiver expression text directly before the `.` at `dot` (member chain / index), or undefined. */
function receiverBefore(code: string, dot: number): string | undefined {
  const before = code.slice(Math.max(0, dot - 80), dot);
  const m = /([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*|\s*\[[^\]\n]*\])*)\s*$/.exec(before);
  return m?.[1];
}

/** Local name `filename` is bound to in a destructuring pattern (`{ filename }`, `{ filename: fn }`). */
function filenameAlias(pattern: string): string | undefined {
  const m = /(?<![\w$])filename\s*(?::\s*([A-Za-z_$][\w$]*))?/.exec(pattern);
  if (m === null) return undefined;
  return m[1] ?? "filename";
}
