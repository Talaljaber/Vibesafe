import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { createJsSource } from "../../src/detectors/utils/js-source.js";
import { extractFunctions, moduleSpan } from "../../src/detectors/utils/js-functions.js";
import type { LockfileInfo } from "../../src/detectors/utils/deps-manifest.js";
import {
  fileBindings,
  hasUniqueOrOwnerPart,
  isSanitizedFilename,
  legacyUploadParser,
  objectProps,
  readsClientFileName,
  resolveObjectIdentifier,
  uploadBindings,
  type ParserVersionInfo,
} from "../../src/detectors/utils/upload-patterns.js";
import { createContext } from "../helpers/injection.js";

const lines = (...l: string[]): string => l.join("\n");

describe("uploadBindings", () => {
  it("finds default imports, requires and named imports", () => {
    const src = createJsSource(
      lines(
        'import multer from "multer";',
        'const Busboy = require("busboy");',
        'import fileUpload from "express-fileupload";',
        'import { IncomingForm, formidable as fm } from "formidable";',
        'import { put as blobPut } from "@vercel/blob";',
      ),
    );
    const b = uploadBindings(src);
    expect(b.multer).toEqual(["multer"]);
    expect(b.busboy).toEqual(["Busboy"]);
    expect(b.fileUpload).toEqual(["fileUpload"]);
    expect(b.formidable).toEqual(["IncomingForm", "fm"]);
    expect(b.vercelPut).toEqual(["blobPut"]);
  });

  it("ignores imports inside comments and strings", () => {
    const src = createJsSource(
      lines('// import multer from "multer";', "const s = 'import busboy from \"busboy\"';"),
    );
    const b = uploadBindings(src);
    expect(b.multer).toEqual([]);
    expect(b.busboy).toEqual([]);
  });
});

describe("objectProps and resolveObjectIdentifier", () => {
  it("reads keys, shorthand, quoted keys, methods and spreads", () => {
    const text =
      'const o = { storage, "limits": { fileSize: 1 }, fileFilter(req, f, cb) {}, ...rest, dest: "x" };';
    const src = createJsSource(text);
    const p = objectProps(src, text.indexOf("{"))!;
    expect([...p.props.keys()]).toEqual(["storage", "limits", "fileFilter", "dest"]);
    expect(p.spreads).toHaveLength(1);
    const lim = p.props.get("limits")!;
    expect(text.slice(lim.start, lim.end).trim()).toBe("{ fileSize: 1 }");
  });

  it("resolves a same-file const object and nothing else", () => {
    const text = 'const OPTS = { dest: "x" };\nconst other = make();';
    const src = createJsSource(text);
    expect(resolveObjectIdentifier(src, "OPTS")).toBe(text.indexOf("{"));
    expect(resolveObjectIdentifier(src, "other")).toBeUndefined();
    expect(resolveObjectIdentifier(src, "missing")).toBeUndefined();
  });
});

describe("fileBindings", () => {
  const bind = (code: string, role?: "server-action"): Set<string> => {
    const src = createJsSource(code, { jsx: false });
    const spans = extractFunctions(src);
    const span = spans[0] ?? moduleSpan(src);
    if (role !== undefined) span.role = role;
    return fileBindings(src, span);
  };

  it("collects FormData get, getAll loops, req.file(s), annotations and instanceof", () => {
    const set = bind(
      lines(
        "async function f(req) {",
        "  const form = await req.formData();",
        '  const a = form.get("a") as File;',
        '  const b = formData.get("b");',
        "  const c = req.file;",
        "  const d = req.files.doc;",
        "  const { e } = req.files;",
        "  function g(h: File) {}",
        "  if (i instanceof Blob) {}",
        '  for (const j of form.getAll("js") as File[]) {}',
        "}",
      ),
    );
    for (const n of ["a", "b", "c", "d", "e", "h", "i", "j"]) expect(set.has(n), n).toBe(true);
  });

  it("uses the first parameter of a server action as the form", () => {
    const set = bind(
      lines("async function up(payload) {", '  const f = payload.get("file");', "}"),
      "server-action",
    );
    expect(set.has("f")).toBe(true);
  });

  it("does not include org, user or plain parameters", () => {
    const set = bind(
      lines(
        "async function f(filename: string, org, user) {",
        "  const name = org.name;",
        "  const u = user.id;",
        "}",
      ),
    );
    expect([...set]).toEqual([]);
  });
});

describe("readsClientFileName, sanitizers and unique parts", () => {
  it("reads upload client names", () => {
    const none = new Set<string>();
    expect(readsClientFileName("file.originalname", none)).toBe(true);
    expect(readsClientFileName("part.originalFilename", none)).toBe(true);
    expect(readsClientFileName("req.file.originalname", none)).toBe(true);
    expect(readsClientFileName("req.files.avatar.name", none)).toBe(true);
    expect(readsClientFileName("f.name", new Set(["f"]))).toBe(true);
    expect(readsClientFileName("f.name", none)).toBe(false);
    expect(readsClientFileName("org.name", new Set(["f"]))).toBe(false);
    expect(readsClientFileName("filename", new Set(["f"]))).toBe(false);
  });

  it("treats basename, sanitize and extname-only names as sanitized", () => {
    const token = /\bfile\.originalname\b/;
    expect(isSanitizedFilename("path.basename(file.originalname)", token)).toBe(true);
    expect(isSanitizedFilename("sanitize(file.originalname)", token)).toBe(true);
    expect(isSanitizedFilename("slugify(file.originalname)", token)).toBe(true);
    expect(isSanitizedFilename("`${id}${path.extname(file.originalname)}`", token)).toBe(true);
    expect(isSanitizedFilename("extname(file.originalname) + file.originalname", token)).toBe(
      false,
    );
    expect(isSanitizedFilename("Date.now() + file.originalname", token)).toBe(false);
  });

  it("recognises unique or owner-scoped parts", () => {
    expect(hasUniqueOrOwnerPart("`${crypto.randomUUID()}.png`")).toBe(true);
    expect(hasUniqueOrOwnerPart("`${user.id}/${name}`")).toBe(true);
    expect(hasUniqueOrOwnerPart("Date.now() + name")).toBe(true);
    expect(hasUniqueOrOwnerPart("file.name")).toBe(false);
  });
});

describe("legacyUploadParser", () => {
  const check = async (
    files: Record<string, string>,
    lib: "multer" | "busboy" | "express-fileupload",
    file = "server.js",
  ): Promise<ParserVersionInfo> =>
    legacyUploadParser(
      createContext(files),
      file,
      lib,
      new Map<string, ParserVersionInfo>(),
      new Map<string, LockfileInfo>(),
    );
  const pkg = (deps: Record<string, string>): string => JSON.stringify({ dependencies: deps });
  const lock = (name: string, version: string): string =>
    JSON.stringify({
      lockfileVersion: 3,
      packages: { "": {}, [`node_modules/${name}`]: { version } },
    });

  it("treats pre-fix ranges as legacy and fixed ranges as not", async () => {
    for (const spec of ["^1.4.2", "~1.4.4", "1.x", "1.4.4"]) {
      const r = await check({ "package.json": pkg({ multer: spec }) }, "multer");
      expect(r.legacy, spec).toBe(true);
      expect(r.source).toBe(`multer@${spec}`);
    }
    for (const spec of ["^1.4.5-lts.1", "^2.0.0", ">=1.4.0", "*", "1.4.5-lts.1", "latest"]) {
      const r = await check({ "package.json": pkg({ multer: spec }) }, "multer");
      expect(r.legacy, spec).toBe(false);
      expect(r.source).toBeUndefined();
    }
    expect((await check({ "package.json": pkg({ busboy: "^0.3.1" }) }, "busboy")).legacy).toBe(
      true,
    );
    expect((await check({ "package.json": pkg({ busboy: "^1.6.0" }) }, "busboy")).legacy).toBe(
      false,
    );
    const f = "express-fileupload";
    expect((await check({ "package.json": pkg({ [f]: "^1.2.0" }) }, f)).legacy).toBe(false);
    expect((await check({ "package.json": pkg({ [f]: "1.2.1" }) }, f)).legacy).toBe(true);
  });

  it("is not legacy without a declaring manifest, for tags, git and workspace specs", async () => {
    expect((await check({}, "multer")).legacy).toBe(false);
    expect((await check({ "package.json": pkg({ express: "4" }) }, "multer")).legacy).toBe(false);
    for (const spec of ["github:expressjs/multer", "workspace:*", "npm:other@1.0.0", "file:../x"]) {
      expect((await check({ "package.json": pkg({ multer: spec }) }, "multer")).legacy, spec).toBe(
        false,
      );
    }
  });

  it("lets the lockfile beat the spec", async () => {
    const old = await check(
      { "package.json": pkg({ multer: "*" }), "package-lock.json": lock("multer", "1.4.4") },
      "multer",
    );
    expect(old).toEqual({ legacy: true, source: "multer@1.4.4 (package-lock.json)" });
    const fresh = await check(
      {
        "package.json": pkg({ multer: "^1.4.2" }),
        "package-lock.json": lock("multer", "1.4.5-lts.2"),
      },
      "multer",
    );
    expect(fresh.legacy).toBe(false);
  });

  it("uses the nearest declaring manifest", async () => {
    const files = {
      "package.json": pkg({ multer: "^2.0.0" }),
      "apps/api/package.json": pkg({ multer: "~1.4.4" }),
      "apps/web/package.json": pkg({ react: "18" }),
    };
    expect((await check(files, "multer", "apps/api/src/server.js")).legacy).toBe(true);
    expect((await check(files, "multer", "apps/web/server.js")).legacy).toBe(false);
    expect((await check(files, "multer", "server.js")).legacy).toBe(false);
  });

  it("does not throw on a broken manifest or an unreadable lockfile and falls back to the spec", async () => {
    expect((await check({ "package.json": "{ not json" }, "multer")).legacy).toBe(false);
    const ctx = createContext({ "package.json": pkg({ multer: "^1.4.2" }) });
    const throwing: ScanContext = {
      ...ctx,
      readFile: async (f) => {
        if (f === "package.json") return pkg({ multer: "^1.4.2" });
        throw new Error("boom");
      },
    };
    const r = await legacyUploadParser(throwing, "server.js", "multer", new Map(), new Map());
    expect(r.legacy).toBe(true);
    const broken: ScanContext = {
      ...ctx,
      readFile: async () => {
        throw new Error("boom");
      },
    };
    const none = await legacyUploadParser(broken, "server.js", "multer", new Map(), new Map());
    expect(none.legacy).toBe(false);
  });
});
