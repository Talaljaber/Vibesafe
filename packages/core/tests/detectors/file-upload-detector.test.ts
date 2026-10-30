import { describe, it, expect } from "vitest";
import type { Finding } from "@talaljaber/vibesafe-shared";
import { FileUploadDetector } from "../../src/detectors/file-upload-detector.js";
import { PathTraversalDetector } from "../../src/detectors/path-traversal-detector.js";
import { expectRubric } from "../helpers/rubric.js";
import { run } from "../helpers/injection.js";

const detector = new FileUploadDetector();
const SIZE = "validation/upload-no-size-limit";
const TYPE = "validation/upload-no-type-check";
const NAME = "validation/upload-unsafe-filename";

const lines = (...l: string[]): string => l.join("\n");
const byRule = (fs: Finding[], rule: string): Finding[] => fs.filter((f) => f.ruleId === rule);
const scan = (files: Record<string, string>): Promise<Finding[]> => run(detector, files);

const MEDIUM_TEXT =
  "The file is saved under the name the uploader chose (`file.originalname`). Two uploads with the same name overwrite each other (including other users' files), and the uploader picks the extension and name (`index.html`, `.htaccess`); with busboy < 1.0 a name like `../../server.js` also escapes the upload folder.";

const MULTER_DISK = lines(
  'const multer = require("multer");',
  "const storage = multer.diskStorage({",
  '  destination: "uploads/",',
  '  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname),',
  "});",
  'const upload = multer({ storage, limits: { fileSize: 1000 }, fileFilter: (r, f, cb) => cb(null, f.mimetype === "image/png") });',
);

const pkg = (deps: Record<string, string>): string => JSON.stringify({ dependencies: deps });

describe("FileUploadDetector: size limits (U1)", () => {
  it("flags multer({ dest }) for size (medium/high) and type (low/medium) on one line", async () => {
    const fs = await scan({
      "server.js": lines(
        'const multer = require("multer");',
        'const upload = multer({ dest: "uploads/" });',
      ),
    });
    const size = byRule(fs, SIZE);
    const type = byRule(fs, TYPE);
    expect(size).toHaveLength(1);
    expect(type).toHaveLength(1);
    expect([size[0]!.severity, size[0]!.confidence]).toEqual(["medium", "high"]);
    expect([type[0]!.severity, type[0]!.confidence]).toEqual(["low", "medium"]);
    expect(size[0]!.line).toBe(2);
    expect(type[0]!.line).toBe(2);
    expect(size[0]!.id).not.toBe(type[0]!.id);
    expectRubric(fs);
  });

  it("flags multer() with no arguments and limits without fileSize", async () => {
    const a = await scan({
      "server.js": lines('import multer from "multer";', "export const upload = multer();"),
    });
    expect(byRule(a, SIZE)).toHaveLength(1);
    const b = await scan({
      "server.js": lines(
        'import multer from "multer";',
        "const storage = multer.memoryStorage();",
        "export const upload = multer({ storage, limits: { files: 3 } });",
      ),
    });
    expect(byRule(b, SIZE)).toHaveLength(1);
    expect(byRule(b, SIZE)[0]!.line).toBe(3);
  });

  it("resolves a same-file options object", async () => {
    const fs = await scan({
      "server.js": lines(
        'const multer = require("multer");',
        'const OPTS = { dest: "uploads/" };',
        "const upload = multer(OPTS);",
      ),
    });
    expect(byRule(fs, SIZE)).toHaveLength(1);
  });

  it("flags busboy without limits and formidable with an unbounded maxFileSize", async () => {
    const bb = await scan({
      "server.js": lines(
        'const busboy = require("busboy");',
        "function handle(req, res) {",
        "  const bb = busboy({ headers: req.headers });",
        "  req.pipe(bb);",
        "}",
      ),
    });
    expect(byRule(bb, SIZE)).toHaveLength(1);
    const fm = await scan({
      "server.js": lines(
        'import formidable from "formidable";',
        "export const form = formidable({ maxFileSize: Infinity });",
      ),
    });
    expect(byRule(fm, SIZE)).toHaveLength(1);
    const fm2 = await scan({
      "server.js": lines(
        'import { IncomingForm } from "formidable";',
        "export const form = new IncomingForm({ maxFileSize: Number.MAX_SAFE_INTEGER });",
      ),
    });
    expect(byRule(fm2, SIZE)).toHaveLength(1);
  });

  it("flags express-fileupload without limits, including useTempFiles", async () => {
    const fs = await scan({
      "server.js": lines(
        'const fileUpload = require("express-fileupload");',
        "app.use(fileUpload({ useTempFiles: true }));",
      ),
    });
    expect(byRule(fs, SIZE)).toHaveLength(1);
  });

  it("is silent when limits.fileSize is set, imported or a same-file constant", async () => {
    const fs = await scan({
      "a.js": lines(
        'const multer = require("multer");',
        "const upload = multer({ storage, limits: { fileSize: 5_000_000 }, fileFilter });",
      ),
      "b.js": lines(
        'import multer from "multer";',
        'import { LIMITS } from "./limits.js";',
        'export const upload = multer({ dest: "uploads/", limits: LIMITS });',
      ),
      "c.js": lines(
        'import multer from "multer";',
        "const LIMITS = { fileSize: 1000 };",
        "export const upload = multer({ storage, limits: LIMITS });",
      ),
      "d.js": lines(
        'const fileUpload = require("express-fileupload");',
        "app.use(fileUpload({ limits: { fileSize: 10 * 1024 * 1024 } }));",
      ),
      "e.js": lines(
        'import formidable from "formidable";',
        "export const form = formidable({ maxFileSize: 5 * 1024 * 1024 });",
      ),
    });
    expect(byRule(fs, SIZE)).toHaveLength(0);
  });
});

describe("FileUploadDetector: type checks (U2)", () => {
  it("anchors busboy at the first .on('file' with discriminator col:busboy:u2", async () => {
    const fs = await scan({
      "server.js": lines(
        'const busboy = require("busboy");',
        'app.post("/up", (req, res) => {',
        "  const bb = busboy({ headers: req.headers, limits: { fileSize: 1000 } });",
        '  bb.on("file", (name, stream, info) => {',
        '    stream.pipe(fs.createWriteStream(path.join("uploads", info.filename)));',
        "  });",
        "  req.pipe(bb);",
        "});",
      ),
    });
    const type = byRule(fs, TYPE);
    expect(type).toHaveLength(1);
    expect(type[0]!.line).toBe(4);
    expect(type[0]!.severity).toBe("low");
    expect(type[0]!.endLine).toBeUndefined();
    const name = byRule(fs, NAME);
    expect(name).toHaveLength(1);
    expect([name[0]!.severity, name[0]!.confidence]).toEqual(["medium", "high"]);
    expect(name[0]!.plainEnglishProblem).toContain("`info.filename`");
    expectRubric(fs);
  });

  it("flags express-fileupload at the first req.files read; public when the target is under public/", async () => {
    const fs = await scan({
      "server.js": lines(
        'const fileUpload = require("express-fileupload");',
        "app.use(fileUpload({ limits: { fileSize: 1000 } }));",
        'app.post("/up", (req, res) => {',
        "  if (!req.files) return res.status(400).end();",
        "  req.files.avatar.mv(`./public/uploads/${req.files.avatar.name}`);",
        "});",
      ),
    });
    const type = byRule(fs, TYPE);
    expect(type).toHaveLength(1);
    expect(type[0]!.line).toBe(4);
    expect([type[0]!.severity, type[0]!.confidence]).toEqual(["medium", "medium"]);
    const name = byRule(fs, NAME);
    expect(name).toHaveLength(1);
    expect([name[0]!.severity, name[0]!.confidence]).toEqual(["medium", "high"]);
  });

  it("treats a dest served by express.static in another file as public", async () => {
    const fs = await scan({
      "server.js": lines(
        'const multer = require("multer");',
        'const up = multer({ dest: "uploads/" });',
      ),
      "static.js": 'app.use("/files", express.static(path.join(__dirname, "uploads")));',
    });
    const type = byRule(fs, TYPE);
    expect([type[0]!.severity, type[0]!.confidence]).toEqual(["medium", "medium"]);
  });

  it("reports one U2 for two multer configs and two U1, with stable ids", async () => {
    const files = {
      "server.js": lines(
        'const multer = require("multer");',
        'const a = multer({ dest: "a/" });',
        'const b = multer({ dest: "b/" });',
      ),
    };
    const one = await scan(files);
    const two = await scan(files);
    expect(byRule(one, TYPE)).toHaveLength(1);
    expect(byRule(one, TYPE)[0]!.line).toBe(2);
    expect(byRule(one, SIZE)).toHaveLength(2);
    expect(one.map((f) => f.id)).toEqual(two.map((f) => f.id));
    expectRubric(one);
  });

  it("flags a server action that reads a file without checking file.type", async () => {
    const fs = await scan({
      "app/actions.ts": lines(
        '"use server";',
        'import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";',
        "export async function upload(formData: FormData) {",
        '  const file = formData.get("file") as File;',
        "  await s3.send(new PutObjectCommand({ Bucket, Key: file.name, Body: Buffer.from(await file.arrayBuffer()) }));",
        "}",
      ),
    });
    const type = byRule(fs, TYPE);
    expect(type).toHaveLength(1);
    expect(type[0]!.line).toBe(4);
    const name = byRule(fs, NAME);
    expect(name).toHaveLength(1);
    expect([name[0]!.severity, name[0]!.confidence]).toEqual(["medium", "medium"]);
    expectRubric(fs);
  });

  it("is silent when a type is checked (fileFilter + mimetype, file.type)", async () => {
    const fs = await scan({
      "a.js": lines(
        'const multer = require("multer");',
        "const upload = multer({",
        "  storage,",
        "  limits: { fileSize: 1000 },",
        '  fileFilter: (req, file, cb) => cb(null, file.mimetype.startsWith("image/")),',
        "});",
      ),
      "app/actions.ts": lines(
        '"use server";',
        "export async function upload(formData: FormData) {",
        '  const file = formData.get("file") as File;',
        '  if (!["image/png"].includes(file.type) || file.size > 1000) throw new Error("bad");',
        "  await save(Buffer.from(await file.arrayBuffer()));",
        "}",
      ),
    });
    expect(byRule(fs, TYPE)).toHaveLength(0);
  });
});

describe("FileUploadDetector: unsafe disk names (U3a)", () => {
  it("multer diskStorage with Date.now() + file.originalname is medium/high with the exact text", async () => {
    const fs = await scan({
      "server.js": lines(
        'const multer = require("multer");',
        "const storage = multer.diskStorage({",
        '  destination: "uploads/",',
        '  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname),',
        "});",
        "const upload = multer({ storage, limits: { fileSize: 1000 }, fileFilter });",
      ),
    });
    const name = byRule(fs, NAME);
    expect(name).toHaveLength(1);
    expect([name[0]!.severity, name[0]!.confidence]).toEqual(["medium", "high"]);
    expect(name[0]!.plainEnglishProblem).toBe(MEDIUM_TEXT);
    expect(name[0]!.line).toBe(4);
    expectRubric(fs);
  });

  it("multer ^1.4.2 with no lockfile is high/high and names the version", async () => {
    const fs = await scan({
      "package.json": pkg({ multer: "^1.4.2" }),
      "server.js": MULTER_DISK,
    });
    const name = byRule(fs, NAME);
    expect([name[0]!.severity, name[0]!.confidence]).toEqual(["high", "high"]);
    expect(name[0]!.plainEnglishProblem).toContain("../../server.js");
    expect(name[0]!.plainEnglishProblem).toContain("multer@^1.4.2");
  });

  it("is medium/high for multer ^2.0.0, ^1.4.5-lts.1 and when no manifest declares it", async () => {
    for (const spec of ["^2.0.0", "^1.4.5-lts.1"]) {
      const fs = await scan({ "package.json": pkg({ multer: spec }), "server.js": MULTER_DISK });
      expect(byRule(fs, NAME)[0]!.severity, spec).toBe("medium");
    }
    const fs = await scan({ "package.json": pkg({ express: "^4.0.0" }), "server.js": MULTER_DISK });
    expect(byRule(fs, NAME)[0]!.severity).toBe("medium");
  });

  it("uses the nearest manifest that declares the library", async () => {
    const fs = await scan({
      "package.json": pkg({ multer: "^2.0.0" }),
      "apps/api/package.json": pkg({ multer: "~1.4.4" }),
      "apps/api/server.js": MULTER_DISK,
    });
    expect(byRule(fs, NAME)[0]!.severity).toBe("high");
    expect(byRule(fs, NAME)[0]!.plainEnglishProblem).toContain("multer@~1.4.4");
  });

  it("lockfile versions beat the spec in both directions", async () => {
    const lock = (version: string): string =>
      JSON.stringify({
        lockfileVersion: 3,
        packages: { "": {}, "node_modules/multer": { version } },
      });
    const old = await scan({
      "package.json": pkg({ multer: "*" }),
      "package-lock.json": lock("1.4.4"),
      "server.js": MULTER_DISK,
    });
    expect(byRule(old, NAME)[0]!.severity).toBe("high");
    expect(byRule(old, NAME)[0]!.plainEnglishProblem).toContain("multer@1.4.4 (package-lock.json)");
    const fresh = await scan({
      "package.json": pkg({ multer: "^1.4.2" }),
      "package-lock.json": lock("1.4.5-lts.2"),
      "server.js": MULTER_DISK,
    });
    expect(byRule(fresh, NAME)[0]!.severity).toBe("medium");
  });

  it("formidable originalFilename in fs.rename is high/high whatever the version", async () => {
    const fs = await scan({
      "package.json": pkg({ formidable: "^3.5.0" }),
      "server.js": lines(
        'import formidable from "formidable";',
        'import fs from "fs";',
        'import path from "path";',
        "export function handle(req, res) {",
        "  const form = formidable({ maxFileSize: 1000 });",
        "  form.parse(req, (err, fields, files) => {",
        "    fs.rename(files.doc.filepath, path.join(UPLOAD_DIR, files.doc.originalFilename), cb);",
        "  });",
        "}",
      ),
    });
    const name = byRule(fs, NAME);
    expect(name).toHaveLength(1);
    expect([name[0]!.severity, name[0]!.confidence]).toEqual(["high", "high"]);
  });

  it("the busboy 0.x callback signature is high/high without a manifest", async () => {
    const fs = await scan({
      "server.js": lines(
        'const busboy = require("busboy");',
        'const fs = require("fs");',
        'const path = require("path");',
        "function h(req) {",
        "  const bb = busboy({ headers: req.headers, limits: { fileSize: 1 } });",
        '  bb.on("file", (fieldname, file, filename, encoding, mimetype) =>',
        "    file.pipe(fs.createWriteStream(path.join(UPLOAD_DIR, filename))));",
        "}",
      ),
    });
    const name = byRule(fs, NAME);
    expect(name).toHaveLength(1);
    expect([name[0]!.severity, name[0]!.confidence]).toEqual(["high", "high"]);
    expect(name[0]!.plainEnglishProblem).toContain("busboy < 1.0 API");
  });

  it("express-fileupload 1.2.1 is high/high, ^1.2.0 is medium/high", async () => {
    const code = lines(
      'const fileUpload = require("express-fileupload");',
      "app.use(fileUpload({ limits: { fileSize: 1000 } }));",
      'app.post("/up", (req, res) => {',
      "  req.files.avatar.mv(`./public/uploads/${req.files.avatar.name}`);",
      "});",
    );
    const old = await scan({
      "package.json": pkg({ "express-fileupload": "1.2.1" }),
      "server.js": code,
    });
    expect(byRule(old, NAME)[0]!.severity).toBe("high");
    expect(byRule(old, NAME)[0]!.plainEnglishProblem).toContain("express-fileupload@1.2.1");
    const range = await scan({
      "package.json": pkg({ "express-fileupload": "^1.2.0" }),
      "server.js": code,
    });
    expect(byRule(range, NAME)[0]!.severity).toBe("medium");
  });

  it("only the path-traversal detector reports a busboy write that also uses req.query", async () => {
    const files = {
      "server.js": lines(
        'const busboy = require("busboy");',
        'const fs = require("fs");',
        'const path = require("path");',
        'app.post("/up", (req, res) => {',
        "  const bb = busboy({ headers: req.headers, limits: { fileSize: 1 } });",
        '  bb.on("file", (name, stream, info) => {',
        '    stream.pipe(fs.createWriteStream(path.join("uploads", req.query.dir, info.filename)));',
        "  });",
        "});",
      ),
    };
    const both = [...(await run(new PathTraversalDetector(), files)), ...(await scan(files))];
    expect(both.some((f) => f.ruleId === "injection/path-traversal")).toBe(true);
    expect(byRule(both, NAME)).toHaveLength(0);
  });

  it("is silent for a unique, sanitized or extname-only multer name", async () => {
    const mk = (cb: string): string =>
      lines(
        'const multer = require("multer");',
        'const path = require("path");',
        "const storage = multer.diskStorage({",
        `  filename: (req, file, cb) => ${cb},`,
        "});",
        "const upload = multer({ storage, limits: { fileSize: 1 }, fileFilter });",
      );
    const fs = await scan({
      "a.js": mk("cb(null, `${crypto.randomUUID()}${path.extname(file.originalname)}`)"),
      "b.js": mk("cb(null, sanitize(file.originalname))"),
      "c.js": mk("cb(null, path.basename(file.originalname))"),
    });
    expect(byRule(fs, NAME)).toHaveLength(0);
  });

  it("is silent for express-fileupload with safeFileNames and a sanitized name", async () => {
    const fs = await scan({
      "server.js": lines(
        'const fileUpload = require("express-fileupload");',
        "app.use(fileUpload({ limits: { fileSize: 10 * 1024 * 1024 }, safeFileNames: true, preserveExtension: true }));",
        'app.post("/up", (req, res) => {',
        "  const file = req.files.doc;",
        "  file.mv(path.join(dir, file.name));",
        "});",
      ),
    });
    expect(byRule(fs, NAME)).toHaveLength(0);
  });

  it("does not report plain fs writes of request paths (path-traversal owns them)", async () => {
    const fs = await scan({
      "server.js": lines(
        'const fs = require("fs");',
        'const multer = require("multer");',
        "const upload = multer({ storage, limits: { fileSize: 1 }, fileFilter });",
        'app.post("/up", upload.single("f"), (req, res) => {',
        "  fs.writeFile(path.join(dir, req.file.originalname), req.file.buffer, cb);",
        "});",
      ),
    });
    expect(byRule(fs, NAME)).toHaveLength(0);
  });
});

describe("FileUploadDetector: storage keys (U3b)", () => {
  it("is high/medium with a public-read ACL", async () => {
    const fs = await scan({
      "app/actions.ts": lines(
        '"use server";',
        "export async function upload(formData: FormData) {",
        '  const file = formData.get("file") as File;',
        '  await s3.send(new PutObjectCommand({ Bucket, Key: file.name, ACL: "public-read", Body: await file.arrayBuffer() }));',
        "}",
      ),
    });
    const name = byRule(fs, NAME);
    expect(name).toHaveLength(1);
    expect([name[0]!.severity, name[0]!.confidence]).toEqual(["high", "medium"]);
    expect(name[0]!.plainEnglishProblem).toContain("public ACL");
    expectRubric(fs);
  });

  it("flags Express memory upload to S3 with req.file.originalname", async () => {
    const fs = await scan({
      "server.js": lines(
        'const multer = require("multer");',
        "const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 1 }, fileFilter });",
        'app.post("/up", upload.single("f"), async (req, res) => {',
        "  await s3.send(new PutObjectCommand({ Bucket, Key: req.file.originalname, Body: req.file.buffer }));",
        "});",
      ),
    });
    const name = byRule(fs, NAME);
    expect(name).toHaveLength(1);
    expect([name[0]!.severity, name[0]!.confidence]).toEqual(["medium", "medium"]);
  });

  it("flags Supabase upload with upsert: true in a route handler", async () => {
    const fs = await scan({
      "app/api/up/route.ts": lines(
        "export async function POST(req: Request) {",
        "  const form = await req.formData();",
        '  const file = form.get("file") as File;',
        '  await supabase.storage.from("docs").upload(file.name, file, { upsert: true });',
        "  return Response.json({ ok: true });",
        "}",
      ),
    });
    expect(byRule(fs, NAME)).toHaveLength(1);
    expect(byRule(fs, SIZE)).toHaveLength(0);
    expect(byRule(fs, TYPE)).toHaveLength(0);
  });

  it("flags Vercel Blob put with allowOverwrite: true", async () => {
    const fs = await scan({
      "app/api/up/route.ts": lines(
        'import { put } from "@vercel/blob";',
        "export async function POST(req: Request) {",
        "  const form = await req.formData();",
        '  const file = form.get("file") as File;',
        '  const blob = await put(file.name, file, { access: "public", allowOverwrite: true });',
        "  return Response.json(blob);",
        "}",
      ),
    });
    expect(byRule(fs, NAME)).toHaveLength(1);
  });

  it("flags a getAll loop in a server action", async () => {
    const fs = await scan({
      "app/actions.ts": lines(
        '"use server";',
        "export async function upload(formData: FormData) {",
        '  for (const f of formData.getAll("files") as File[]) {',
        "    await s3.send(new PutObjectCommand({ Bucket, Key: f.name, Body: Buffer.from(await f.arrayBuffer()) }));",
        "  }",
        "}",
      ),
    });
    const name = byRule(fs, NAME);
    expect(name).toHaveLength(1);
    expect([name[0]!.severity, name[0]!.confidence]).toEqual(["medium", "medium"]);
  });

  it("flags a Google Cloud Storage bucket.file(name).save", async () => {
    const fs = await scan({
      "server.js": lines(
        'const multer = require("multer");',
        "const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 1 }, fileFilter });",
        'app.post("/up", upload.single("f"), async (req, res) => {',
        "  await bucket.file(req.file.originalname).save(req.file.buffer);",
        "});",
      ),
    });
    expect(byRule(fs, NAME)).toHaveLength(1);
  });

  it("is silent on unique, owner-scoped, non-upsert and helper-parameter keys", async () => {
    const fs = await scan({
      "app/api/a/route.ts": lines(
        "export async function POST(req: Request) {",
        "  const form = await req.formData();",
        '  const file = form.get("file") as File;',
        "  if (!ALLOWED.includes(file.type) || file.size > MAX) return new Response(null, { status: 400 });",
        "  const target = path.join(UPLOAD_ROOT, orgId, `${randomUUID()}${ext}`);",
        "  await writeFile(target, Buffer.from(await file.arrayBuffer()));",
        "  await s3.send(new PutObjectCommand({ Bucket, Key: `orgs/${orgId}/docs/${Date.now()}-${safeName}`, Body: b }));",
        '  await supabase.storage.from("avatars").upload(`${user.id}/${file.name}`, file, { upsert: true });',
        '  await supabase.storage.from("docs").upload(file.name, file);',
        '  await put(file.name, file, { access: "public" });',
        "  return Response.json({ ok: true });",
        "}",
      ),
      "lib/storage.ts": lines(
        "export async function putFile(body: Buffer, filename: string) {",
        "  await s3.send(new PutObjectCommand({ Bucket, Key: filename, Body: body }));",
        "}",
        "export async function putOther(body: Buffer, fileName: string) {",
        "  await s3.send(new PutObjectCommand({ Bucket, Key: fileName, Body: body }));",
        "}",
        "export async function presign(key: string) {",
        "  return getSignedUrl(s3, new PutObjectCommand({ Bucket, Key: key }));",
        "}",
        "export async function report(org: { name: string }, product: { name: string }) {",
        "  await s3.send(new PutObjectCommand({ Bucket, Key: `${org.name}/reports/latest.pdf`, Body: b }));",
        "  await s3.send(new PutObjectCommand({ Bucket, Key: product.name, Body: b }));",
        "}",
      ),
    });
    expect(byRule(fs, NAME)).toHaveLength(0);
  });
});

describe("FileUploadDetector: scope and robustness", () => {
  it("ignores comments, strings, test files, client components and Python", async () => {
    const fs = await scan({
      "a.js": lines(
        '// const upload = multer({ dest: "uploads/" });',
        'const s = "multer({ dest: \\"x\\" })";',
        "export {};",
      ),
      "tests/upload.test.ts": lines(
        'import multer from "multer";',
        'export const u = multer({ dest: "x" });',
      ),
      "components/Upload.tsx": lines(
        '"use client";',
        "export function Upload({ formData }: { formData: FormData }) {",
        '  return fetch("/api/upload", { method: "POST", body: formData });',
        "}",
      ),
      "app.py": lines(
        "from flask import request",
        "def upload():",
        '    f = request.files["file"]',
        '    f.save("uploads/" + f.filename)',
      ),
    });
    expect(fs).toEqual([]);
  });

  it("works with a single-file targetFiles context and keeps ids stable", async () => {
    const files = {
      "server.js": lines(
        'const multer = require("multer");',
        'const upload = multer({ dest: "uploads/" });',
      ),
      "other.js": "export {};",
    };
    const a = await run(detector, files, { targetFiles: ["server.js"] });
    const b = await run(detector, files, { targetFiles: ["server.js"] });
    expect(a.length).toBeGreaterThan(0);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("never throws on odd input", async () => {
    const fs = await scan({
      "a.js": 'const multer = require("multer"); multer({ ...opts, limits: {',
      "b.js": 'import multer from "multer"; multer(',
    });
    expect(Array.isArray(fs)).toBe(true);
  });
});

describe("FileUploadDetector: review round 1", () => {
  const diskWith = (expr: string): string =>
    lines(
      'const multer = require("multer");',
      "const storage = multer.diskStorage({",
      '  destination: "uploads/",',
      `  filename: (req, file, cb) => cb(null, ${expr}),`,
      "});",
      'const upload = multer({ storage, limits: { fileSize: 1000 }, fileFilter: (r, f, cb) => cb(null, f.mimetype === "image/png") });',
    );

  it("is silent for multer disk names with a random prefix, still flags Date.now()", async () => {
    for (const expr of [
      "`${uuidv4()}-${file.originalname}`",
      "randomUUID() + file.originalname",
      "nanoid() + '-' + file.originalname",
    ]) {
      expect(byRule(await scan({ "s.js": diskWith(expr) }), NAME)).toEqual([]);
    }
    expect(
      byRule(await scan({ "s.js": diskWith("Date.now() + file.originalname") }), NAME),
    ).toHaveLength(1);
  });

  it("is silent for busboy and formidable names with a random component", async () => {
    const bb = lines(
      'const busboy = require("busboy");',
      "function h(req) {",
      "  const bb = busboy({ headers: req.headers, limits: { fileSize: 1 } });",
      '  bb.on("file", (name, file, info) => {',
      "    file.pipe(fs.createWriteStream(path.join(UPLOAD_DIR, randomUUID() + info.filename)));",
      "  });",
      "}",
    );
    expect(byRule(await scan({ "b.js": bb }), NAME)).toEqual([]);
    const fm = lines(
      'const formidable = require("formidable");',
      "const form = formidable({ maxFileSize: 1000, filename: (n, e, part) => `${nanoid()}-${part.originalFilename}` });",
    );
    expect(byRule(await scan({ "f.js": fm }), NAME)).toEqual([]);
  });

  it("is silent for owner-scoped storage keys", async () => {
    const a = lines(
      "export async function POST(req: Request) {",
      "  const user = await getUser();",
      "  const uid = user!.id;",
      "  const formData = await req.formData();",
      '  const file = formData.get("f") as File;',
      '  await supabase.storage.from("docs").upload(`${uid}/${file.name}`, file, { upsert: true });',
      "}",
    );
    expect(byRule(await scan({ "app/api/up/route.ts": a }), NAME)).toEqual([]);
    const b = lines(
      'import multer from "multer";',
      "const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 1 }, fileFilter });",
      'app.post("/up", upload.single("f"), async (req, res) => {',
      "  await s3.send(new PutObjectCommand({ Bucket: B, Key: `avatars/${currentUser.id}/${req.file.originalname}`, Body: req.file.buffer }));",
      "});",
    );
    expect(byRule(await scan({ "s.js": b }), NAME)).toEqual([]);
  });

  it("is silent for multer().none() and a none-only binding, flags mixed use", async () => {
    const a = lines('import multer from "multer";', 'app.post("/t", multer().none(), h);');
    expect(await scan({ "a.js": a })).toEqual([]);
    const b = lines(
      'import multer from "multer";',
      "const textOnly = multer();",
      'app.post("/t", textOnly.none(), h);',
    );
    expect(await scan({ "b.js": b })).toEqual([]);
    const c = lines(
      'import multer from "multer";',
      "const up = multer();",
      'app.post("/t", up.none(), h);',
      'app.post("/u", up.single("f"), h);',
    );
    expect(byRule(await scan({ "c.js": c }), SIZE)).toHaveLength(1);
  });

  it("does not treat a text formData field passed to save() as a file", async () => {
    const a = lines(
      '"use server";',
      "export async function setTheme(formData: FormData) {",
      '  const theme = formData.get("theme");',
      "  await db.settings.save(theme);",
      "}",
    );
    expect(byRule(await scan({ "app/actions.ts": a }), TYPE)).toEqual([]);
  });
});
