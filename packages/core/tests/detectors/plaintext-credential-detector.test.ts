import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import {
  PlaintextCredentialDetector,
  stripSqlComments,
} from "../../src/detectors/plaintext-credential-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const createContext = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake/path",
  projectContext: {} as any,
  files: Object.keys(files),
  config: { rootPath: "/fake/path" },
  readFile: async (file) => files[file] ?? "",
});

const detector = new PlaintextCredentialDetector();
const run = async (files: Record<string, string>) => {
  const findings = await detector.detect(createContext(files));
  expectRubric(findings);
  return findings;
};
const rules = (
  findings: { file?: string | undefined; ruleId: string; line?: number | undefined }[],
) => findings.map((f) => `${f.file}:${f.line} ${f.ruleId}`);

const API_KEYS_MODULE = [
  'import "server-only";',
  'import { adminDb } from "./db";',
  "export async function createApiKey(orgId: string) {",
  "  const key = generateApiKey();",
  "  const { data } = await adminDb",
  '    .from("api_keys")',
  "    .insert({ org_id: orgId, key, prefix: key.slice(0, 8) })",
  "    .select()",
  "    .single();",
  "  return { ...data, key };",
  "}",
  "export async function verifyApiKey(key: string) {",
  '  const { data } = await adminDb.from("api_keys").select("id").eq("key", key).maybeSingle();',
  "  return data;",
  "}",
].join("\n");

describe("crypto/plaintext-api-key-storage", () => {
  it("flags a generated key inserted as-is (once per file, at the write)", async () => {
    const findings = await run({ "lib/server/apiKeys.ts": API_KEYS_MODULE });
    expect(rules(findings)).toEqual(["lib/server/apiKeys.ts:7 crypto/plaintext-api-key-storage"]);
    expect(findings[0]!.severity).toBe("high");
    expect(findings[0]!.confidence).toBe("medium");
  });

  it("flags Prisma/Drizzle writes of generated tokens and plaintext lookups", async () => {
    const findings = await run({
      "lib/tokens.ts": [
        "export async function issue(userId: string) {",
        "  await prisma.apiToken.create({ data: { userId, token: crypto.randomBytes(32).toString('hex') } });",
        "}",
      ].join("\n"),
      "lib/sessions.ts": [
        "export async function login(userId: string) {",
        "  const sessionToken = nanoid(32);",
        "  await db.insert(sessions).values({ userId, token: sessionToken });",
        "}",
      ].join("\n"),
      "lib/check.ts": [
        "export async function check(presented: string) {",
        '  return supabase.from("api_keys").select("*").eq("key", presented).single();',
        "}",
      ].join("\n"),
    });
    expect(rules(findings)).toEqual([
      "lib/tokens.ts:2 crypto/plaintext-api-key-storage",
      "lib/sessions.ts:3 crypto/plaintext-api-key-storage",
      "lib/check.ts:2 crypto/plaintext-api-key-storage",
    ]);
    expect(findings[2]!.title).toContain("looked up");
  });

  it("does not flag hashed keys, non-generated values, settings tables or client code", async () => {
    const findings = await run({
      "lib/hashed.ts": API_KEYS_MODULE.replace(
        "  const key = generateApiKey();",
        "  const key = generateApiKey();\n  const keyHash = createHash('sha256').update(key).digest('hex');",
      ),
      "lib/settings.ts": [
        "export async function save(theme: string) {",
        '  await db.from("settings").insert({ key: "theme", value: theme });',
        "  const key = randomId();",
        '  await db.from("settings").insert({ key, value: 1 });',
        "}",
      ].join("\n"),
      "lib/oauth.ts": [
        "export async function store(userId: string, tokens: Tokens) {",
        '  await db.from("accounts").update({ access_token: tokens.access_token }).eq("user_id", userId);',
        "}",
      ].join("\n"),
      "components/Keys.tsx": [
        '"use client";',
        "export function Keys() {",
        "  const key = generateApiKey();",
        '  supabase.from("api_keys").insert({ key });',
        "}",
      ].join("\n"),
    });
    expect(findings).toEqual([]);
  });

  it("ignores commented-out code and tests", async () => {
    const findings = await run({
      "lib/a.ts": [
        "// const key = generateApiKey();",
        '// await db.from("api_keys").insert({ key });',
      ].join("\n"),
      "lib/apiKeys.test.ts": API_KEYS_MODULE,
      "tests/fixtures/apiKeys.ts": API_KEYS_MODULE,
    });
    expect(findings).toEqual([]);
  });
});

describe("crypto/weak-password-hash", () => {
  it("flags md5/sha1 applied to passwords", async () => {
    const findings = await run({
      "lib/users.ts": [
        "import crypto from 'crypto';",
        "export const hashPassword = (password: string) =>",
        "  crypto.createHash('md5').update(password).digest('hex');",
        "const passwordHash = crypto.createHash(\"sha1\").update(input + salt).digest('hex');",
        "const legacy = md5(user.password);",
        "const h = CryptoJS.SHA1(body.passwd).toString();",
      ].join("\n"),
    });
    expect(rules(findings)).toEqual([
      "lib/users.ts:3 crypto/weak-password-hash",
      "lib/users.ts:4 crypto/weak-password-hash",
      "lib/users.ts:5 crypto/weak-password-hash",
      "lib/users.ts:6 crypto/weak-password-hash",
    ]);
  });

  it("does not flag md5/sha1 of non-password data or strong hashes of passwords", async () => {
    const findings = await run({
      "lib/etag.ts": [
        "export const etag = (buf: Buffer) => createHash('md5').update(buf).digest('hex');",
        "export const avatar = (email: string) => md5(email.trim().toLowerCase());",
        "export const cacheKey = createHash('sha1').update(url).digest('hex');",
        "export const pw = createHash('sha256').update(password).digest('hex');",
        "// createHash('md5').update(password)",
      ].join("\n"),
      "app.py": "hashlib.md5(password.encode()).hexdigest()",
    });
    expect(findings).toEqual([]);
  });
});

describe("crypto/plaintext-seed-password", () => {
  it("flags crypt('literal', gen_salt()) and literal password columns in SQL", async () => {
    const findings = await run({
      "supabase/seed.sql": [
        "-- seed",
        "insert into auth.users (id, email, encrypted_password) values (",
        "  'a1', 'admin@example.org',",
        "  crypt('Sup3r!Admin2024', gen_salt('bf'))",
        "), (",
        "  'b2', 'demo@example.org',",
        "  '$2a$10$Xq3m9V1pTt7kQ2hZcR8uOe5bN4yLwF6sJdG0aHiK1oP2rS3tU4vW6'",
        ");",
        "INSERT INTO users (email, password) VALUES ('ops@example.org', 'Opsteam#2024');",
      ].join("\n"),
    });
    expect(rules(findings)).toEqual([
      "supabase/seed.sql:4 crypto/plaintext-seed-password",
      "supabase/seed.sql:9 crypto/plaintext-seed-password",
    ]);
    expect(findings[0]!.evidence).not.toContain("Sup3r!Admin2024");
    expect(findings[1]!.evidence).not.toContain("Opsteam#2024");
    expect(findings[0]!.severity).toBe("high");
  });

  it("flags literal passwords in JS seed scripts", async () => {
    const findings = await run({
      "prisma/seed.ts": [
        "await prisma.user.create({",
        "  data: { email: 'admin@example.org', password: await bcrypt.hash('Adm1n!Secure', 10) },",
        "});",
        "await prisma.user.create({ data: { email: 'b@example.org', password: 'Plain#Pass99' } });",
      ].join("\n"),
    });
    expect(rules(findings)).toEqual([
      "prisma/seed.ts:2 crypto/plaintext-seed-password",
      "prisma/seed.ts:4 crypto/plaintext-seed-password",
    ]);
  });

  it("does not flag hashes, placeholders, variables, comments or non-seed JS", async () => {
    const findings = await run({
      "supabase/seed.sql": [
        "-- crypt('Commented!Out1', gen_salt('bf'))",
        "/* insert into users (email, password) values ('a@b.c', 'Hidden#Pass1'); */",
        "insert into auth.users (email, encrypted_password) values ('x@y.z', crypt('password', gen_salt('bf')));",
        "insert into users (email, password_hash) values ('x@y.z', '$argon2id$v=19$m=65536$abc');",
        "insert into users (email, password) values ('x@y.z', :'seed_password');",
        "insert into notes (title, body) values ('password', 'Not#APassword1');",
      ].join("\n"),
      "prisma/seed.ts": [
        "await prisma.user.create({ data: { password: await bcrypt.hash(process.env.SEED_PASSWORD!, 10) } });",
        "await prisma.user.create({ data: { password: 'password123' } });",
      ].join("\n"),
      "app/api/users/route.ts": "await db.user.create({ data: { password: 'Plain#Pass99' } });",
    });
    expect(findings).toEqual([]);
  });

  it("produces stable ids across runs", async () => {
    const files = { "db/seed.sql": "select crypt('Real#Secret77', gen_salt('bf'));" };
    const a = await run(files);
    const b = await run(files);
    expect(a).toHaveLength(1);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });
});

describe("stripSqlComments", () => {
  it("blanks comments but keeps strings, offsets and newlines", () => {
    const sql = "select '--not a comment' -- real\n/* block\n */ select 1;";
    const out = stripSqlComments(sql);
    expect(out.length).toBe(sql.length);
    expect(out).toContain("'--not a comment'");
    expect(out).not.toContain("real");
    expect(out.split("\n")).toHaveLength(3);
  });
});

describe("PlaintextCredentialDetector caps", () => {
  it("caps a rule at 25 findings per file plus one medium-confidence summary", async () => {
    const src = Array.from({ length: 30 }, (_, i) => `const h${i} = md5(password${i});`).join("\n");
    const findings = await run({ "lib/many.ts": src });
    expect(findings).toHaveLength(26);
    expect(findings[25]!.confidence).toBe("medium");
    expect(findings[25]!.evidence).toContain("5 more");
  });
});
