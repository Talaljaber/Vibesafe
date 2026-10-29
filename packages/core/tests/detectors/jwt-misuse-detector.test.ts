import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { JwtMisuseDetector } from "../../src/detectors/jwt-misuse-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const createContext = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake/path",
  projectContext: {} as any,
  files: Object.keys(files),
  config: { rootPath: "/fake/path" },
  readFile: async (file) => files[file] ?? "",
});

const detector = new JwtMisuseDetector();
const run = async (files: Record<string, string>) => {
  const findings = await detector.detect(createContext(files));
  expectRubric(findings);
  return findings;
};
const rules = (findings: { ruleId: string; line?: number | undefined }[]) =>
  findings.map((f) => `${f.ruleId}@${f.line}`);

describe("JwtMisuseDetector: literal secrets", () => {
  it("flags jwt.sign / jwt.verify with a string literal secret", async () => {
    const findings = await run({
      "lib/auth.ts": [
        'import jwt from "jsonwebtoken";',
        'export const sign = (p: object) => jwt.sign(p, "super-secret-value", { expiresIn: "1h" });',
        "export const check = (t: string) =>",
        "  jwt.verify(t, 'super-secret-value', { algorithms: ['HS256'] });",
      ].join("\n"),
    });
    expect(rules(findings)).toEqual(["crypto/jwt-literal-secret@2", "crypto/jwt-literal-secret@4"]);
    expect(findings[0]!.severity).toBe("high");
    expect(findings[0]!.confidence).toBe("high");
    expect(findings[0]!.evidence).not.toContain("super-secret-value");
  });

  it("redacts only the secret literal, not the call that contains the same text", async () => {
    const findings = await run({
      "lib/auth.ts": 'export const token = (p: object) => jwt.sign(p, "sign");',
    });
    expect(rules(findings)).toEqual(["crypto/jwt-literal-secret@1"]);
    expect(findings[0]!.evidence).toContain("jwt.sign(p,");
    expect(findings[0]!.evidence).not.toContain('"sign"');
  });

  it("flags a const literal secret once, at its declaration, and jose keys", async () => {
    const findings = await run({
      "lib/token.js": [
        "const jwt = require('jsonwebtoken');",
        "const SECRET = 'hardcoded-signing-key';",
        "exports.a = (p) => jwt.sign(p, SECRET, { algorithm: 'HS256' });",
        "exports.b = (t) => jwt.verify(t, SECRET, { algorithms: ['HS256'] });",
      ].join("\n"),
      "lib/jose.ts": [
        'import { SignJWT, jwtVerify } from "jose";',
        "export const mint = (p) => new SignJWT(p).setProtectedHeader({ alg: 'HS256' })",
        "  .sign(new TextEncoder().encode('jose-literal-secret'));",
      ].join("\n"),
    });
    expect(rules(findings)).toEqual(["crypto/jwt-literal-secret@2", "crypto/jwt-literal-secret@3"]);
    expect(findings.map((f) => f.file)).toEqual(["lib/token.js", "lib/jose.ts"]);
  });

  it("leaves a recognised vendor key used as the secret to the secret detector", async () => {
    const live = "sk_live_" + "a1B2c3D4e5F6g7H8i9J0k1L2";
    const findings = await run({
      "lib/auth.ts": `import jwt from "jsonwebtoken";\njwt.sign(p, "${live}", { algorithm: "HS256" });`,
    });
    expect(findings).toEqual([]);
  });

  it("does not flag env secrets, fallbacks (reported elsewhere), or non-literal keys", async () => {
    const findings = await run({
      "lib/auth.ts": [
        'import jwt from "jsonwebtoken";',
        "const A = process.env.JWT_SECRET!;",
        'const B = process.env.JWT_SECRET || "fallback";',
        "jwt.sign(p, A, { algorithm: 'HS256' });",
        "jwt.sign(p, B, { algorithm: 'HS256' });",
        "jwt.verify(t, getKey(), { algorithms: ['RS256'] });",
        "jwt.verify(t, publicKey, { algorithms: ['RS256'] });",
        "// jwt.sign(p, 'commented-out-secret')",
        "const doc = \"jwt.sign(p, 'in-a-string')\";",
      ].join("\n"),
    });
    expect(findings).toEqual([]);
  });
});

describe("JwtMisuseDetector: decode used for auth", () => {
  it("flags jwt.decode whose claims drive identity with no verification in the file", async () => {
    const findings = await run({
      "middleware.ts": [
        'import jwt from "jsonwebtoken";',
        "export function middleware(req) {",
        "  const token = req.cookies.get('session')?.value;",
        "  const payload = jwt.decode(token) as { role: string };",
        "  if (payload.role !== 'admin') return deny();",
        "}",
      ].join("\n"),
      "app/api/me/route.ts": [
        'import { jwtDecode } from "jwt-decode";',
        "export async function GET(req: Request) {",
        "  const { sub } = jwtDecode(req.headers.get('authorization')!);",
        "  return Response.json(await db.user(sub));",
        "}",
      ].join("\n"),
    });
    expect(rules(findings)).toEqual([
      "crypto/jwt-decode-for-auth@4",
      "crypto/jwt-decode-for-auth@3",
    ]);
    expect(findings.map((f) => f.file)).toEqual(["middleware.ts", "app/api/me/route.ts"]);
    expect(findings.every((f) => f.severity === "high" && f.confidence === "high")).toBe(true);
  });

  it("does not flag decode when the file verifies, reads only expiry, or runs in the browser", async () => {
    const findings = await run({
      "lib/server/auth.ts": [
        'import jwt from "jsonwebtoken";',
        "export function read(token: string) {",
        "  const header = jwt.decode(token, { complete: true });",
        "  const p = jwt.verify(token, process.env.JWT_SECRET!, { algorithms: ['HS256'] });",
        "  return { kid: header.kid, user: p.sub };",
        "}",
      ].join("\n"),
      "lib/server/refresh.ts": [
        'import jwt from "jsonwebtoken";',
        "export const expiresSoon = (t: string) => (jwt.decode(t) as any).exp < Date.now() / 1000 + 60;",
      ].join("\n"),
      "components/Avatar.tsx": [
        '"use client";',
        'import { jwtDecode } from "jwt-decode";',
        "export function Avatar({ token }) {",
        "  const { email } = jwtDecode(token);",
        "  return <span>{email}</span>;",
        "}",
      ].join("\n"),
    });
    expect(findings).toEqual([]);
  });
});

describe("JwtMisuseDetector: algorithms", () => {
  it("flags 'none' in algorithms and algorithm options", async () => {
    const findings = await run({
      "lib/a.ts": [
        'import jwt from "jsonwebtoken";',
        "jwt.verify(token, key, { algorithms: ['HS256', 'none'] });",
        "jwt.sign(payload, '', { algorithm: \"none\" });",
      ].join("\n"),
    });
    expect(rules(findings)).toEqual(["crypto/jwt-algorithm-none@2", "crypto/jwt-algorithm-none@3"]);
  });

  it("does not flag 'none' outside JWT code or in comments", async () => {
    const findings = await run({
      "lib/compress.ts": "export const opts = { algorithm: 'none', level: 0 };",
      "lib/b.ts": 'import jwt from "jsonwebtoken";\n// never use { algorithms: ["none"] }\n',
    });
    expect(findings).toEqual([]);
  });

  it("flags jwt.verify without an algorithms allow-list as low severity", async () => {
    const findings = await run({
      "lib/auth.ts": [
        'import { verify } from "jsonwebtoken";',
        "export const a = (t: string) => verify(t, process.env.JWT_SECRET!);",
        "export const b = (t: string) => verify(t, process.env.JWT_SECRET!, (err, p) => p);",
        "export const c = (t: string) => verify(t, process.env.JWT_SECRET!, { ignoreExpiration: false });",
        "export const d = (t: string) => verify(t, process.env.JWT_SECRET!, { algorithms: ['HS256'] });",
        "export const e = (t: string) => verify(t, process.env.JWT_SECRET!, VERIFY_OPTIONS);",
      ].join("\n"),
    });
    expect(rules(findings)).toEqual([
      "crypto/jwt-verify-without-algorithms@2",
      "crypto/jwt-verify-without-algorithms@3",
      "crypto/jwt-verify-without-algorithms@4",
    ]);
    expect(findings.every((f) => f.severity === "low" && f.confidence === "medium")).toBe(true);
  });

  it("skips tests, generated files and non-JS files", async () => {
    const src = 'import jwt from "jsonwebtoken";\njwt.sign(p, "literal-secret-here");';
    const findings = await run({
      "lib/auth.test.ts": src,
      "__tests__/auth.ts": src,
      "types/auth.d.ts": src,
      "auth.py": src,
      "db/init.sql": src,
    });
    expect(findings).toEqual([]);
  });

  it("produces stable ids across runs", async () => {
    const files = { "a.ts": 'import jwt from "jsonwebtoken";\njwt.sign(p, "abc-literal");' };
    const a = await run(files);
    const b = await run(files);
    expect(a).toHaveLength(1);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });
});

describe("JwtMisuseDetector caps", () => {
  it("caps a rule at 25 findings per file plus one medium-confidence summary", async () => {
    const src = [
      'import jwt from "jsonwebtoken";',
      ...Array.from({ length: 30 }, (_, i) => `jwt.verify(t${i}, key);`),
    ].join("\n");
    const findings = await run({ "lib/many.ts": src });
    expect(findings).toHaveLength(26);
    expect(
      findings.filter((f) => f.confidence === "medium" && f.evidence?.includes("5 more")),
    ).toHaveLength(1);
  });
});
