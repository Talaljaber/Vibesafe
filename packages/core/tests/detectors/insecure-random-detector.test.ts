import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import {
  InsecureRandomDetector,
  enclosingFunctionName,
  isSecretValueName,
} from "../../src/detectors/insecure-random-detector.js";
import { maskCode } from "../../src/detectors/utils/route-analyzer.js";
import { expectRubric } from "../helpers/rubric.js";

const createContext = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake/path",
  projectContext: {} as any,
  files: Object.keys(files),
  config: { rootPath: "/fake/path" },
  readFile: async (file) => files[file] ?? "",
});

const detector = new InsecureRandomDetector();
const run = async (files: Record<string, string>) => {
  const findings = await detector.detect(createContext(files));
  expectRubric(findings);
  return findings;
};

describe("isSecretValueName", () => {
  it.each([
    "token",
    "resetToken",
    "generateApiKey",
    "apiKey",
    "API_KEY",
    "secretKey",
    "signingKey",
    "sessionId",
    "createSession",
    "otp",
    "otpCode",
    "verificationCode",
    "inviteCode",
    "generateInvite",
    "resetLink",
    "tempPassword",
    "nonce",
    "salt",
    "csrfToken",
  ])("matches %s", (name) => {
    expect(isSecretValueName(name)).toBe(true);
  });

  it.each([
    "key",
    "cacheKey",
    "queryKey",
    "statusCode",
    "code",
    "jitter",
    "shuffle",
    "color",
    "randomColor",
    "id",
    "requestId",
    "sessionStorage",
    "resetTimer",
    "reset",
    "tokenizer",
    "tokenLength",
    "saltRounds",
    "retryDelay",
    "mockToken",
  ])("does not match %s", (name) => {
    expect(isSecretValueName(name)).toBe(false);
  });
});

describe("enclosingFunctionName", () => {
  const at = (src: string) => enclosingFunctionName(maskCode(src), src.indexOf("Math.random"));

  it("finds declarations, arrows and methods through blocks and callbacks", () => {
    expect(
      at(
        "function generateApiKey() {\n for (let i = 0; i < 3; i++) {\n  k += Math.random();\n }\n}",
      ),
    ).toBe("generateApiKey");
    expect(
      at(
        "export const makeToken = async (n: number): Promise<string> => {\n return Math.random();\n}",
      ),
    ).toBe("makeToken");
    expect(
      at(
        "class A {\n  async createOtp(len: number): Promise<string> {\n    return [1].map(() => Math.random()).join('');\n  }\n}",
      ),
    ).toBe("createOtp");
    expect(at("const newToken = () => Math.random().toString(36)")).toBe("newToken");
    expect(at("const x = Math.random();")).toBeUndefined();
  });
});

describe("InsecureRandomDetector", () => {
  it("flags Math.random building an API key inside a key generator (loop accumulator)", async () => {
    const findings = await run({
      "lib/server/keys.ts": [
        'const CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";',
        "export function generateApiKey() {",
        '  let key = "sk_";',
        "  for (let i = 0; i < 32; i++) {",
        "    key += CHARS.charAt(Math.floor(Math.random() * CHARS.length));",
        "  }",
        "  return key;",
        "}",
      ].join("\n"),
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe("crypto/insecure-random-token");
    expect(findings[0]!.severity).toBe("high");
    expect(findings[0]!.confidence).toBe("high");
    expect(findings[0]!.line).toBe(5);
    expect(findings[0]!.category).toBe("crypto");
    expect(findings[0]!.id).toMatch(/^CRYPTO-[0-9a-f]{10}$/);
  });

  it("flags assignments, object properties and returns named like secrets", async () => {
    const findings = await run({
      "app/api/reset/route.ts": [
        "export async function POST(req: Request) {",
        "  const resetToken = Math.random().toString(36).slice(2);",
        "  await db.insert({ otpCode: Math.floor(Math.random() * 1e6) });",
        "  return Response.json({ ok: true });",
        "}",
        "function createSessionId() {",
        "  return Math.random().toString(16).slice(2);",
        "}",
      ].join("\n"),
    });
    expect(findings.map((f) => f.line)).toEqual([2, 3, 7]);
  });

  it("flags a neutral helper whose result the same file uses as a token (medium confidence)", async () => {
    const findings = await run({
      "lib/invites.ts": [
        "function randomString(n: number) {",
        "  let s = '';",
        "  for (let i = 0; i < n; i++) s += ALPHABET[Math.floor(Math.random() * ALPHABET.length)];",
        "  return s;",
        "}",
        "export function inviteUser(email: string) {",
        "  const inviteToken = randomString(24);",
        "  return save(email, inviteToken);",
        "}",
      ].join("\n"),
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.line).toBe(3);
    expect(findings[0]!.confidence).toBe("medium");
  });

  it("flags Date.now() concatenated into a token, not Date.now() arithmetic", async () => {
    const findings = await run({
      "lib/tokens.js": [
        "const verifyToken = 'v_' + Date.now();",
        "const resetCode = `${Date.now()}`;",
        "const cutoff = new Date(Date.now() - DAY_MS).toISOString();",
        "const fileName = `export-${Date.now()}.csv`;",
        "const started = Date.now();",
      ].join("\n"),
    });
    expect(findings.map((f) => f.line)).toEqual([1, 2]);
    expect(findings[0]!.title).toContain("Date.now()");
  });

  it("does not flag non-security randomness (React keys, jitter, colors, cache keys, sampling)", async () => {
    const findings = await run({
      "components/List.tsx": [
        "export function ApiKeysList({ items }) {",
        "  return items.map((i) => <li key={Math.random()}>{i}</li>);",
        "}",
      ].join("\n"),
      "lib/retry.ts": [
        "export function generateToken() {",
        "  const delay = 100 + Math.random() * 50;",
        "  if (Math.random() < 0.1) log('sampled');",
        "  return crypto.randomBytes(32).toString('hex');",
        "}",
        "const cacheKey = 'k' + Math.random();",
        "const color = `hsl(${Math.random() * 360}, 50%, 50%)`;",
        "function shuffle(a) { return a.sort(() => Math.random() - 0.5); }",
        "const id = Math.random().toString(36);",
      ].join("\n"),
    });
    expect(findings).toEqual([]);
  });

  it("does not flag when a CSPRNG is on the same line", async () => {
    const findings = await run({
      "lib/t.ts": "const token = crypto.randomUUID() + Math.random().toString(36);",
    });
    expect(findings).toEqual([]);
  });

  it("ignores comments and strings", async () => {
    const findings = await run({
      "lib/a.ts": [
        "// const token = Math.random().toString(36);",
        "const doc = 'const token = Math.random()';",
        "/* apiKey = Math.random() */",
      ].join("\n"),
    });
    expect(findings).toEqual([]);
  });

  it("skips non-JS files, tests and generated files", async () => {
    const src = "const token = Math.random().toString(36);";
    const findings = await run({
      "scripts/gen.py": "token = Math.random()",
      "db/seed.sql": src,
      "lib/token.test.ts": src,
      "tests/helpers/token.ts": src,
      "dist/types.d.ts": src,
      "lib/gen.ts": `// @generated\n${src}`,
    });
    expect(findings).toEqual([]);
  });

  it("produces stable ids across runs", async () => {
    const files = { "lib/k.ts": "export const apiKey = Math.random().toString(36);" };
    const a = await run(files);
    const b = await run(files);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
    expect(a).toHaveLength(1);
  });
});

describe("InsecureRandomDetector caps", () => {
  it("caps a file at 25 findings plus one medium-confidence summary", async () => {
    const src = Array.from({ length: 30 }, (_, i) => `const token${i} = Math.random();`).join("\n");
    const findings = await run({ "lib/many.ts": src });
    expect(findings).toHaveLength(26);
    expect(findings[25]!.confidence).toBe("medium");
    expect(findings[25]!.evidence).toContain("5 more");
  });
});
