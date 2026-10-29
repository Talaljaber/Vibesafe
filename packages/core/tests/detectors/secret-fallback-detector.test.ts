import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import {
  SecretFallbackDetector,
  isSecretEnvName,
} from "../../src/detectors/secret-fallback-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const createContext = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake/path",
  projectContext: {} as any,
  files: Object.keys(files),
  config: { rootPath: "/fake/path" },
  readFile: async (file) => files[file] ?? "",
});

const detector = new SecretFallbackDetector();
const run = async (files: Record<string, string>) => {
  const findings = await detector.detect(createContext(files));
  expectRubric(findings);
  return findings;
};

describe("isSecretEnvName", () => {
  it.each([
    "JWT_SECRET",
    "SESSION_SECRET",
    "NEXTAUTH_SECRET",
    "API_KEY",
    "OPENAI_API_KEY",
    "STRIPE_KEY",
    "DB_PASSWORD",
    "DB_PASS",
    "ENCRYPTION_KEY",
    "PRIVATE_KEY",
    "GITHUB_TOKEN",
    "COOKIE_SECRET",
    "PASSWORD_SALT",
    "jwtSecret",
    "SESSION_COOKIE_SECRET",
    "COOKIE_SIGNING_KEY",
  ])("treats %s as a secret", (name) => {
    expect(isSecretEnvName(name)).toBe(true);
  });

  it.each([
    "PORT",
    "NODE_ENV",
    "DATABASE_URL",
    "STAFF_EMAILS",
    "NEXT_PUBLIC_SUPABASE_ANON_KEY",
    "NEXT_PUBLIC_STRIPE_KEY",
    "VITE_API_KEY",
    "STRIPE_PUBLISHABLE_KEY",
    "JWT_EXPIRES_IN",
    "JWT_ALGORITHM",
    "TOKEN_TTL",
    "SALT_ROUNDS",
    "API_KEY_HEADER",
    "CACHE_KEY",
    "SESSION_COOKIE_NAME",
    "LOG_LEVEL",
    "AUTH_TOKEN_COOKIE",
    "TOKEN_STORAGE_KEY",
    "JWT_COOKIE",
    "JWT_CLAIM",
    "CSRF_TOKEN_FIELD",
    "TOKEN_PARAM",
    "GITHUB_TOKEN_SCOPES",
  ])("does not treat %s as a secret", (name) => {
    expect(isSecretEnvName(name)).toBe(false);
  });
});

describe("SecretFallbackDetector", () => {
  it("flags a JWT secret fallback as critical when the file signs with it", async () => {
    const findings = await run({
      "lib/server/auth.ts": [
        'import jwt from "jsonwebtoken";',
        'const JWT_SECRET = process.env.JWT_SECRET || "my-app-secret";',
        "export function sign(p: object) {",
        '  return jwt.sign(p, JWT_SECRET, { expiresIn: "7d" });',
        "}",
      ].join("\n"),
    });
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.ruleId).toBe("crypto/hardcoded-secret-fallback");
    expect(f.severity).toBe("critical");
    expect(f.confidence).toBe("high");
    expect(f.deployBlocking).toBe(true);
    expect(f.line).toBe(2);
    expect(f.evidence).not.toContain("my-app-secret");
  });

  it("flags inline signer options (express-session secret, ?? fallback) as critical", async () => {
    const findings = await run({
      "server.js": [
        "app.use(session({",
        '  secret: process.env.SESSION_SECRET ?? "keyboard cat",',
        "  resave: false,",
        "}));",
      ].join("\n"),
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("critical");
    expect(findings[0]!.line).toBe(2);
  });

  it("flags a fallback not used for signing as high", async () => {
    const findings = await run({
      "lib/openai.ts": "export const key = process.env.OPENAI_API_KEY || 'dev-openai-key';",
      "lib/crypto.ts": [
        "const ENCRYPTION_KEY =",
        "  process.env.ENCRYPTION_KEY ||",
        "  'a-very-long-development-key';",
      ].join("\n"),
    });
    expect(findings.map((f) => [f.file, f.line, f.severity])).toEqual([
      ["lib/openai.ts", 1, "high"],
      ["lib/crypto.ts", 3, "high"],
    ]);
  });

  it("flags destructured defaults from process.env", async () => {
    const findings = await run({
      "config.ts": [
        "const {",
        "  PORT = '3000',",
        "  JWT_SECRET = 'changeme',",
        "} = process.env;",
        "jwt.verify(token, JWT_SECRET);",
      ].join("\n"),
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.line).toBe(3);
    expect(findings[0]!.severity).toBe("critical");
  });

  it("does not flag safe forms (assertions, empty or identifier fallbacks, non-secret names)", async () => {
    const findings = await run({
      "lib/db.ts": [
        'import "server-only";',
        "const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY!;",
        "const secret = process.env.JWT_SECRET ?? '';",
        "const s2 = process.env.JWT_SECRET || DEFAULT_SECRET;",
        "const s3 = process.env.JWT_SECRET || process.env.FALLBACK_SECRET;",
        "const port = process.env.PORT || '3000';",
        "const url = process.env.DATABASE_URL || 'postgres://localhost/dev';",
        "const staff = (process.env.STAFF_EMAILS ?? '').split(',');",
        "const anon = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || 'public-anon';",
        "const ttl = process.env.TOKEN_TTL || '3600';",
        "const flag = process.env.API_KEY_REQUIRED || 'false';",
        "const tpl = process.env.SESSION_SECRET || `${prefix}-x`;",
      ].join("\n"),
    });
    expect(findings).toEqual([]);
  });

  it("does not flag cookie, storage-key or claim names that fall back to a label", async () => {
    const findings = await run({
      "lib/auth-cookies.ts": [
        'export const tokenCookie = process.env.AUTH_TOKEN_COOKIE || "auth_token";',
        'export const storageKey = process.env.TOKEN_STORAGE_KEY || "app.token";',
        'export const jwtCookie = process.env.JWT_COOKIE || "jwt";',
        'const cookieSecret = process.env.COOKIE_SECRET || "dev-cookie-secret";',
      ].join("\n"),
    });
    expect(findings.map((f) => f.line)).toEqual([4]);
  });

  it("redacts only the fallback literal, not identifiers containing the same text", async () => {
    const findings = await run({
      "lib/auth.ts": 'export const jwtSecretValue = process.env.JWT_SECRET || "jwt";',
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.evidence).toContain("jwtSecretValue = process.env.JWT_SECRET");
    expect(findings[0]!.evidence).not.toContain('"jwt"');
  });

  it("checks signer use once per binding, not per fallback", async () => {
    const lines = Array.from(
      { length: 3000 },
      (_, i) => `const s${i} = process.env.SECRET_${i} || "fallback-value-${i}";`,
    );
    lines.push("jwt.sign(payload, s0);");
    const started = Date.now();
    const findings = await run({ "lib/huge.ts": lines.join("\n") });
    expect(Date.now() - started).toBeLessThan(3000);
    expect(findings).toHaveLength(26);
    expect(findings[0]!.severity).toBe("critical");
    expect(findings[1]!.severity).toBe("high");
  });

  it("leaves lines with a recognised live key to the secret detector", async () => {
    const live = "sk_live_" + "a1B2c3D4e5F6g7H8i9J0k1L2";
    const findings = await run({
      "lib/stripe.ts": `const key = process.env.STRIPE_SECRET_KEY || "${live}";`,
    });
    expect(findings).toEqual([]);
  });

  it("ignores comments, strings, non-JS files and tests", async () => {
    const line = 'const JWT_SECRET = process.env.JWT_SECRET || "fallback-secret";';
    const findings = await run({
      "lib/a.ts": `// ${line}\nconst doc = '${line.replace(/'/g, "")}';`,
      "settings.py": 'SECRET = os.environ.get("JWT_SECRET") or "x" # process.env.JWT_SECRET || "y"',
      "db/seed.sql": line,
      ".env": "JWT_SECRET=abc",
      "lib/auth.test.ts": line,
      "tests/setup.ts": line,
    });
    expect(findings).toEqual([]);
  });

  it("produces stable ids across runs", async () => {
    const files = { "a.ts": "const s = process.env.COOKIE_SECRET || 'abc123';" };
    const a = await run(files);
    const b = await run(files);
    expect(a).toHaveLength(1);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("caps a file at 25 findings plus one medium-confidence summary", async () => {
    const src = Array.from(
      { length: 30 },
      (_, i) => `const s${i} = process.env.SECRET_${i} || "fallback-${i}";`,
    ).join("\n");
    const findings = await run({ "lib/many.ts": src });
    expect(findings).toHaveLength(26);
    expect(findings[25]!.confidence).toBe("medium");
    expect(findings[25]!.evidence).toContain("5 more");
  });
});
