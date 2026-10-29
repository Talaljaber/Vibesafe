import { describe, it, expect } from "vitest";
import { SecretDetector } from "../../src/detectors/secret-detector";
import type { ScanContext } from "@talaljaber/vibesafe-shared";

describe("SecretDetector", () => {
  const detector = new SecretDetector();

  const createContext = (files: Record<string, string>): ScanContext => ({
    rootPath: "/fake/path",
    projectContext: {} as any,
    files: Object.keys(files),
    config: {} as any,
    readFile: async (file) => files[file] || "",
  });

  it("should detect exposed openai keys", async () => {
    const context = createContext({
      "app/api/route.ts": "const key = 'sk-123456789012345678901234567890123456789012345678';",
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(1);
    expect(findings[0].category).toBe("secret");
    expect(findings[0].ruleId).toBe("secret/sec-openai-key");
  });

  it("should flag .env missing from .gitignore", async () => {
    const context = createContext({
      ".env": "DB_PASS=123",
      ".gitignore": "node_modules\n",
    });
    const findings = await detector.detect(context);
    expect(findings.some((f) => f.ruleId === "secret/env-not-ignored")).toBe(true);
  });

  it("should not flag if .env is in .gitignore", async () => {
    const context = createContext({
      ".env": "DB_PASS=123",
      ".gitignore": "node_modules\n.env\n",
    });
    const findings = await detector.detect(context);
    expect(findings.some((f) => f.ruleId === "secret/env-not-ignored")).toBe(false);
  });

  const envFindings = async (files: Record<string, string>) =>
    (await detector.detect(createContext(files))).filter(
      (f) => f.ruleId === "secret/env-not-ignored",
    );

  it("does not treat .envrc, comments or negations as ignoring .env", async () => {
    expect(await envFindings({ ".env": "A=1", ".gitignore": ".envrc\n" })).toHaveLength(1);
    expect(await envFindings({ ".env": "A=1", ".gitignore": "# .env\n" })).toHaveLength(1);
    expect(await envFindings({ ".env": "A=1", ".gitignore": ".env\n!.env\n" })).toHaveLength(1);
  });

  it("checks every .env* file and skips templates", async () => {
    const found = await envFindings({
      ".env": "A=1",
      ".env.production": "A=1",
      ".env.example": "A=",
      ".env.sample": "A=",
      ".env.template": "A=",
      ".gitignore": ".env\n",
    });
    expect(found.map((f) => f.file)).toEqual([".env.production"]);
    expect(await envFindings({ ".env.production": "A=1", ".gitignore": ".env*\n" })).toHaveLength(
      0,
    );
  });

  it("skips yarn.lock", async () => {
    const findings = await detector.detect(
      createContext({
        "yarn.lock": "const key = 'sk-123456789012345678901234567890123456789012345678';",
      }),
    );
    expect(findings).toHaveLength(0);
  });

  describe("severity", () => {
    const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    const jwt = (role: string) => `${header}.${b64({ role, iss: "supabase" })}.${"s".repeat(20)}`;

    it("keeps live provider keys critical and blocking", async () => {
      const [f] = await detector.detect(
        createContext({ "a.ts": "k = 'sk-123456789012345678901234567890123456789012345678'" }),
      );
      expect(f?.severity).toBe("critical");
      expect(f?.deployBlocking).toBe(true);
    });

    it("makes generic and Stripe test patterns non-blocking", async () => {
      const findings = await detector.detect(
        createContext({
          "a.ts": 'const password = "placeholder";\nconst k = "sk_test_' + "a".repeat(24) + '";',
          "b.ts": 'const secret = "abcdefghijkl";',
        }),
      );
      expect(findings.length).toBeGreaterThanOrEqual(3);
      for (const f of findings) {
        expect(["low", "medium"]).toContain(f.severity);
        expect(f.deployBlocking).toBe(false);
      }
    });

    it("reports a service_role JWT once, as a service key", async () => {
      const findings = await detector.detect(
        createContext({ "a.ts": `const k = "${jwt("service_role")}";` }),
      );
      expect(findings.map((f) => f.ruleId)).toEqual(["secret/sec-supabase-service-key"]);
      expect(findings[0]?.deployBlocking).toBe(true);
    });

    it("does not flag an anon key as a service key", async () => {
      const findings = await detector.detect(
        createContext({ "a.ts": `const k = "${jwt("anon")}";` }),
      );
      expect(findings.some((f) => f.ruleId === "secret/sec-supabase-service-key")).toBe(false);
      expect(findings.some((f) => f.deployBlocking)).toBe(false);
    });
  });

  describe("database URLs with passwords", () => {
    const DB_HOST = "db.kq7wpzt3hxv.supabase.co";
    // Built at runtime so this test file does not itself contain a scannable URL.
    const PW = "Xk9prodQ2v7";
    const dbUrl = (pass: string, host = DB_HOST, scheme = "postgres", user = "postgres") =>
      `${scheme}://${user}:${pass}@${host}:5432/postgres`;
    const urlFindings = async (files: Record<string, string>) =>
      (await detector.detect(createContext(files))).filter(
        (f) => f.ruleId === "secret/sec-database-url",
      );

    it.each([
      ["postgres", dbUrl(PW)],
      ["postgresql", dbUrl(PW, DB_HOST, "postgresql")],
      ["mysql", dbUrl(PW, "mysql.prod.internal.acme.io", "mysql", "app")],
      ["mongodb+srv", `mongodb+srv://app:${PW}@cluster0.ab1cd.mongodb.net/shop`],
      ["rediss with empty user", `rediss://:${PW}@cache.acme-prod.io:6380`],
      ["amqps", `amqps://svc:${PW}@rabbit.acme-prod.io/vhost`],
    ])("flags a %s URL in code, .env and shell scripts", async (_name, url) => {
      const findings = await urlFindings({
        "scripts/backup.js": `const DATABASE_URL = process.env.DATABASE_URL ||\n  "${url}";`,
        ".env.production": `DATABASE_URL=${url}`,
        "scripts/restore.sh": `pg_restore -d "${url}" dump.bin`,
      });
      expect(findings.map((f) => [f.file, f.line])).toEqual([
        ["scripts/backup.js", 2],
        [".env.production", 1],
        ["scripts/restore.sh", 1],
      ]);
      for (const f of findings) {
        expect(f.severity).toBe("high");
        expect(f.confidence).toBe("high");
        expect(f.deployBlocking).toBe(false);
        expect(f.evidence).not.toContain(PW);
        expect(f.fixSteps[0]).toMatch(/Rotate the database password/);
        expect(f.aiFixPrompt).toMatch(/DATABASE_URL/);
      }
    });

    it.each([
      ["localhost", dbUrl(PW, "localhost")],
      ["loopback", dbUrl(PW, "127.0.0.1")],
      ["compose service (single-label host)", dbUrl(PW, "db")],
      ["default password", dbUrl("postgres")],
      ["password placeholder", dbUrl("<password>", "<host>", "postgres", "<user>")],
      ["changeme", dbUrl("changeme")],
      ["template interpolation", dbUrl("${DB_PASSWORD}")],
      ["shell variable", dbUrl("$PGPASSWORD")],
      ["printf placeholder", dbUrl("%s")],
      ["example host", dbUrl(PW, "db.example.com")],
      ["password equals user", dbUrl("appuser", DB_HOST, "postgres", "appuser")],
      ["no password", `postgres://postgres@${DB_HOST}:5432/postgres`],
      ["https URL", `https://user:${PW}@${DB_HOST}/`],
      [
        "Supabase pooler placeholder",
        dbUrl(
          "[YOUR-PASSWORD]",
          "aws-0-us-east-1.pooler.supabase.com",
          "postgresql",
          "postgres.kq7wpzt3hxv",
        ),
      ],
      ["Supabase direct placeholder", dbUrl("[YOUR-PASSWORD]", DB_HOST, "postgresql")],
      ["Upstash placeholder", "redis://default:your-redis-password@redis.upstash.io:6379"],
      ["upper-case placeholder", dbUrl("YOUR_DB_PASSWORD")],
    ])("does not flag %s", async (_name, url) => {
      expect(
        await urlFindings({ "a.ts": `const u = "${url}";`, ".env.example": `X=${url}` }),
      ).toEqual([]);
    });
  });
});
