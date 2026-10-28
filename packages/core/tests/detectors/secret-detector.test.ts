import { describe, it, expect } from "vitest";
import { SecretDetector } from "../../src/detectors/secret-detector";
import type { ScanContext } from "@vibesafe/shared";

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
    expect(findings.some(f => f.ruleId === "secret/env-not-ignored")).toBe(true);
  });

  it("should not flag if .env is in .gitignore", async () => {
    const context = createContext({
      ".env": "DB_PASS=123",
      ".gitignore": "node_modules\n.env\n",
    });
    const findings = await detector.detect(context);
    expect(findings.some(f => f.ruleId === "secret/env-not-ignored")).toBe(false);
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
    expect(await envFindings({ ".env.production": "A=1", ".gitignore": ".env*\n" })).toHaveLength(0);
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
});
