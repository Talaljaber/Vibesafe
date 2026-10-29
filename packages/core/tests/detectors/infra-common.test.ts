import { describe, it, expect } from "vitest";
import type { Finding } from "@talaljaber/vibesafe-shared";
import {
  capFindingsPerRule,
  credentialNameKind,
  findUrlCredential,
  hasSpecificSecret,
  looksLikeSecretValue,
} from "../../src/detectors/utils/infra-common.js";
import { makeFinding } from "../../src/detectors/utils/finding.js";

describe("credentialNameKind", () => {
  it("requires the credential word at the end of the name", () => {
    for (const name of [
      "JWT_SECRET",
      "DB_PASSWORD",
      "GITHUB_TOKEN",
      "STRIPE_SECRET_KEY",
      "AWS_SECRET_ACCESS_KEY",
      "SUPABASE_SERVICE_ROLE_KEY",
      "SECRET_KEY_BASE",
      "API_TOKEN_2",
      "DB_PASSWORD_PROD",
      "NEXTAUTH_SECRET",
      "SECRET_KEY",
      "APP_KEY",
    ]) {
      expect(credentialNameKind(name), name).toBe("credential");
    }
    for (const name of [
      "TOKEN_ISSUER",
      "TOKEN_TYPE",
      "PASSWORD_HASHER",
      "AWS_CREDENTIALS_SOURCE",
      "CREDENTIALS_PROVIDER",
      "PASSWORD_POLICY",
      "SECRET_MANAGER",
      "API_KEY_PREFIX",
      "DB_PASSWORD_FILE",
      "TOKEN_TTL",
      "NEXT_PUBLIC_API_KEY",
      "STRIPE_PUBLISHABLE_KEY",
      "SUPABASE_ANON_KEY",
    ]) {
      expect(credentialNameKind(name), name).toBeUndefined();
    }
    expect(credentialNameKind("DATABASE_URL")).toBe("connection");
    expect(credentialNameKind("SENTRY_DSN")).toBe("connection");
  });
});

describe("looksLikeSecretValue", () => {
  it("rejects references, placeholders, config words, paths and URLs without a password", () => {
    for (const v of [
      "${X}",
      "changeme",
      "Bearer",
      "development",
      "RS256",
      "argon2id",
      "3600",
      "/run/secrets/x",
      "./key.pem",
      "creds.json",
      "https://auth.example.com",
      "postgres://app:${PW}@db/app",
    ]) {
      expect(looksLikeSecretValue(v), v).toBe(false);
    }
    for (const v of ["hunter22", "4f9a8c1e2b7d6f3a9e0c", "postgres://app:s3cret@db/app"]) {
      expect(looksLikeSecretValue(v), v).toBe(true);
    }
  });
});

describe("findUrlCredential", () => {
  it("finds the first URL with a password and stays linear on long input", () => {
    expect(findUrlCredential("x=http://a.b/c then mysql://root:pw1@db:3306/x")).toEqual({
      scheme: "mysql",
      user: "root",
      password: "pw1",
      host: "db",
    });
    expect(findUrlCredential("https://example.com/a")).toBeUndefined();
    const long = "a.".repeat(200_000) + "://x";
    const started = Date.now();
    expect(findUrlCredential(long)).toBeUndefined();
    expect(Date.now() - started).toBeLessThan(1000);
  });
});

describe("hasSpecificSecret", () => {
  it("ignores the low-confidence generic patterns", () => {
    expect(hasSpecificSecret('password: "postgres"')).toBe(false);
    expect(hasSpecificSecret('JWT_SECRET="4f9a8c1e2b7d6f3a9e0c"')).toBe(false);
    expect(hasSpecificSecret("ghp_" + "a".repeat(10) + "B".repeat(10) + "c".repeat(16))).toBe(true);
  });
});

describe("capFindingsPerRule", () => {
  const f = (ruleId: string, file: string, line: number): Finding =>
    makeFinding({
      category: "security_config",
      ruleId,
      title: "T",
      severity: "high",
      confidence: "high",
      file,
      line,
      evidence: `line ${line}`,
      plainEnglishProblem: "P",
      whyItMatters: "W",
      fixSteps: ["S"],
      aiFixPrompt: "A",
    });

  it("caps per rule and file and leaves smaller groups alone", () => {
    const input = [
      ...Array.from({ length: 4 }, (_, i) => f("security_config/a", "x", i + 1)),
      ...Array.from({ length: 2 }, (_, i) => f("security_config/a", "y", i + 1)),
      ...Array.from({ length: 3 }, (_, i) => f("security_config/b", "x", i + 1)),
    ];
    const out = capFindingsPerRule(input, 2);
    expect(out.map((o) => [o.ruleId, o.file, o.line, o.confidence])).toEqual([
      ["security_config/a", "x", 1, "high"],
      ["security_config/a", "x", 2, "high"],
      ["security_config/a", "x", 3, "medium"],
      ["security_config/a", "y", 1, "high"],
      ["security_config/a", "y", 2, "high"],
      ["security_config/b", "x", 1, "high"],
      ["security_config/b", "x", 2, "high"],
      ["security_config/b", "x", 3, "medium"],
    ]);
    expect(out[2]!.title).toBe("T (2 more in this file)");
    expect(new Set(out.map((o) => o.id)).size).toBe(out.length);
  });
});
