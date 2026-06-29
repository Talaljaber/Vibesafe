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
});
