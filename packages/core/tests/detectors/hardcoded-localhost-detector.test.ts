import { describe, it, expect } from "vitest";
import { HardcodedLocalhostDetector } from "../../src/detectors/hardcoded-localhost-detector";
import type { ScanContext } from "@vibesafe/shared";

describe("HardcodedLocalhostDetector", () => {
  const detector = new HardcodedLocalhostDetector();

  const createContext = (files: Record<string, string>): ScanContext => ({
    rootPath: "/fake/path",
    projectContext: {} as any,
    files: Object.keys(files),
    config: {} as any,
    readFile: async (file) => files[file] || "",
  });

  it("should detect localhost URLs in code files", async () => {
    const context = createContext({
      "app/api.ts": `const apiBaseUrl = "http://localhost:3000/api";`,
    });

    const findings = await detector.detect(context);

    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("code_quality/hardcoded-localhost");
    expect(findings[0].line).toBe(1);
  });

  it("should detect loopback and private network IP addresses", async () => {
    const context = createContext({
      "src/config.ts": `
        export const localApi = "http://127.0.0.1:8080";
        export const officeApi = "http://192.168.1.20:8080";
        export const serviceApi = "http://10.0.0.5:8080";
        export const stagingApi = "http://172.16.4.10:8080";
        export const ipv6Local = "http://[::1]:8080";
      `,
      "src/server.mjs": `const db = "mongodb://localhost:27017";`,
    });

    const findings = await detector.detect(context);

    expect(findings).toHaveLength(6);
    expect(findings.every((finding) => finding.ruleId === "code_quality/hardcoded-localhost")).toBe(
      true,
    );
  });

  it("should ignore public IP addresses and non-code files", async () => {
    const context = createContext({
      "src/config.ts": `const apiBaseUrl = "https://8.8.8.8/api";`,
      "README.md": `Use http://localhost:3000 for local development.`,
    });

    const findings = await detector.detect(context);

    expect(findings).toHaveLength(0);
  });

  it("should ignore localhost references in test files", async () => {
    const context = createContext({
      "src/api.test.ts": `const apiBaseUrl = "http://localhost:3000/api";`,
      "src/api.spec.ts": `const apiBaseUrl = "http://127.0.0.1:3000/api";`,
      "src/__tests__/api.ts": `const apiBaseUrl = "http://192.168.1.20:3000/api";`,
      "__tests__/api.ts": `const apiBaseUrl = "http://10.0.0.5:3000/api";`,
      "src/api.ts": `const apiBaseUrl = "http://10.0.0.5:3000/api";`,
    });

    const findings = await detector.detect(context);

    expect(findings).toHaveLength(1);
    expect(findings[0].file).toBe("src/api.ts");
  });
});
