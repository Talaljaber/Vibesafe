import { describe, it, expect } from "vitest";
import type { Finding, ScanResult, Severity } from "@vibesafe/shared";
import { formatSarif, toSarifUri, FINGERPRINT_KEY } from "../src/formatters/sarif.js";
import { isOutputFormat, renderOutput } from "../src/formatters/index.js";

function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: "SEC-abc123",
    ruleId: "secret/hardcoded-api-key",
    title: "Hardcoded API key",
    severity: "critical",
    category: "secret",
    deployBlocking: true,
    confidence: "high",
    file: "src/app.ts",
    line: 12,
    evidence: "sk-THIS-MUST-NOT-LEAK",
    plainEnglishProblem: "Your key is in the code.",
    whyItMatters: "Anyone can use it.",
    fixSteps: ["Move it to .env", "Rotate the key"],
    autoFixAvailable: false,
    tags: ["nextjs"],
    ...over,
  };
}

function scan(findings: Finding[]): ScanResult {
  return { findings } as unknown as ScanResult;
}

describe("formatSarif", () => {
  it("emits a minimal SARIF 2.1.0 document shape", () => {
    const log = formatSarif(scan([finding()]), "1.2.3");
    expect(log.version).toBe("2.1.0");
    expect(log.$schema).toMatch(/sarif-2\.1\.0/);
    expect(log.runs).toHaveLength(1);
    const driver = log.runs[0]!.tool.driver;
    expect(driver.name).toBe("VibeSafe");
    expect(driver.version).toBe("1.2.3");
    expect(driver.informationUri).toMatch(/^https:\/\//);
    expect(Array.isArray(driver.rules)).toBe(true);
    expect(Array.isArray(log.runs[0]!.results)).toBe(true);
  });

  it("is valid with zero findings", () => {
    const log = formatSarif(scan([]), "0.0.0");
    expect(log.runs[0]!.results).toEqual([]);
    expect(log.runs[0]!.tool.driver.rules).toEqual([]);
  });

  it("builds rules and results with location, fingerprint and help", () => {
    const log = formatSarif(scan([finding()]), "1");
    const rule = log.runs[0]!.tool.driver.rules[0]!;
    expect(rule.id).toBe("secret/hardcoded-api-key");
    expect(rule.shortDescription.text).toBe("Hardcoded API key");
    expect(rule.help.text).toBe("1. Move it to .env\n2. Rotate the key");
    expect(rule.properties.tags).toEqual(["nextjs"]);
    expect(rule.properties.category).toBe("secret");
    expect(rule.properties["security-severity"]).toBe("9.0");

    const result = log.runs[0]!.results[0]!;
    expect(result.ruleId).toBe(rule.id);
    expect(log.runs[0]!.tool.driver.rules[result.ruleIndex]!.id).toBe(result.ruleId);
    expect(result.level).toBe("error");
    expect(result.message.text).toBe("Your key is in the code.");
    expect(result.partialFingerprints[FINGERPRINT_KEY]).toBe("SEC-abc123");
    const loc = result.locations![0]!.physicalLocation;
    expect(loc.artifactLocation.uri).toBe("src/app.ts");
    expect(loc.region).toEqual({ startLine: 12 });
  });

  it.each<[Severity, string, string]>([
    ["critical", "error", "9.0"],
    ["high", "error", "7.5"],
    ["medium", "warning", "5.0"],
    ["low", "note", "3.0"],
  ])("maps %s to level %s and security-severity %s", (severity, level, score) => {
    const log = formatSarif(scan([finding({ severity })]), "1");
    expect(log.runs[0]!.results[0]!.level).toBe(level);
    expect(log.runs[0]!.tool.driver.rules[0]!.properties["security-severity"]).toBe(score);
  });

  it("deduplicates rules and keeps ruleIndex consistent", () => {
    const log = formatSarif(
      scan([
        finding({ id: "A", line: 1 }),
        finding({ id: "B", ruleId: "auth/x", category: "auth", severity: "low" }),
        finding({ id: "C", line: 3, severity: "low", tags: ["vite"] }),
      ]),
      "1",
    );
    const { rules } = log.runs[0]!.tool.driver;
    expect(rules.map((r) => r.id)).toEqual(["secret/hardcoded-api-key", "auth/x"]);
    // Rule takes the highest severity of its findings and the union of tags.
    expect(rules[0]!.properties["security-severity"]).toBe("9.0");
    expect(rules[0]!.properties.tags).toEqual(["nextjs", "vite"]);
    expect(log.runs[0]!.results.map((r) => r.ruleIndex)).toEqual([0, 1, 0]);
  });

  it("omits locations when there is no file and region when line is unknown", () => {
    const noFile = formatSarif(scan([finding({ file: undefined, line: undefined })]), "1");
    expect(noFile.runs[0]!.results[0]!.locations).toBeUndefined();

    const noLine = formatSarif(scan([finding({ line: undefined })]), "1");
    const loc = noLine.runs[0]!.results[0]!.locations![0]!.physicalLocation;
    expect(loc.region).toBeUndefined();
    expect(loc.artifactLocation.uri).toBe("src/app.ts");
  });

  it("ignores invalid line numbers and inconsistent end positions", () => {
    for (const line of [0, -3, 1.5, NaN]) {
      const log = formatSarif(scan([finding({ line })]), "1");
      expect(log.runs[0]!.results[0]!.locations![0]!.physicalLocation.region).toBeUndefined();
    }
    const log = formatSarif(scan([finding({ line: 10, endLine: 5, column: 4, endColumn: 2 })]), "1");
    expect(log.runs[0]!.results[0]!.locations![0]!.physicalLocation.region).toEqual({
      startLine: 10,
      startColumn: 4,
    });
  });

  it("includes end line and columns when valid", () => {
    const log = formatSarif(scan([finding({ line: 10, endLine: 12, column: 2, endColumn: 8 })]), "1");
    expect(log.runs[0]!.results[0]!.locations![0]!.physicalLocation.region).toEqual({
      startLine: 10,
      endLine: 12,
      startColumn: 2,
    });
    const same = formatSarif(scan([finding({ line: 10, endLine: 10, column: 2, endColumn: 8 })]), "1");
    expect(same.runs[0]!.results[0]!.locations![0]!.physicalLocation.region).toEqual({
      startLine: 10,
      endLine: 10,
      startColumn: 2,
      endColumn: 8,
    });
  });

  it("never leaks evidence into the output", () => {
    const text = JSON.stringify(formatSarif(scan([finding()]), "1"));
    expect(text).not.toContain("sk-THIS-MUST-NOT-LEAK");
  });

  it("falls back to the problem text as help when there are no fix steps", () => {
    const log = formatSarif(scan([finding({ fixSteps: [] })]), "1");
    expect(log.runs[0]!.tool.driver.rules[0]!.help.text).toBe("Your key is in the code.");
  });

  it("includes helpUri only when learnMoreUrl is set", () => {
    const withUrl = formatSarif(scan([finding({ learnMoreUrl: "https://example.com/x" })]), "1");
    expect(withUrl.runs[0]!.tool.driver.rules[0]!.helpUri).toBe("https://example.com/x");
    const without = formatSarif(scan([finding()]), "1");
    expect(without.runs[0]!.tool.driver.rules[0]).not.toHaveProperty("helpUri");
  });

  it("keeps instance-specific text out of rule metadata", () => {
    const log = formatSarif(
      scan([
        finding({ ruleId: "dependency/risky-install-script", title: 'Risky lifecycle script: "postinstall"', plainEnglishProblem: "postinstall runs x", whyItMatters: "Scripts run on install.", fixSteps: ["Review a"] }),
        finding({ id: "B", ruleId: "dependency/risky-install-script", title: 'Risky lifecycle script: "preinstall"', plainEnglishProblem: "preinstall runs y", whyItMatters: "Scripts run on install.", fixSteps: ["Review b"] }),
      ]),
      "1",
    );
    const rule = log.runs[0]!.tool.driver.rules[0]!;
    expect(rule.shortDescription.text).toBe("dependency: risky install script");
    expect(rule.fullDescription.text).toBe("Scripts run on install.");
    expect(JSON.stringify(rule)).not.toMatch(/postinstall|preinstall|Review/);
    expect(log.runs[0]!.results.map((r) => r.message.text)).toEqual(["postinstall runs x", "preinstall runs y"]);
  });

  it("reports detector errors and warnings as invocation notifications", () => {
    const ok = formatSarif(scan([]), "1");
    expect(ok.runs[0]!.invocations).toEqual([{ executionSuccessful: true, toolExecutionNotifications: [] }]);
    const bad = formatSarif(
      { findings: [], errors: [{ detectorId: "d", detectorName: "Det", message: "boom" }], warnings: ["careful"] } as unknown as ScanResult,
      "1",
    );
    const inv = bad.runs[0]!.invocations[0]!;
    expect(inv.executionSuccessful).toBe(false);
    expect(inv.toolExecutionNotifications).toEqual([
      { level: "error", message: { text: "Det: boom" } },
      { level: "warning", message: { text: "careful" } },
    ]);
  });

  it("declares %SRCROOT% in originalUriBaseIds", () => {
    expect(formatSarif(scan([finding()]), "1").runs[0]!.originalUriBaseIds).toHaveProperty("%SRCROOT%");
  });
  it("round-trips through JSON", () => {
    const log = formatSarif(scan([finding()]), "1");
    expect(JSON.parse(JSON.stringify(log))).toEqual(log);
  });
});

describe("toSarifUri", () => {
  it("uses forward slashes and strips leading ./", () => {
    expect(toSarifUri("src\\app\\page.tsx")).toBe("src/app/page.tsx");
    expect(toSarifUri("./src/a.ts")).toBe("src/a.ts");
  });

  it("percent-encodes spaces and URI-reserved characters", () => {
    expect(toSarifUri("my dir/a#b?.ts")).toBe("my%20dir/a%23b%3F.ts");
  });
});

describe("output format registry", () => {
  it("recognises supported formats only", () => {
    expect(isOutputFormat("json")).toBe(true);
    expect(isOutputFormat("sarif")).toBe(true);
    expect(isOutputFormat("xml")).toBe(false);
    expect(isOutputFormat("toString")).toBe(false);
    expect(isOutputFormat("__proto__")).toBe(false);
  });

  it("renders sarif as parseable JSON", () => {
    const out = renderOutput("sarif", scan([finding()]), { version: "9" });
    expect(JSON.parse(out).version).toBe("2.1.0");
  });
});
