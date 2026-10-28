import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { Detector, Finding, ScanContext, Severity } from "@vibesafe/shared";
import { loadUserConfig, CONFIG_FILE_NAMES } from "../../src/config/load-config.js";
import { validateUserConfig } from "../../src/config/schema.js";
import { defineConfig } from "../../src/config/user-config.js";
import { applyRuleOverrides, resolveOverride } from "../../src/scanner/rule-overrides.js";
import { ScannerPipeline } from "../../src/scanner/pipeline.js";
import { DetectorRegistry } from "../../src/scanner/detector-registry.js";

function finding(ruleId: string, severity: Severity, category: Finding["category"]): Finding {
  return {
    id: `${ruleId}-${severity}`,
    ruleId,
    title: ruleId,
    severity,
    category,
    deployBlocking: false,
    confidence: "high",
    file: "src/a.ts",
    line: 1,
    plainEnglishProblem: "p",
    whyItMatters: "w",
    fixSteps: [],
    autoFixAvailable: false,
    estimatedMinutes: 5,
  };
}

class FakeDetector implements Detector {
  name = "Fake";
  description = "fake";
  constructor(
    public id: string,
    public category: Finding["category"],
    private findings: Finding[],
  ) {}
  async detect(_ctx: ScanContext): Promise<Finding[]> {
    return this.findings;
  }
}

function makePipeline(): { pipeline: ScannerPipeline; ran: string[] } {
  const ran: string[] = [];
  const registry = new DetectorRegistry();
  const mk = (id: string, cat: Finding["category"], fs: Finding[]) => {
    const d = new FakeDetector(id, cat, fs);
    const orig = d.detect.bind(d);
    d.detect = async (c) => {
      ran.push(id);
      return orig(c);
    };
    registry.register(d);
  };
  mk("quality", "code_quality", [
    finding("code_quality/console-log", "low", "code_quality"),
    finding("code_quality/huge-file", "medium", "code_quality"),
  ]);
  mk("sec", "secret", [finding("secret/key", "critical", "secret")]);
  return { pipeline: new ScannerPipeline(registry), ran };
}

describe("user config file (#7)", () => {
  let tmp: string;
  beforeEach(async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), "vibesafe-cfg-"));
    await fs.mkdir(path.join(tmp, "src"), { recursive: true });
    await fs.writeFile(path.join(tmp, "src", "a.ts"), "export {};\n");
  });
  afterEach(async () => {
    await fs.rm(tmp, { recursive: true, force: true });
  });
  const write = (name: string, body: string) => fs.writeFile(path.join(tmp, name), body);

  describe("loader", () => {
    it("returns undefined when there is no config", async () => {
      expect(await loadUserConfig(tmp)).toBeUndefined();
    });

    it.each([
      [".vibesafe.config.json", `{"deep": true}`],
      ["vibesafe.config.json", `{"deep": true}`],
      [".vibesafe.config.ts", `const c: { deep: boolean } = { deep: true };\nexport default c;`],
      [".vibesafe.config.mts", `const c: { deep: boolean } = { deep: true };\nexport default c;`],
      [".vibesafe.config.js", `export default { deep: true };`],
      [".vibesafe.config.mjs", `export default { deep: true };`],
      [".vibesafe.config.cjs", `module.exports = { deep: true };`],
      ["vibesafe.config.cjs", `module.exports = { deep: true };`],
    ])("loads %s", async (name, body) => {
      await write(name, body);
      const loaded = await loadUserConfig(tmp);
      expect(loaded?.config.deep).toBe(true);
      expect(loaded?.scanConfig.deep).toBe(true);
      expect(path.basename(loaded!.filePath)).toBe(name);
    });

    it("prefers the dotted name over the plain name", async () => {
      await write("vibesafe.config.json", `{"deep": false}`);
      await write(".vibesafe.config.json", `{"deep": true}`);
      expect((await loadUserConfig(tmp))?.config.deep).toBe(true);
      expect(CONFIG_FILE_NAMES[0]).toBe(".vibesafe.config.ts");
    });

    it("supports defineConfig in a TS file and maps fields", async () => {
      await write(
        ".vibesafe.config.ts",
        `export default {
          rules: { "code_quality/*": "off", "secret/key": "high" },
          disabledDetectors: ["git-history"],
          categories: ["secret", "auth"],
          exclude: ["legacy/**"],
          includeTests: true,
          minSeverity: "medium",
          deep: true,
        };`,
      );
      const loaded = await loadUserConfig(tmp);
      expect(loaded?.scanConfig).toEqual({
        ruleOverrides: { "code_quality/*": "off", "secret/key": "high" },
        disabledDetectors: ["git-history"],
        enabledCategories: ["secret", "auth"],
        excludePatterns: ["legacy/**"],
        includeTests: true,
        minSeverity: "medium",
        deep: true,
      });
    });

    it("defineConfig is an identity helper", () => {
      const c = { deep: true };
      expect(defineConfig(c)).toBe(c);
    });

    it("throws a clear error for malformed JSON", async () => {
      await write(".vibesafe.config.json", "{ nope");
      await expect(loadUserConfig(tmp)).rejects.toThrow(/Failed to load \.vibesafe\.config\.json/);
    });

    it("throws a clear error when the script throws", async () => {
      await write(".vibesafe.config.js", `throw new Error("boom");`);
      await expect(loadUserConfig(tmp)).rejects.toThrow(/Failed to load .*boom/);
    });

    it("throws listing every validation problem", async () => {
      await write(".vibesafe.config.json", `{"rules":{"a":"nope"},"bogus":1,"deep":"yes"}`);
      await expect(loadUserConfig(tmp)).rejects.toThrow(/Invalid \.vibesafe\.config\.json[\s\S]*unknown option "bogus"[\s\S]*rules\["a"\][\s\S]*"deep"/);
    });
  });

  describe("validateUserConfig", () => {
    it("accepts an empty object and a full valid config", () => {
      expect(validateUserConfig({})).toEqual([]);
      expect(
        validateUserConfig({
          rules: { "x/*": "off", y: "low" },
          disabledDetectors: ["a"],
          categories: ["xss"],
          exclude: ["a"],
          includeTests: false,
          minSeverity: "high",
          deep: false,
        }),
      ).toEqual([]);
    });
    it.each([
      [null],
      [[]],
      ["str"],
      [{ rules: [] }],
      [{ rules: { a: 1 } }],
      [{ rules: { a: "info" } }],
      [{ disabledDetectors: "a" }],
      [{ exclude: [1] }],
      [{ categories: ["nope"] }],
      [{ categories: "secret" }],
      [{ includeTests: 1 }],
      [{ minSeverity: "urgent" }],
      [{ deep: "true" }],
      [{ unknownKey: 1 }],
    ])("rejects %j", (v) => {
      expect(validateUserConfig(v).length).toBeGreaterThan(0);
    });
  });

  describe("rule overrides", () => {
    it("exact beats glob; longer glob beats shorter", () => {
      const o = { "code_quality/*": "off", "code_quality/console-log": "high", "*": "low" } as const;
      expect(resolveOverride("code_quality/console-log", o)).toBe("high");
      expect(resolveOverride("code_quality/huge-file", o)).toBe("off");
      expect(resolveOverride("xss/x", o)).toBe("low");
      expect(resolveOverride("xss/x", { "code_quality/*": "off" })).toBeUndefined();
    });
    it("does not treat dots/regex chars in keys as wildcards", () => {
      expect(resolveOverride("a/bXc", { "a/b.c*": "off" })).toBeUndefined();
      expect(resolveOverride("a/b.cd", { "a/b.c*": "off" })).toBe("off");
    });
    it("drops off, changes severity, keeps others, does not mutate input", () => {
      const f = [finding("a/x", "low", "code_quality"), finding("b/y", "low", "code_quality")];
      const out = applyRuleOverrides(f, { "a/x": "off", "b/y": "critical" });
      expect(out).toHaveLength(1);
      expect(out[0]!.severity).toBe("critical");
      expect(out[0]!.deployBlocking).toBe(true);
      expect(f[1]!.severity).toBe("low");
      expect(applyRuleOverrides(f, undefined)).toBe(f);
    });
  });

  describe("pipeline integration", () => {
    it("applies config file: rules off + severity re-score", async () => {
      await write(
        ".vibesafe.config.json",
        JSON.stringify({ rules: { "code_quality/console-log": "off", "code_quality/huge-file": "critical" } }),
      );
      const { pipeline } = makePipeline();
      const base = await pipeline.scan({ rootPath: tmp, useConfigFile: false });
      const res = await pipeline.scan({ rootPath: tmp });
      expect(base.findings).toHaveLength(3);
      expect(res.findings.map((f) => f.ruleId)).not.toContain("code_quality/console-log");
      const huge = res.findings.find((f) => f.ruleId === "code_quality/huge-file")!;
      expect(huge.severity).toBe("critical");
      expect(res.summary.criticalCount).toBe(2);
      expect(res.score).toBeLessThan(base.score);
      expect(res.deployStatus).toBe("blocker");
    });

    it("lowering a critical finding removes the blocker", async () => {
      await write(".vibesafe.config.json", JSON.stringify({ rules: { "secret/key": "low" } }));
      const { pipeline } = makePipeline();
      const res = await pipeline.scan({ rootPath: tmp });
      expect(res.deployStatus).not.toBe("blocker");
      expect(res.findings.at(-1)!.ruleId).toBe("secret/key");
    });

    it("disabledDetectors and categories skip detectors", async () => {
      await write(".vibesafe.config.json", JSON.stringify({ disabledDetectors: ["quality"] }));
      const a = makePipeline();
      await a.pipeline.scan({ rootPath: tmp });
      expect(a.ran).toEqual(["sec"]);

      await write(".vibesafe.config.json", JSON.stringify({ categories: ["code_quality"] }));
      const b = makePipeline();
      await b.pipeline.scan({ rootPath: tmp });
      expect(b.ran).toEqual(["quality"]);
    });

    it("explicit options win over file values", async () => {
      await write(".vibesafe.config.json", JSON.stringify({ categories: ["code_quality"], minSeverity: "critical" }));
      const { pipeline, ran } = makePipeline();
      const res = await pipeline.scan({ rootPath: tmp, enabledCategories: ["secret"], minSeverity: "low" });
      expect(ran).toEqual(["sec"]);
      expect(res.findings.map((f) => f.ruleId)).toEqual(["secret/key"]);
    });

    it("undefined explicit options do not clobber file values", async () => {
      await write(".vibesafe.config.json", JSON.stringify({ minSeverity: "critical" }));
      const { pipeline } = makePipeline();
      const res = await pipeline.scan({ rootPath: tmp, minSeverity: undefined, deep: undefined });
      expect(res.findings.map((f) => f.ruleId)).toEqual(["secret/key"]);
    });

    it("exclude and includeTests come from the file", async () => {
      await fs.mkdir(path.join(tmp, "legacy"), { recursive: true });
      await fs.writeFile(path.join(tmp, "legacy", "old.ts"), "x");
      await fs.mkdir(path.join(tmp, "tests"), { recursive: true });
      await fs.writeFile(path.join(tmp, "tests", "t.ts"), "x");
      const seen: string[][] = [];
      const registry = new DetectorRegistry();
      const d = new FakeDetector("s", "secret", []);
      d.detect = async (c) => {
        seen.push([...c.files]);
        return [];
      };
      registry.register(d);
      const pipeline = new ScannerPipeline(registry);

      await pipeline.scan({ rootPath: tmp });
      expect(seen[0]).toContain("legacy/old.ts");
      expect(seen[0]).not.toContain("tests/t.ts");

      await write(".vibesafe.config.json", JSON.stringify({ exclude: ["legacy/**"], includeTests: true }));
      await pipeline.scan({ rootPath: tmp });
      expect(seen[1]).not.toContain("legacy/old.ts");
      expect(seen[1]).toContain("tests/t.ts");
      // explicit false overrides the file's true
      await pipeline.scan({ rootPath: tmp, includeTests: false });
      expect(seen[2]).not.toContain("tests/t.ts");
    });

    it("useConfigFile:false ignores even an invalid file", async () => {
      await write(".vibesafe.config.json", "{ broken");
      const { pipeline } = makePipeline();
      await expect(pipeline.scan({ rootPath: tmp })).rejects.toThrow(/Failed to load/);
      await expect(pipeline.scan({ rootPath: tmp, useConfigFile: false })).resolves.toBeDefined();
    });
  });
});
