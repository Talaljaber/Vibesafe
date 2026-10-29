import { describe, it, expect } from "vitest";
import type { Finding } from "@talaljaber/vibesafe-shared";
import {
  formatDelta,
  isExcludedPath,
  isRelevantPath,
  stripControl,
} from "../src/commands/watch.js";

const finding = (over: Partial<Finding> = {}): Finding => ({
  id: "SEC-1",
  ruleId: "secret/key",
  title: "Key",
  severity: "high",
  category: "secret",
  deployBlocking: false,
  confidence: "high",
  file: "a.ts",
  line: 2,
  plainEnglishProblem: "",
  whyItMatters: "",
  fixSteps: [],
  autoFixAvailable: false,
  ...over,
});

const delta = (over = {}) => ({
  added: [],
  resolved: [],
  scoreBefore: 100,
  scoreAfter: 100,
  scoreChange: 0,
  statusAfter: "safe" as const,
  ...over,
});

describe("isExcludedPath", () => {
  it.each([
    "node_modules/x/index.js",
    "src/node_modules/x.js",
    ".git/config",
    "dist/a.js",
    "build/a.js",
    "packages/cli/dist/a.js",
    "apps/web/build/x/a.js",
  ])("excludes %s", (p) => expect(isExcludedPath(p)).toBe(true));
  it.each([
    "src/dist/a.ts",
    "src/build/a.ts",
    "src/app.ts",
    "dist",
    "",
    "packages/cli/src/a.ts",
    "packages/dist/a.js",
    "other/x/dist/a.js",
  ])("keeps %s", (p) => expect(isExcludedPath(p)).toBe(false));
  it("handles windows separators", () => {
    expect(isExcludedPath("a\\node_modules\\b.js")).toBe(true);
  });
});

describe("isRelevantPath", () => {
  it.each(["src/a.ts", "package.json", ".gitignore", ".env", ".env.local", "x/prod.env"])(
    "true for %s",
    (p) => expect(isRelevantPath(p)).toBe(true),
  );
  it.each(["image.png", "notes.xyz"])("false for %s", (p) => expect(isRelevantPath(p)).toBe(false));
});

describe("stripControl", () => {
  it("removes ESC and other control characters", () => {
    expect(stripControl("a\u001b]0;pwned\u0007b\u009bc\n")).toBe("a]0;pwnedbc");
  });
});

describe("formatDelta", () => {
  it("reports no change", () => {
    const out = formatDelta(delta(), ["a.ts"]).join("\n");
    expect(out).toContain("no change in findings");
    expect(out).toContain("score 100 -> 100 (0), status: safe");
  });

  it("lists added and resolved findings with a signed score and truncates files", () => {
    const out = formatDelta(
      delta({
        added: [finding()],
        resolved: [finding({ title: "Old", file: "b.ts", line: undefined })],
        scoreChange: 5,
        scoreAfter: 105,
      }),
      ["1", "2", "3", "4", "5", "6", "7"],
    ).join("\n");
    expect(out).toContain("+ new");
    expect(out).toContain("[high] Key (a.ts:2)");
    expect(out).toContain("- resolved");
    expect(out).toContain("[high] Old (b.ts)");
    expect(out).toContain("+2 more");
    expect(out).toContain("(+5)");
  });

  it("strips terminal control sequences from untrusted names", () => {
    const out = formatDelta(
      delta({ added: [finding({ file: "evil\u001b[2J.ts", title: "t\u001b]0;x\u0007" })] }),
      ["f\u001b[31m.ts"],
    ).join("\n");
    // eslint-disable-next-line no-control-regex
    expect(out.replace(/\u001b\[[0-9;]*m/g, "")).not.toMatch(/[\u0000-\u0009\u000b-\u001f\u007f]/);
  });
});
