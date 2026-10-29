import { describe, it, expect } from "vitest";
import { applyInlineIgnores } from "../../src/scanner/inline-ignores.js";
import type { Finding } from "@talaljaber/vibesafe-shared";

function f(ruleId: string, line?: number, file: string | null = "a.ts"): Finding {
  return {
    id: `${ruleId}:${line ?? "none"}`,
    ruleId,
    title: "t",
    severity: "low",
    category: "code_quality",
    deployBlocking: false,
    confidence: "high",
    plainEnglishProblem: "p",
    whyItMatters: "w",
    fixSteps: [],
    autoFixAvailable: false,
    ...(file ? { file } : {}),
    ...(line ? { line } : {}),
  };
}

async function run(content: string, findings: Finding[]): Promise<string[]> {
  const kept = await applyInlineIgnores(findings, async () => content);
  return kept.map((k) => k.id);
}

describe("applyInlineIgnores", () => {
  it("disable-line with no ids suppresses all rules on that line", async () => {
    const src = ["const a = 1;", "console.log(x); // vibesafe-disable-line"].join("\n");
    expect(
      await run(src, [f("code_quality/console-log", 2), f("secret/x", 2), f("secret/x", 1)]),
    ).toEqual(["secret/x:1"]);
  });

  it("disable-line with ids suppresses only those rules", async () => {
    const src = "foo(); // vibesafe-disable-line code_quality/console-log, secret/x";
    const kept = await run(src, [
      f("code_quality/console-log", 1),
      f("secret/x", 1),
      f("auth/missing-route-auth", 1),
    ]);
    expect(kept).toEqual(["auth/missing-route-auth:1"]);
  });

  it("disable-next-line applies to the following line only", async () => {
    const src = [
      "// vibesafe-disable-next-line secret/x",
      "const k = 'abc';",
      "const j = 'def';",
    ].join("\n");
    expect(await run(src, [f("secret/x", 2), f("secret/x", 3), f("other/y", 2)])).toEqual([
      "secret/x:3",
      "other/y:2",
    ]);
  });

  it("disable-file with ids only suppresses those rules, including findings without a line", async () => {
    const src = "/* vibesafe-disable-file structure/missing-readme */\ncode();";
    const kept = await run(src, [
      f("structure/missing-readme"),
      f("secret/x", 2),
      f("structure/missing-readme", 2),
    ]);
    expect(kept).toEqual(["secret/x:2"]);
  });

  it("disable-file with no ids suppresses everything in the file, even line-less findings", async () => {
    const src = "# vibesafe-disable-file\nA=1";
    expect(await run(src, [f("secret/x"), f("secret/y", 2)])).toEqual([]);
  });

  it("does not treat a directive inside a string as a directive", async () => {
    const src = [
      'const s = "vibesafe-disable-line";',
      "const t = 'vibesafe-disable-file';",
      "const u = `// vibesafe-disable-next-line`;",
      "const secret = 'x';",
    ].join("\n");
    expect(await run(src, [f("secret/x", 1), f("secret/x", 4)])).toEqual([
      "secret/x:1",
      "secret/x:4",
    ]);
  });

  it("supports JSX and block comments", async () => {
    const src = [
      "<div>",
      "  {/* vibesafe-disable-next-line xss/dangerously-set-inner-html */}",
      "  <p dangerouslySetInnerHTML={x} />",
      "</div>",
    ].join("\n");
    expect(await run(src, [f("xss/dangerously-set-inner-html", 3)])).toEqual([]);
  });

  it("supports prefix wildcards and ignores free-text explanations", async () => {
    const src = "x(); // vibesafe-disable-line secret/* because legacy";
    expect(await run(src, [f("secret/aws", 1), f("auth/z", 1)])).toEqual(["auth/z:1"]);
    const src2 = "x(); // vibesafe-disable-line because legacy";
    expect(await run(src2, [f("auth/z", 1)])).toEqual([]);
  });

  it("keeps findings without a file", async () => {
    expect(await run("// vibesafe-disable-file", [f("a/b", undefined, null)])).toEqual([
      "a/b:none",
    ]);
  });
});
