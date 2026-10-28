import { describe, it, expect } from "vitest";
import { VibeSafeHoverProvider } from "../src/providers/hoverProvider.js";
import { buildCsp, getNonce } from "../src/util/csp.js";
import type { ScanResult } from "@vibesafe/shared";

const evil = "[click](command:workbench.action.terminal.sendSequence) <img src=x onerror=alert(1)>";

const result = {
  projectPath: "/ws/proj",
  findings: [
    {
      id: "F-1",
      ruleId: "r/x",
      title: evil,
      plainEnglishProblem: evil,
      whyItMatters: evil,
      fixSteps: [evil],
      aiFixPrompt: "prompt",
      autoFixAvailable: true,
      file: "src/a.ts",
      line: 1,
    },
  ],
} as unknown as ScanResult;

describe("VibeSafeHoverProvider", () => {
  const provider = new VibeSafeHoverProvider();
  provider.update(result);
  const doc = { uri: { fsPath: "/ws/proj/src/a.ts" } };
  const hover = provider.provideHover(doc as never, { line: 0 } as never, {} as never) as {
    contents: { value: string; isTrusted: unknown; supportHtml: unknown };
  };
  const md = hover.contents;

  it("restricts trusted commands and disables html", () => {
    expect(md.isTrusted).toEqual({
      enabledCommands: ["vibesafe.copyFixPrompt", "vibesafe.applyFix"],
    });
    expect(md.supportHtml).toBe(false);
  });

  it("escapes finding text so it cannot form links or html", () => {
    expect(md.value).not.toMatch(/(^|[^\\])\[click\]/);
    expect(md.value).not.toMatch(/(^|[^\\])</);
  });

  it("command links carry only the finding id", () => {
    expect(md.value).toContain("command:vibesafe.applyFix?" + encodeURIComponent('["F-1"]'));
    expect(md.value).toContain("command:vibesafe.copyFixPrompt?" + encodeURIComponent('["F-1"]'));
  });
});

describe("csp", () => {
  it("builds a nonce-based policy", () => {
    const n = getNonce();
    const csp = buildCsp("vscode-webview:", n);
    expect(csp).toContain(`script-src 'nonce-${n}'`);
    expect(csp).toContain("default-src 'none'");
    expect(buildCsp("x")).toContain("script-src 'none'");
  });
});
