import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const scanMock = vi.hoisted(() => vi.fn());
const selectMock = vi.hoisted(() => vi.fn());
const previewMock = vi.hoisted(() => vi.fn());
const applyMock = vi.hoisted(() => vi.fn());

vi.mock("@inquirer/prompts", () => ({ select: selectMock, confirm: vi.fn() }));
vi.mock("@vibesafe/core", () => ({
  createDefaultRegistry: () => ({}),
  createDefaultFixRegistry: () => ({
    getFixer: (ruleId: string) =>
      ruleId === "fixable" ? { preview: previewMock, apply: applyMock } : undefined,
  }),
  ScannerPipeline: class {
    scan = scanMock;
  },
}));

import { runFixWizard } from "../src/commands/fix-wizard.js";
import { sanitizeTerminal } from "../src/ui/sanitize.js";

function finding(id: string, ruleId: string, autoFix: boolean) {
  return {
    id,
    ruleId,
    title: `Title ${id}`,
    severity: "high",
    file: "a.ts",
    line: 3,
    whyItMatters: `Why ${id}`,
    fixSteps: [`Step for ${id}`],
    aiFixPrompt: `Prompt for ${id}`,
    autoFixAvailable: autoFix,
  };
}

function scanResult(findings: ReturnType<typeof finding>[], score: number) {
  return {
    score,
    findings,
    repairPlan: { steps: findings.map((f, i) => ({ order: i + 1, findingId: f.id })) },
  };
}

describe("runFixWizard", () => {
  let out: string;
  const origTty = process.stdin.isTTY;

  beforeEach(() => {
    out = "";
    const capture = (...a: unknown[]) => {
      out += a.join(" ") + "\n";
    };
    vi.spyOn(console, "log").mockImplementation(capture);
    vi.spyOn(console, "error").mockImplementation(capture);
    process.stdin.isTTY = true;
    process.exitCode = undefined;
    previewMock.mockResolvedValue({
      description: "Do the thing",
      filesToModify: ["a.ts"],
      filesToCreate: [],
      diff: "- old\n+ new",
    });
    applyMock.mockResolvedValue({ success: true, message: "applied ok" });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    scanMock.mockReset();
    selectMock.mockReset();
    previewMock.mockReset();
    applyMock.mockReset();
    process.stdin.isTTY = origTty;
    process.exitCode = undefined;
  });

  it("errors clearly without a TTY and never scans", async () => {
    process.stdin.isTTY = false;
    const res = await runFixWizard(".");
    expect(res).toBeUndefined();
    expect(process.exitCode).toBe(1);
    expect(out).toContain("interactive terminal");
    expect(scanMock).not.toHaveBeenCalled();
  });

  it("reports nothing to fix when there are no findings", async () => {
    scanMock.mockResolvedValue(scanResult([], 100));
    const res = await runFixWizard(".");
    expect(res?.applied).toBe(0);
    expect(selectMock).not.toHaveBeenCalled();
    expect(out).toContain("Nothing to fix");
  });

  it("applies an auto-fixable finding, rescans and shows the score delta", async () => {
    scanMock
      .mockResolvedValueOnce(scanResult([finding("f1", "fixable", true)], 60))
      .mockResolvedValueOnce(scanResult([], 80));
    selectMock.mockResolvedValueOnce("apply");
    const res = await runFixWizard(".");
    expect(applyMock).toHaveBeenCalledTimes(1);
    expect(res).toMatchObject({
      applied: 1,
      skipped: 0,
      failed: 0,
      scoreBefore: 60,
      scoreAfter: 80,
    });
    expect(out).toContain("- old");
    expect(out).toContain("+20");
  });

  it("leaves deep/includeTests unset so the config file applies, for the scan and the rescan", async () => {
    scanMock
      .mockResolvedValueOnce({
        ...scanResult([finding("f1", "fixable", true)], 60),
        warnings: ["Applied config file x"],
      })
      .mockResolvedValueOnce(scanResult([], 80));
    selectMock.mockResolvedValueOnce("apply");
    await runFixWizard(".");
    expect(scanMock).toHaveBeenCalledTimes(2);
    for (const [opts] of scanMock.mock.calls) {
      expect(opts).not.toHaveProperty("deep");
      expect(opts).not.toHaveProperty("includeTests");
      expect(opts).not.toHaveProperty("useConfigFile");
    }
    expect(out).toContain("Applied config file x");
  });

  it("threads --no-config, --trust-config and explicit flags into both scans", async () => {
    scanMock
      .mockResolvedValueOnce(scanResult([finding("f1", "fixable", true)], 60))
      .mockResolvedValueOnce(scanResult([], 80));
    selectMock.mockResolvedValueOnce("apply");
    await runFixWizard(".", { config: false, trustConfig: true, includeTests: true, deep: false });
    expect(scanMock).toHaveBeenCalledTimes(2);
    for (const [opts] of scanMock.mock.calls) {
      expect(opts).toMatchObject({
        useConfigFile: false,
        trustConfigScripts: true,
        includeTests: true,
        deep: false,
      });
    }
  });

  it("uses the scan -i flags for the rescan after reusing the initial result", async () => {
    scanMock.mockResolvedValueOnce(scanResult([], 90));
    selectMock.mockResolvedValueOnce("apply");
    await runFixWizard(".", {
      initialResult: scanResult([finding("f1", "fixable", true)], 70) as never,
      config: false,
    });
    expect(scanMock).toHaveBeenCalledTimes(1);
    expect(scanMock.mock.calls[0]?.[0]).toMatchObject({ useConfigFile: false });
  });

  it("skip does not apply and does not rescan", async () => {
    scanMock.mockResolvedValueOnce(scanResult([finding("f1", "fixable", true)], 60));
    selectMock.mockResolvedValueOnce("skip");
    const res = await runFixWizard(".");
    expect(applyMock).not.toHaveBeenCalled();
    expect(scanMock).toHaveBeenCalledTimes(1);
    expect(res).toMatchObject({ applied: 0, skipped: 1, scoreAfter: 60 });
  });

  it("shows fix steps and AI prompt for manual findings and offers no Apply", async () => {
    scanMock.mockResolvedValueOnce(scanResult([finding("m1", "manual", false)], 50));
    selectMock.mockResolvedValueOnce("skip");
    await runFixWizard(".");
    expect(out).toContain("Step for m1");
    expect(out).toContain("Prompt for m1");
    expect(out).toContain("Why m1");
    expect(out).toContain("a.ts:3");
    const choices = selectMock.mock.calls[0]![0].choices.map((c: { value: string }) => c.value);
    expect(choices).toEqual(["skip", "quit"]);
    expect(previewMock).not.toHaveBeenCalled();
  });

  it("quit stops the walk and counts the rest as not reviewed", async () => {
    scanMock.mockResolvedValueOnce(
      scanResult(
        [
          finding("f1", "fixable", true),
          finding("m1", "manual", false),
          finding("m2", "manual", false),
        ],
        40,
      ),
    );
    selectMock.mockResolvedValueOnce("quit");
    const res = await runFixWizard(".");
    expect(res?.quit).toBe(true);
    expect(selectMock).toHaveBeenCalledTimes(1);
    expect(applyMock).not.toHaveBeenCalled();
    expect(out).toContain("Not reviewed: 3");
  });

  it("treats Ctrl+C (ExitPromptError) as quit", async () => {
    scanMock.mockResolvedValueOnce(scanResult([finding("f1", "fixable", true)], 40));
    const err = new Error("closed");
    err.name = "ExitPromptError";
    selectMock.mockRejectedValueOnce(err);
    const res = await runFixWizard(".");
    expect(res?.quit).toBe(true);
    expect(applyMock).not.toHaveBeenCalled();
  });

  it("rethrows unexpected prompt errors", async () => {
    scanMock.mockResolvedValueOnce(scanResult([finding("f1", "fixable", true)], 40));
    selectMock.mockRejectedValueOnce(new Error("boom"));
    await expect(runFixWizard(".")).rejects.toThrow("boom");
  });

  it("counts a failed apply and keeps going", async () => {
    scanMock.mockResolvedValueOnce(
      scanResult([finding("f1", "fixable", true), finding("f2", "fixable", true)], 40),
    );
    applyMock
      .mockResolvedValueOnce({ success: false, message: "nope" })
      .mockRejectedValueOnce(new Error("exploded"));
    selectMock.mockResolvedValue("apply");
    const res = await runFixWizard(".");
    expect(res).toMatchObject({ applied: 0, failed: 2 });
    expect(applyMock).toHaveBeenCalledTimes(2);
    expect(previewMock).toHaveBeenCalledTimes(2);
    expect(out).toContain("nope");
    expect(out).toContain("exploded");
    expect(scanMock).toHaveBeenCalledTimes(1);
  });

  it("falls back to manual guidance when the preview throws", async () => {
    scanMock.mockResolvedValueOnce(scanResult([finding("f1", "fixable", true)], 40));
    previewMock.mockRejectedValueOnce(new Error("bad path"));
    selectMock.mockResolvedValueOnce("skip");
    await runFixWizard(".");
    expect(out).toContain("Could not preview");
    expect(out).toContain("Step for f1");
    const choices = selectMock.mock.calls[0]![0].choices.map((c: { value: string }) => c.value);
    expect(choices).not.toContain("apply");
  });

  it("reuses an initial scan result instead of scanning again", async () => {
    selectMock.mockResolvedValueOnce("skip");
    await runFixWizard(".", {
      initialResult: scanResult([finding("m1", "manual", false)], 70) as never,
    });
    expect(scanMock).not.toHaveBeenCalled();
  });

  it("treats an empty preview as not applicable and shows manual guidance", async () => {
    scanMock.mockResolvedValueOnce(scanResult([finding("f1", "fixable", true)], 40));
    previewMock.mockResolvedValueOnce({
      description: "Line 3 no longer contains a standalone console.log( statement",
      filesToModify: [],
      filesToCreate: [],
    });
    selectMock.mockResolvedValueOnce("skip");
    await runFixWizard(".");
    expect(out).toContain("no longer contains a standalone");
    expect(out).toContain("Step for f1");
    expect(out).toContain("Prompt for f1");
    const choices = selectMock.mock.calls[0]![0].choices.map((c: { value: string }) => c.value);
    expect(choices).toEqual(["skip", "quit"]);
    expect(applyMock).not.toHaveBeenCalled();
  });

  it("strips terminal escape sequences and carriage returns from untrusted text", async () => {
    scanMock.mockResolvedValueOnce(scanResult([finding("f1", "fixable", true)], 40));
    previewMock.mockResolvedValueOnce({
      description: "desc\x1b]0;evil\x07",
      filesToModify: ["a\x1b[2K.ts"],
      filesToCreate: [],
      diff: "- console.log('x')\x1b[2K\r\x1b[1A\n+ safe",
    });
    selectMock.mockResolvedValueOnce("skip");
    await runFixWizard(".");
    expect(out).not.toContain("\x1b[2K");
    expect(out).not.toContain("\x1b[1A");
    expect(out).not.toContain("\x1b]0;");
    expect(out).not.toContain("\r");
    expect(out).toContain("console.log('x')");
  });

  it("sanitizeTerminal keeps newlines and tabs", () => {
    expect(sanitizeTerminal("a\tb\nc\r\x00\x7f\x9bd")).toBe("a\tb\ncd");
  });

  it("walks steps in repairPlan order regardless of finding order", async () => {
    const f1 = finding("f1", "manual", false);
    const f2 = finding("f2", "manual", false);
    const f3 = finding("f3", "manual", false);
    scanMock.mockResolvedValueOnce({
      score: 10,
      findings: [f1, f2, f3],
      repairPlan: {
        steps: [
          { order: 1, findingId: "f3" },
          { order: 2, findingId: "ghost" },
          { order: 3, findingId: "f1" },
          { order: 4, findingId: "f2" },
        ],
      },
    });
    selectMock.mockResolvedValue("skip");
    const res = await runFixWizard(".");
    expect(res?.skipped).toBe(3);
    expect(out.indexOf("Title f3")).toBeLessThan(out.indexOf("Title f1"));
    expect(out.indexOf("Title f1")).toBeLessThan(out.indexOf("Title f2"));
    expect(out).toContain("[1/3]");
  });

  it("mixes apply and skip then quits with correct counts", async () => {
    scanMock
      .mockResolvedValueOnce(
        scanResult(
          [
            finding("f1", "fixable", true),
            finding("f2", "fixable", true),
            finding("f3", "manual", false),
            finding("f4", "manual", false),
          ],
          50,
        ),
      )
      .mockResolvedValueOnce(scanResult([], 70));
    selectMock
      .mockResolvedValueOnce("apply")
      .mockResolvedValueOnce("skip")
      .mockResolvedValueOnce("quit");
    const res = await runFixWizard(".");
    expect(res).toMatchObject({ applied: 1, skipped: 1, failed: 0, quit: true, scoreAfter: 70 });
    expect(out).toContain("Not reviewed: 2");
  });
});
