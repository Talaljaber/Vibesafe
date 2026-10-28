import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const scanMock = vi.hoisted(() => vi.fn());
const selectMock = vi.hoisted(() => vi.fn());
const previewMock = vi.hoisted(() => vi.fn());
const applyMock = vi.hoisted(() => vi.fn());

vi.mock("@inquirer/prompts", () => ({ select: selectMock, confirm: vi.fn() }));
vi.mock("@vibesafe/core", () => ({
  createDefaultRegistry: () => ({}),
  createDefaultFixRegistry: () => ({
    getFixer: (ruleId: string) => (ruleId === "fixable" ? { preview: previewMock, apply: applyMock } : undefined),
  }),
  ScannerPipeline: class {
    scan = scanMock;
  },
}));

import { runFixWizard } from "../src/commands/fix-wizard.js";

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
    expect(res).toMatchObject({ applied: 1, skipped: 0, failed: 0, scoreBefore: 60, scoreAfter: 80 });
    expect(out).toContain("- old");
    expect(out).toContain("+20");
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
      scanResult([finding("f1", "fixable", true), finding("m1", "manual", false), finding("m2", "manual", false)], 40),
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
    scanMock.mockResolvedValueOnce(scanResult([], 40));
    const res = await runFixWizard(".");
    expect(res).toMatchObject({ applied: 0, failed: 2 });
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
    await runFixWizard(".", { initialResult: scanResult([finding("m1", "manual", false)], 70) as never });
    expect(scanMock).not.toHaveBeenCalled();
  });
});
