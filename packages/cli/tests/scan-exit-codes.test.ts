import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const scanMock = vi.hoisted(() => vi.fn());
const confirmMock = vi.hoisted(() => vi.fn());
const wizardMock = vi.hoisted(() => vi.fn());

vi.mock("@vibesafe/core", () => ({
  createDefaultRegistry: () => ({}),
  ScannerPipeline: class {
    scan = scanMock;
  },
}));
vi.mock("@inquirer/prompts", () => ({ confirm: confirmMock }));
vi.mock("../src/commands/fix-wizard.js", () => ({ runFixWizard: wizardMock }));
vi.mock("../src/ui/printer.js", () => ({ printScanResult: vi.fn(async () => {}) }));

import { runScan } from "../src/commands/scan.js";

function fakeResult(deployStatus: string) {
  return { deployStatus, errors: [], findings: [] };
}

const origTty = process.stdin.isTTY;

describe("runScan exit codes", () => {
  beforeEach(() => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
    process.exitCode = undefined;
  });

  afterEach(() => {
    vi.restoreAllMocks();
    scanMock.mockReset();
    confirmMock.mockReset();
    wizardMock.mockReset();
    process.stdin.isTTY = origTty;
    process.exitCode = undefined;
  });

  it.each([
    ["blocker", 1],
    ["danger", 1],
    ["warning", 0],
    ["safe", 0],
  ])("deploy status %s exits %i", async (status, code) => {
    scanMock.mockResolvedValue(fakeResult(status));
    await runScan(".", {});
    expect(process.exitCode).toBe(code);
  });

  it("exits 2 when the scan throws", async () => {
    scanMock.mockRejectedValue(new Error("boom"));
    await runScan(".", { json: true });
    expect(process.exitCode).toBe(2);
  });

  it("does not pass an onProgress callback in --json mode", async () => {
    scanMock.mockResolvedValue(fakeResult("safe"));
    await runScan(".", { json: true });
    expect(scanMock.mock.calls[0]?.[1]).toBeUndefined();
  });

  describe("interactive mode", () => {
    const withFindings = (status: string) => ({
      deployStatus: status,
      errors: [],
      findings: [{ id: "f1" }],
    });

    it("runs the wizard with the scan result and preserves the CI exit code", async () => {
      process.stdin.isTTY = true;
      const result = withFindings("blocker");
      scanMock.mockResolvedValue(result);
      confirmMock.mockResolvedValue(true);
      wizardMock.mockImplementation(async () => {
        process.exitCode = 0;
      });
      await runScan(".", { interactive: true });
      expect(wizardMock).toHaveBeenCalledTimes(1);
      expect(wizardMock.mock.calls[0]?.[1]).toMatchObject({ initialResult: result });
      expect(scanMock).toHaveBeenCalledTimes(1);
      expect(process.exitCode).toBe(1);
    });

    it("keeps the CI exit code and reports a wizard-specific error when the wizard throws", async () => {
      process.stdin.isTTY = true;
      scanMock.mockResolvedValue(withFindings("blocker"));
      confirmMock.mockResolvedValue(true);
      wizardMock.mockRejectedValue(new Error("prompt broke"));
      const errSpy = vi.spyOn(console, "error");
      await runScan(".", { interactive: true });
      expect(process.exitCode).toBe(1);
      const printed = errSpy.mock.calls.map((c) => c.join(" ")).join("\n");
      expect(printed).toContain("Error during fix wizard");
      expect(printed).not.toContain("Error during scan");
    });

    it("skips the wizard when the user declines", async () => {
      process.stdin.isTTY = true;
      scanMock.mockResolvedValue(withFindings("blocker"));
      confirmMock.mockResolvedValue(false);
      await runScan(".", { interactive: true });
      expect(confirmMock).toHaveBeenCalledTimes(1);
      expect(wizardMock).not.toHaveBeenCalled();
      expect(process.exitCode).toBe(1);
    });

    it("treats Ctrl+C at the prompt as declining", async () => {
      process.stdin.isTTY = true;
      scanMock.mockResolvedValue(withFindings("safe"));
      const err = new Error("closed");
      err.name = "ExitPromptError";
      confirmMock.mockRejectedValue(err);
      await runScan(".", { interactive: true });
      expect(wizardMock).not.toHaveBeenCalled();
      expect(process.exitCode).toBe(0);
    });

    it("never prompts with --json", async () => {
      process.stdin.isTTY = true;
      scanMock.mockResolvedValue(withFindings("blocker"));
      await runScan(".", { interactive: true, json: true });
      expect(confirmMock).not.toHaveBeenCalled();
      expect(wizardMock).not.toHaveBeenCalled();
    });

    it("never prompts without a TTY", async () => {
      process.stdin.isTTY = false;
      scanMock.mockResolvedValue(withFindings("blocker"));
      await runScan(".", { interactive: true });
      expect(confirmMock).not.toHaveBeenCalled();
      expect(wizardMock).not.toHaveBeenCalled();
    });

    it("never prompts when there are no findings", async () => {
      process.stdin.isTTY = true;
      scanMock.mockResolvedValue(fakeResult("safe"));
      await runScan(".", { interactive: true });
      expect(confirmMock).not.toHaveBeenCalled();
    });

    it("never prompts without --interactive", async () => {
      process.stdin.isTTY = true;
      scanMock.mockResolvedValue(withFindings("blocker"));
      await runScan(".", {});
      expect(confirmMock).not.toHaveBeenCalled();
    });
  });
});
