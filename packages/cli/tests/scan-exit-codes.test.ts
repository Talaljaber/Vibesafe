import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const scanMock = vi.hoisted(() => vi.fn());

vi.mock("@vibesafe/core", () => ({
  createDefaultRegistry: () => ({}),
  ScannerPipeline: class {
    scan = scanMock;
  },
}));
vi.mock("../src/ui/printer.js", () => ({ printScanResult: vi.fn(async () => {}) }));

import { runScan } from "../src/commands/scan.js";

function fakeResult(deployStatus: string) {
  return { deployStatus, errors: [], findings: [] };
}

describe("runScan exit codes", () => {
  beforeEach(() => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
    process.exitCode = undefined;
  });

  afterEach(() => {
    vi.restoreAllMocks();
    scanMock.mockReset();
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
});
