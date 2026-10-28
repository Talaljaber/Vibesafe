import { describe, it, expect, vi } from "vitest";

vi.mock("@vibesafe/core", () => ({
  createDefaultRegistry: () => ({}),
  ScannerPipeline: class {},
}));

import { buildScanOptions } from "../src/commands/scan.js";

describe("buildScanOptions", () => {
  it("passes nothing but rootPath when no flags are set", () => {
    expect(buildScanOptions("/p", {})).toEqual({ rootPath: "/p" });
  });

  it("passes explicit true and false so flags can override the config file", () => {
    expect(buildScanOptions("/p", { deep: true, includeTests: false })).toEqual({
      rootPath: "/p",
      deep: true,
      includeTests: false,
    });
  });

  it("maps --no-config and --trust-config", () => {
    expect(buildScanOptions("/p", { config: false, trustConfig: true })).toEqual({
      rootPath: "/p",
      useConfigFile: false,
      trustConfigScripts: true,
    });
    expect(buildScanOptions("/p", { config: true })).toEqual({ rootPath: "/p" });
  });
});
