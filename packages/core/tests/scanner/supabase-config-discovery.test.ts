import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { classifyInfraFile } from "@talaljaber/vibesafe-shared";
import { FileDiscovery } from "../../src/scanner/file-discovery.js";
import { classifyPath } from "../../src/detectors/utils/file-kind.js";

describe("supabase/config.toml classification", () => {
  it("matches only the CLI path", () => {
    for (const p of [
      "supabase/config.toml",
      "apps/web/supabase/config.toml",
      "supabase\\config.toml",
    ]) {
      expect(classifyInfraFile(p), p).toBe("supabase-config");
      expect(classifyPath(p), p).toBe("supabase-config");
    }
    for (const p of [
      "config.toml",
      "supabase/other.toml",
      "pyproject.toml",
      "supabase/config.toml.bak",
      "Supabase/config.toml",
      "notsupabase/config.toml",
    ]) {
      expect(classifyInfraFile(p), p).toBeNull();
    }
  });
});

describe("discovery of supabase/config.toml", () => {
  let root: string;
  beforeAll(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), "vibesafe-sbcfg-"));
    for (const f of ["supabase/config.toml", "config.toml", "other/settings.toml"]) {
      const full = path.join(root, f);
      await fs.mkdir(path.dirname(full), { recursive: true });
      await fs.writeFile(full, "[auth]\n");
    }
  });
  afterAll(async () => {
    await fs.rm(root, { recursive: true, force: true });
  });

  it("returns supabase/config.toml and not other toml files", async () => {
    const found = (await new FileDiscovery(root).discoverFiles()).map((f) => f.replace(/\\/g, "/"));
    expect(found).toContain("supabase/config.toml");
    expect(found).not.toContain("config.toml");
    expect(found).not.toContain("other/settings.toml");
  });
});
