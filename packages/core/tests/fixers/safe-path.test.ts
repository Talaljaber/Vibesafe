import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { resolveInsideRoot } from "../../src/fixers/safe-path";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

describe("resolveInsideRoot", () => {
  let tempDir: string;
  let outside: string;

  beforeEach(async () => {
    const base = await fs.mkdtemp(path.join(os.tmpdir(), "vibesafe-safe-"));
    tempDir = path.join(base, "project");
    outside = path.join(base, "outside");
    await fs.mkdir(tempDir);
    await fs.mkdir(outside);
  });

  afterEach(async () => {
    await fs.rm(path.dirname(tempDir), { recursive: true, force: true });
  });

  it("accepts files inside the root, existing or not", async () => {
    await fs.writeFile(path.join(tempDir, "a.js"), "x");
    await expect(resolveInsideRoot(tempDir, "a.js")).resolves.toBe(path.join(tempDir, "a.js"));
    await expect(resolveInsideRoot(tempDir, "new.js")).resolves.toBe(path.join(tempDir, "new.js"));
  });

  it("rejects traversal and absolute paths", async () => {
    await expect(resolveInsideRoot(tempDir, "../outside/x.js")).rejects.toThrow();
    await expect(resolveInsideRoot(tempDir, "../../x.js")).rejects.toThrow();
    await expect(resolveInsideRoot(tempDir, path.join(outside, "x.js"))).rejects.toThrow();
    await expect(resolveInsideRoot(tempDir, "")).rejects.toThrow();
  });

  it("rejects symlinked files and directories", async (ctx) => {
    await fs.writeFile(path.join(outside, "secret.js"), "x");
    try {
      await fs.symlink(path.join(outside, "secret.js"), path.join(tempDir, "link.js"), "file");
      await fs.symlink(outside, path.join(tempDir, "linkdir"), "junction");
    } catch {
      ctx.skip();
      return;
    }
    await expect(resolveInsideRoot(tempDir, "link.js")).rejects.toThrow();
    await expect(resolveInsideRoot(tempDir, "linkdir/secret.js")).rejects.toThrow();
    await expect(resolveInsideRoot(tempDir, "linkdir/new.js")).rejects.toThrow();
  });
});
