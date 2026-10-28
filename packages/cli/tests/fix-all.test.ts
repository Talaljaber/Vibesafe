import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { spawnSync } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runFixAll } from "../src/commands/fix-all.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(__dirname, "../dist/bin.js");

let base: string;
let proj: string;
let lines: string[];
const log = (l: string) => void lines.push(l);

async function write(rel: string, content: string) {
  const p = path.join(proj, rel);
  await fs.mkdir(path.dirname(p), { recursive: true });
  await fs.writeFile(p, content);
}
const read = (rel: string) => fs.readFile(path.join(proj, rel), "utf-8");

beforeEach(async () => {
  base = await fs.mkdtemp(path.join(os.tmpdir(), "vibesafe-fixall-"));
  proj = path.join(base, "project");
  await fs.mkdir(proj);
  lines = [];
  // A small project: .env present but not ignored, plus a stray console.log.
  await write("package.json", JSON.stringify({ name: "demo", version: "1.0.0" }));
  await write(".env", "API_KEY=abc\n");
  await write(".gitignore", "node_modules\n");
  await write("src/index.js", 'const a = 1;\nconsole.log("debug", a);\nexport default a;\n');
});

afterEach(async () => {
  await fs.rm(base, { recursive: true, force: true });
});

describe("runFixAll", () => {
  it("applies every fixable finding after one confirmation and reports scores", async () => {
    let asked = 0;
    const res = await runFixAll(proj, {
      interactive: true,
      log,
      confirm: async () => {
        asked++;
        return true;
      },
    });
    expect(asked).toBe(1);
    expect(res.status).toBe("applied");
    expect(res.candidates).toBeGreaterThan(0);
    expect(res.failed).toBe(0);
    expect(res.succeeded).toBe(res.candidates);
    expect(res.scoreAfter).toBeGreaterThanOrEqual(res.scoreBefore);
    expect(await read(".gitignore")).toContain(".env");
    expect(await read("src/index.js")).not.toMatch(/^\s*console\.log/m);
    expect(lines.join("\n")).toMatch(/Score: \d+ -> \d+/);
  });

  it("--yes skips the prompt even without a TTY", async () => {
    const res = await runFixAll(proj, {
      yes: true,
      interactive: false,
      log,
      confirm: async () => {
        throw new Error("must not prompt");
      },
    });
    expect(res.status).toBe("applied");
    expect(await read(".gitignore")).toContain(".env");
  });

  it("without --yes and no TTY it refuses and changes nothing", async () => {
    const res = await runFixAll(proj, { interactive: false, log });
    expect(res.status).toBe("no-tty");
    expect(res.outcomes).toEqual([]);
    expect(await read(".gitignore")).toBe("node_modules\n");
    expect(lines.join("\n")).toContain("--yes");
  });

  it("declining the confirmation changes nothing", async () => {
    const res = await runFixAll(proj, { interactive: true, log, confirm: async () => false });
    expect(res.status).toBe("cancelled");
    expect(res.scoreAfter).toBe(res.scoreBefore);
    expect(await read(".gitignore")).toBe("node_modules\n");
    expect(await read("src/index.js")).toContain('console.log("debug"');
  });

  it("an aborted prompt (Ctrl+C) counts as a cancel", async () => {
    const res = await runFixAll(proj, {
      interactive: true,
      log,
      confirm: async () => {
        const e = new Error("aborted");
        e.name = "ExitPromptError";
        throw e;
      },
    });
    expect(res.status).toBe("cancelled");
  });

  it("reports nothing to fix on a clean project and never prompts", async () => {
    await write(".gitignore", "node_modules\n.env\n.env.*\n!.env.example\n");
    await write("src/index.js", "export default 1;\n");
    await fs.rm(path.join(proj, ".env"));
    const res = await runFixAll(proj, {
      interactive: true,
      log,
      confirm: async () => {
        throw new Error("must not prompt");
      },
    });
    expect(res.status).toBe("nothing-to-fix");
    expect(res.candidates).toBe(0);
  });

  it("is idempotent: a second run has nothing to fix", async () => {
    await runFixAll(proj, { yes: true, log });
    const second = await runFixAll(proj, { yes: true, log });
    expect(second.status).toBe("nothing-to-fix");
  });
});

describe("vibesafe fix --all (built binary)", () => {
  it("exits 1 with a clear message without --yes and no TTY, leaving files untouched", async () => {
    const res = spawnSync(process.execPath, [BIN, "fix", "--all", proj], { encoding: "utf-8", input: "" });
    expect(res.status).toBe(1);
    expect(res.stdout).toContain("--yes");
    expect(await read(".gitignore")).toBe("node_modules\n");
  }, 30000);

  it("--yes applies the fixes and exits 0", async () => {
    const res = spawnSync(process.execPath, [BIN, "fix", "--all", proj, "--yes"], { encoding: "utf-8" });
    expect(res.status).toBe(0);
    expect(res.stdout).toMatch(/Score: \d+ -> \d+/);
    expect(await read(".gitignore")).toContain(".env");
  }, 30000);

  it("fix without a finding id or --all errors", () => {
    const res = spawnSync(process.execPath, [BIN, "fix"], { encoding: "utf-8" });
    expect(res.status).toBe(1);
  }, 30000);
});
