import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { ConsoleLogFixer } from "@talaljaber/vibesafe-core";
import { spawnSync } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runFixAll, runFixAllCommand } from "../src/commands/fix-all.js";
import { sanitizeTerminal } from "../src/ui/sanitize.js";

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
  vi.restoreAllMocks();
  process.exitCode = undefined;
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

  it("skips findings whose fixer cannot change anything and does not count them as failures", async () => {
    await write(
      "src/index.js",
      'const a = 1;\nif (a) console.log(a);\nconst f = () => console.log(a);\nconsole.log("ok");\n',
    );
    const res = await runFixAll(proj, { yes: true, log });
    expect(res.failed).toBe(0);
    expect(res.skipped).toBe(2);
    expect(res.candidates).toBe(res.succeeded);
    expect(lines.join("\n")).toContain("Skipped (not auto-fixable): 2");
    expect(await read("src/index.js")).toContain("if (a) console.log(a);");
    // Re-running stays clean: skips are not failures.
    const again = await runFixAll(proj, { yes: true, log });
    expect(again.failed).toBe(0);
  });

  it("prompts with the filtered count only", async () => {
    await write("src/index.js", "const a = 1;\nif (a) console.log(a);\n");
    let prompt = "";
    const res = await runFixAll(proj, {
      interactive: true,
      log,
      confirm: async (m) => {
        prompt = m;
        return false;
      },
    });
    expect(prompt).toBe(`Apply all ${res.candidates} fixes?`);
    expect(res.skipped).toBe(1);
  });

  it("strips terminal escape sequences from repo content before printing", async () => {
    await write("src/index.js", 'const a = 1;\nconsole.log("\u001b[2K\u001b[1A\rspoofed", a);\n');
    await runFixAll(proj, { interactive: true, log, confirm: async () => false });
    const out = lines.join("\n");
    expect(out).not.toContain("\u001b[2K");
    expect(out).not.toContain("\u001b[1A");
    expect(out).not.toContain("\r");
    expect(out).toContain("spoofed");
    expect(sanitizeTerminal("a\u001b[31mb\u001b]0;title\u0007c\u009bd\te\nf")).toBe("abcd\te\nf");
    expect(sanitizeTerminal("It\u2019s\u2026 \u20ac5 \u00a92026 \u2122 \u00a0x")).toBe(
      "It\u2019s\u2026 \u20ac5 \u00a92026 \u2122 \u00a0x",
    );
    expect(sanitizeTerminal("a\u2028b\u2029c")).toBe("abc");
  });

  it("a failing or throwing fix does not stop the rest, and is counted as failed", async () => {
    await write(
      "src/index.js",
      'const a = 1;\nconsole.log("one");\nconst b = 2;\nconsole.log("two");\nexport { a, b };\n',
    );
    const real = ConsoleLogFixer.prototype.apply;
    let calls = 0;
    vi.spyOn(ConsoleLogFixer.prototype, "apply").mockImplementation(async function (
      this: ConsoleLogFixer,
      ...args
    ) {
      if (++calls === 1) throw new Error("boom");
      return real.apply(this, args);
    });
    const res = await runFixAll(proj, { yes: true, log });
    expect(res.failed).toBe(1);
    expect(res.succeeded).toBe(res.candidates - 1);
    expect(res.outcomes.find((o) => !o.success)?.message).toBe("boom");
    expect(lines.join("\n")).toContain("FAIL");
    expect(await read(".gitignore")).toContain(".env");
    expect(await read("src/index.js")).toContain("// console.log");
  });
});

describe("runFixAllCommand exit codes", () => {
  it("sets exitCode 1 when a fix fails", async () => {
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    vi.spyOn(ConsoleLogFixer.prototype, "apply").mockResolvedValue({
      success: false,
      filesModified: [],
      filesCreated: [],
      message: "nope",
    });
    const res = await runFixAllCommand(proj, { yes: true });
    expect(res.failed).toBeGreaterThan(0);
    expect(process.exitCode).toBe(1);
  });

  it("sets exitCode 1 for no-tty without --yes", async () => {
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    const tty = Object.getOwnPropertyDescriptor(process.stdin, "isTTY");
    Object.defineProperty(process.stdin, "isTTY", { value: false, configurable: true });
    try {
      const res = await runFixAllCommand(proj, {});
      expect(res.status).toBe("no-tty");
      expect(process.exitCode).toBe(1);
    } finally {
      if (tty) Object.defineProperty(process.stdin, "isTTY", tty);
      else delete (process.stdin as { isTTY?: boolean }).isTTY;
    }
  });

  it("leaves exitCode unset on success", async () => {
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    const res = await runFixAllCommand(proj, { yes: true });
    expect(res.failed).toBe(0);
    expect(process.exitCode).toBeUndefined();
  });
});

describe("runFixAll idempotence", () => {
  it("is idempotent: a second run has nothing to fix", async () => {
    await runFixAll(proj, { yes: true, log });
    const second = await runFixAll(proj, { yes: true, log });
    expect(second.status).toBe("nothing-to-fix");
  });
});

describe("vibesafe fix --all (built binary)", () => {
  it("exits 1 with a clear message without --yes and no TTY, leaving files untouched", async () => {
    const res = spawnSync(process.execPath, [BIN, "fix", "--all", proj], {
      encoding: "utf-8",
      input: "",
    });
    expect(res.status).toBe(1);
    expect(res.stdout).toContain("--yes");
    expect(await read(".gitignore")).toBe("node_modules\n");
  }, 30000);

  it("--yes applies the fixes and exits 0", async () => {
    const res = spawnSync(process.execPath, [BIN, "fix", "--all", proj, "--yes"], {
      encoding: "utf-8",
    });
    expect(res.status).toBe(0);
    expect(res.stdout).toMatch(/Score: \d+ -> \d+/);
    expect(await read(".gitignore")).toContain(".env");
  }, 30000);

  it("fix without a finding id or --all errors", () => {
    const res = spawnSync(process.execPath, [BIN, "fix"], { encoding: "utf-8" });
    expect(res.status).toBe(1);
    expect(res.stderr).toContain("missing required argument");
  }, 30000);

  it("rejects a finding id combined with --all", () => {
    const res = spawnSync(process.execPath, [BIN, "fix", "some-id", proj, "--all", "--yes"], {
      encoding: "utf-8",
    });
    expect(res.status).toBe(1);
    expect(res.stderr).toContain("--all takes no finding id");
  }, 30000);
});
