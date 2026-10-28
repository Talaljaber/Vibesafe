import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { spawnSync } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runFixAll } from "../src/commands/fix-all.js";
import { runWatch, buildWatchScanOptions, type WatchOptions } from "../src/commands/watch.js";

// The .vibesafe.config file must shape fix --all and watch exactly like scan, and
// --no-config (config: false) must switch it off for them too.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(__dirname, "../dist/bin.js");

let base: string;
let proj: string;
const noLog = () => undefined;

async function write(rel: string, content: string) {
  const p = path.join(proj, rel);
  await fs.mkdir(path.dirname(p), { recursive: true });
  await fs.writeFile(p, content);
}
const read = (rel: string) => fs.readFile(path.join(proj, rel), "utf-8");
const writeConfig = (cfg: Record<string, unknown>) =>
  write(".vibesafe.config.json", JSON.stringify(cfg));

beforeEach(async () => {
  base = await fs.mkdtemp(path.join(os.tmpdir(), "vibesafe-cfgcmd-"));
  proj = path.join(base, "project");
  await fs.mkdir(proj);
  // .env not gitignored (secret/env-not-ignored) plus a stray console.log (code_quality/console-log).
  await write("package.json", JSON.stringify({ name: "demo", version: "1.0.0" }));
  await write(".env", "API_KEY=abc\n");
  await write(".gitignore", "node_modules\n");
  await write("src/index.js", 'const a = 1;\nconsole.log("debug", a);\nexport default a;\n');
});

afterEach(async () => {
  process.exitCode = undefined;
  await fs.rm(base, { recursive: true, force: true });
});

describe("buildWatchScanOptions", () => {
  it("leaves includeTests to the config file when the flag is unset and never scans git history", () => {
    expect(buildWatchScanOptions("/p", {})).toEqual({ rootPath: "/p", deep: false });
  });

  it("maps --include-tests / --no-include-tests, --no-config and --trust-config", () => {
    expect(
      buildWatchScanOptions("/p", { includeTests: false, config: false, trustConfig: true }),
    ).toEqual({
      rootPath: "/p",
      deep: false,
      includeTests: false,
      useConfigFile: false,
      trustConfigScripts: true,
    });
    expect(buildWatchScanOptions("/p", { includeTests: true, config: true })).toEqual({
      rootPath: "/p",
      deep: false,
      includeTests: true,
    });
  });
});

describe("fix --all honours the config file", () => {
  it("only offers findings from the configured categories", async () => {
    await writeConfig({ categories: ["secret"] });
    const res = await runFixAll(proj, { yes: true, log: noLog });
    expect(res.status).toBe("applied");
    expect(res.outcomes.map((o) => o.ruleId)).toEqual(["secret/env-not-ignored"]);
    expect(await read(".gitignore")).toContain(".env");
    expect(await read("src/index.js")).toContain('console.log("debug"');
  });

  it("applies rule overrides that switch a rule off", async () => {
    await writeConfig({ rules: { "code_quality/console-log": "off" } });
    const res = await runFixAll(proj, { yes: true, log: noLog });
    expect(res.outcomes.some((o) => o.ruleId === "code_quality/console-log")).toBe(false);
    expect(await read("src/index.js")).toContain('console.log("debug"');
  });

  it("takes includeTests from the config file", async () => {
    await writeConfig({ includeTests: true });
    await write("src/app.test.js", 'const t = 1;\nconsole.log("in test", t);\nexport default t;\n');
    const res = await runFixAll(proj, { yes: true, log: noLog });
    expect(res.outcomes.some((o) => o.file === "src/app.test.js")).toBe(true);
    expect(await read("src/app.test.js")).not.toMatch(/^\s*console\.log/m);
  });

  it("an explicit includeTests: false beats the config file", async () => {
    await writeConfig({ includeTests: true });
    await write("src/app.test.js", 'const t = 1;\nconsole.log("in test", t);\nexport default t;\n');
    await runFixAll(proj, { yes: true, includeTests: false, log: noLog });
    expect(await read("src/app.test.js")).toContain('console.log("in test"');
  });

  it("--no-config ignores the file", async () => {
    await writeConfig({ categories: ["secret"] });
    const res = await runFixAll(proj, { yes: true, config: false, log: noLog });
    const ruleIds = res.outcomes.map((o) => o.ruleId);
    expect(ruleIds).toContain("code_quality/console-log");
    expect(ruleIds).toContain("secret/env-not-ignored");
    expect(await read("src/index.js")).not.toMatch(/^\s*console\.log/m);
  });

  it("logs the applied-config warning so a config cannot hide findings silently", async () => {
    await writeConfig({ categories: ["secret"] });
    const lines: string[] = [];
    await runFixAll(proj, { yes: true, log: (l) => void lines.push(l) });
    expect(lines.join("\n")).toContain("Applied config file .vibesafe.config.json");
  });
});

type Ev = Record<string, unknown> & { type: string };

async function readyEvent(options: Omit<WatchOptions, "json" | "signal" | "write">): Promise<Ev> {
  const events: Ev[] = [];
  const controller = new AbortController();
  const done = runWatch(proj, {
    ...options,
    json: true,
    debounceMs: 50,
    signal: controller.signal,
    write: (line) => events.push(JSON.parse(line) as Ev),
  });
  try {
    const start = Date.now();
    while (Date.now() - start < 20000) {
      const ready = events.find((e) => e.type === "ready" || e.type === "error");
      if (ready) return ready;
      await new Promise((r) => setTimeout(r, 50));
    }
    throw new Error("timed out waiting for the ready event");
  } finally {
    controller.abort();
    await done;
  }
}

const categories = (e: Ev) => (e.findings as Array<{ category: string }>).map((f) => f.category);
const files = (e: Ev) => (e.findings as Array<{ file?: string }>).map((f) => f.file);

describe("watch honours the config file", () => {
  it("applies config categories and reports the config warning in the ready event", async () => {
    await writeConfig({ categories: ["secret"] });
    const ready = await readyEvent({});
    expect(ready.type).toBe("ready");
    expect(categories(ready).length).toBeGreaterThan(0);
    expect(new Set(categories(ready))).toEqual(new Set(["secret"]));
    expect((ready.warnings as string[]).some((w) => w.includes("Applied config file"))).toBe(true);
  }, 30000);

  it("takes includeTests from the config file unless the flag says otherwise", async () => {
    await writeConfig({ includeTests: true });
    await write("src/app.test.js", 'const t = 1;\nconsole.log("in test", t);\nexport default t;\n');
    expect(files(await readyEvent({}))).toContain("src/app.test.js");
    expect(files(await readyEvent({ includeTests: false }))).not.toContain("src/app.test.js");
  }, 60000);

  it("--no-config ignores the file", async () => {
    await writeConfig({ categories: ["secret"] });
    const ready = await readyEvent({ config: false });
    expect(categories(ready)).toContain("code_quality");
    expect(ready.warnings).toEqual([]);
  }, 30000);
});

describe("built binary threads the config flags", () => {
  it("fix --all applies the config, and --no-config switches it off", async () => {
    await writeConfig({ categories: ["secret"] });
    const withConfig = spawnSync(process.execPath, [BIN, "fix", "--all", proj, "--yes"], {
      encoding: "utf-8",
    });
    expect(withConfig.status).toBe(0);
    expect(await read(".gitignore")).toContain(".env");
    expect(await read("src/index.js")).toContain('console.log("debug"');

    const noConfig = spawnSync(
      process.execPath,
      [BIN, "fix", "--all", proj, "--yes", "--no-config"],
      {
        encoding: "utf-8",
      },
    );
    expect(noConfig.status).toBe(0);
    expect(await read("src/index.js")).not.toMatch(/^\s*console\.log/m);
  }, 60000);

  it("fix and watch advertise the config flags", () => {
    for (const cmd of ["fix", "watch"]) {
      const res = spawnSync(process.execPath, [BIN, cmd, "--help"], { encoding: "utf-8" });
      expect(res.stdout).toContain("--no-config");
      expect(res.stdout).toContain("--trust-config");
    }
    const watchHelp = spawnSync(process.execPath, [BIN, "watch", "--help"], {
      encoding: "utf-8",
    }).stdout;
    expect(watchHelp).toContain("--no-include-tests");
  }, 30000);
});

describe("scan output from config-supplied strings", () => {
  it("strips terminal control sequences from config warnings in text mode", async () => {
    await writeConfig({ disabledDetectors: ["]0;pwnedevil[31m-detector"] });
    const res = spawnSync(process.execPath, [BIN, "scan", proj], {
      encoding: "utf-8",
      maxBuffer: 64 * 1024 * 1024,
    });
    const out = res.stdout + res.stderr;
    expect(out).toContain("evil");
    expect(out).not.toContain("]0;pwned");
    expect(out).not.toContain("[31m-detector");
  }, 30000);
});
