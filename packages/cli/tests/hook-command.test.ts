import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { spawnSync } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  CLAUDE_HOOK_COMMAND,
  claudeHookSnippet,
  mergeClaudeHook,
  runHookClaude,
  HookSettingsError,
} from "../src/commands/hook.js";
import { buildScanOptions } from "../src/commands/scan-options.js";
import { buildWatchScanOptions } from "../src/commands/watch.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(__dirname, "../dist/bin.js");

describe("claudeHookSnippet / mergeClaudeHook", () => {
  it("is a PostToolUse command hook on edit tools that turns a failing scan into feedback", () => {
    const snippet = claudeHookSnippet();
    const entry = snippet.hooks.PostToolUse[0]!;
    expect(entry.matcher).toBe("Edit|MultiEdit|Write");
    expect(entry.hooks[0]!.type).toBe("command");
    expect(entry.hooks[0]!.command).toBe(CLAUDE_HOOK_COMMAND);
    expect(CLAUDE_HOOK_COMMAND).toContain("vibesafe scan");
    expect(CLAUDE_HOOK_COMMAND).toContain("|| exit 2");
    expect(CLAUDE_HOOK_COMMAND).not.toContain("--online");
  });

  it("matches the shipped example", async () => {
    const example = JSON.parse(
      await fs.readFile(
        path.resolve(__dirname, "../../../examples/claude-code/settings.json"),
        "utf-8",
      ),
    );
    expect(example).toEqual(claudeHookSnippet());
  });

  it("adds the hook to empty settings", () => {
    const { settings, changed } = mergeClaudeHook({});
    expect(changed).toBe(true);
    expect(settings).toEqual(claudeHookSnippet());
  });

  it("keeps every existing setting and hook", () => {
    const existing = {
      permissions: { allow: ["Bash(npm test)"] },
      hooks: {
        PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "echo pre" }] }],
        PostToolUse: [{ matcher: "Write", hooks: [{ type: "command", command: "prettier -w" }] }],
      },
    };
    const { settings, changed } = mergeClaudeHook(structuredClone(existing));
    expect(changed).toBe(true);
    expect(settings.permissions).toEqual(existing.permissions);
    const hooks = settings.hooks as Record<string, unknown[]>;
    expect(hooks.PreToolUse).toEqual(existing.hooks.PreToolUse);
    expect(hooks.PostToolUse).toHaveLength(2);
    expect(hooks.PostToolUse![0]).toEqual(existing.hooks.PostToolUse[0]);
  });

  it("is idempotent, also for a hand-written vibesafe scan hook", () => {
    const once = mergeClaudeHook({}).settings;
    expect(mergeClaudeHook(once)).toEqual({ settings: once, changed: false });
    const custom = {
      hooks: {
        PostToolUse: [
          { matcher: "Edit", hooks: [{ type: "command", command: "pnpm vibesafe scan . --json" }] },
        ],
      },
    };
    expect(mergeClaudeHook(custom).changed).toBe(false);
  });

  it("refuses shapes it cannot merge without losing data", () => {
    expect(() => mergeClaudeHook([])).toThrow(HookSettingsError);
    expect(() => mergeClaudeHook("x")).toThrow(HookSettingsError);
    expect(() => mergeClaudeHook({ hooks: [] })).toThrow(/"hooks" must be an object/);
    expect(() => mergeClaudeHook({ hooks: { PostToolUse: {} } })).toThrow(/must be an array/);
  });
});

describe("runHookClaude", () => {
  let dir: string;
  let settingsPath: string;
  const errors: string[] = [];
  const logs: string[] = [];

  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "vibesafe-hook-"));
    settingsPath = path.join(dir, ".claude", "settings.json");
    errors.length = 0;
    logs.length = 0;
    vi.spyOn(console, "error").mockImplementation((m: unknown) => void errors.push(String(m)));
    vi.spyOn(console, "log").mockImplementation((m: unknown) => void logs.push(String(m)));
    process.exitCode = undefined;
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    process.exitCode = undefined;
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("prints the snippet as pure JSON on stdout and writes nothing without --write", async () => {
    await runHookClaude({ dir });
    expect(JSON.parse(logs.join("\n"))).toEqual(claudeHookSnippet());
    await expect(fs.stat(settingsPath)).rejects.toThrow();
  });

  it("creates .claude/settings.json with --write", async () => {
    await runHookClaude({ write: true, dir });
    expect(JSON.parse(await fs.readFile(settingsPath, "utf-8"))).toEqual(claudeHookSnippet());
    expect(process.exitCode).toBeUndefined();
  });

  it("merges into existing settings and is idempotent", async () => {
    await fs.mkdir(path.dirname(settingsPath), { recursive: true });
    await fs.writeFile(settingsPath, JSON.stringify({ model: "opus", hooks: {} }));
    await runHookClaude({ write: true, dir });
    const first = await fs.readFile(settingsPath, "utf-8");
    await runHookClaude({ write: true, dir });
    expect(await fs.readFile(settingsPath, "utf-8")).toBe(first);
    const parsed = JSON.parse(first);
    expect(parsed.model).toBe("opus");
    expect(parsed.hooks.PostToolUse).toHaveLength(1);
    expect(errors.join("\n")).toContain("no change");
  });

  it("refuses to touch a settings file that is not valid JSON", async () => {
    await fs.mkdir(path.dirname(settingsPath), { recursive: true });
    const broken = '{ "hooks": { // comment\n';
    await fs.writeFile(settingsPath, broken);
    await runHookClaude({ write: true, dir });
    expect(await fs.readFile(settingsPath, "utf-8")).toBe(broken);
    expect(process.exitCode).toBe(1);
    expect(errors.join("\n")).toContain("not valid JSON");
  });

  it("refuses to merge into an unexpected shape", async () => {
    await fs.mkdir(path.dirname(settingsPath), { recursive: true });
    await fs.writeFile(settingsPath, JSON.stringify({ hooks: { PostToolUse: "nope" } }));
    await runHookClaude({ write: true, dir });
    expect(JSON.parse(await fs.readFile(settingsPath, "utf-8"))).toEqual({
      hooks: { PostToolUse: "nope" },
    });
    expect(process.exitCode).toBe(1);
  });
});

describe("--online wiring", () => {
  it("scan passes online only when the flag is given", () => {
    expect(buildScanOptions("/p", {})).not.toHaveProperty("online");
    expect(buildScanOptions("/p", { online: false })).not.toHaveProperty("online");
    expect(buildScanOptions("/p", { online: true })).toMatchObject({ online: true });
  });

  it("watch never enables it, even if an online option leaks in", () => {
    expect(buildWatchScanOptions("/p", {})).not.toHaveProperty("online");
    const leaked = { online: true } as unknown as Parameters<typeof buildWatchScanOptions>[1];
    expect(buildWatchScanOptions("/p", leaked)).not.toHaveProperty("online");
  });
});

// Requires `pnpm build` (dist/bin.js).
describe("vibesafe CLI (built binary)", () => {
  it("`hook claude` prints only the JSON snippet (no banner)", () => {
    const res = spawnSync(process.execPath, [BIN, "hook", "claude"], { encoding: "utf-8" });
    expect(res.status).toBe(0);
    expect(JSON.parse(res.stdout)).toEqual(claudeHookSnippet());
  }, 30000);

  it("`scan --help` documents --online and the exit codes", () => {
    const res = spawnSync(process.execPath, [BIN, "scan", "--help"], { encoding: "utf-8" });
    expect(res.status).toBe(0);
    expect(res.stdout).toContain("--online");
    expect(res.stdout).toContain("Exit codes:");
    expect(res.stdout).toMatch(/1\s+deploy status danger or blocker/);
    expect(res.stdout).toMatch(/2\s+usage or runtime error/);
  }, 30000);
});
