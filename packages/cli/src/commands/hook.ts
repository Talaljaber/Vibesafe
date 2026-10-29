import fs from "node:fs/promises";
import path from "node:path";

/**
 * `vibesafe hook claude`: a Claude Code hook that re-scans the project after Claude edits a
 * file. When the scan fails (deploy status danger or blocker, exit code 1) the hook exits 2,
 * which Claude Code treats as feedback: the markdown summary on stderr is shown to Claude so it
 * can fix the blocking issues. Exit 0 stays silent. The hook never blocks the edit itself.
 */
export const CLAUDE_HOOK_COMMAND =
  'npx --no-install vibesafe scan "$CLAUDE_PROJECT_DIR" --format markdown >&2 || exit 2';

/** Tools after which the hook runs. */
export const CLAUDE_HOOK_MATCHER = "Edit|MultiEdit|Write";

interface HookCommand {
  type: "command";
  command: string;
  timeout?: number;
}

interface HookMatcher {
  matcher: string;
  hooks: HookCommand[];
}

/** The `hooks` block to add to `.claude/settings.json`. */
export function claudeHookSnippet(): { hooks: { PostToolUse: HookMatcher[] } } {
  return {
    hooks: {
      PostToolUse: [
        {
          matcher: CLAUDE_HOOK_MATCHER,
          hooks: [{ type: "command", command: CLAUDE_HOOK_COMMAND, timeout: 120 }],
        },
      ],
    },
  };
}

/** Raised when the existing settings cannot be merged without losing data. */
export class HookSettingsError extends Error {}

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

function hasVibesafeHook(entries: unknown[]): boolean {
  return entries.some(
    (entry) =>
      isPlainObject(entry) &&
      Array.isArray(entry.hooks) &&
      entry.hooks.some(
        (h) =>
          isPlainObject(h) &&
          typeof h.command === "string" &&
          /\bvibesafe\s+scan\b/.test(h.command),
      ),
  );
}

/**
 * Adds the VibeSafe PostToolUse hook to parsed settings without touching anything else.
 * Idempotent: settings that already run `vibesafe scan` from a PostToolUse hook are returned
 * unchanged. Throws HookSettingsError when `settings`, `hooks` or `hooks.PostToolUse` has an
 * unexpected shape (rather than overwriting it).
 */
export function mergeClaudeHook(settings: unknown): {
  settings: Record<string, unknown>;
  changed: boolean;
} {
  if (!isPlainObject(settings)) {
    throw new HookSettingsError("settings must be a JSON object");
  }
  const hooks = settings.hooks ?? {};
  if (!isPlainObject(hooks)) throw new HookSettingsError('"hooks" must be an object');
  const post = hooks.PostToolUse ?? [];
  if (!Array.isArray(post)) throw new HookSettingsError('"hooks.PostToolUse" must be an array');
  if (hasVibesafeHook(post)) return { settings, changed: false };
  const entry = claudeHookSnippet().hooks.PostToolUse[0]!;
  return {
    settings: { ...settings, hooks: { ...hooks, PostToolUse: [...post, entry] } },
    changed: true,
  };
}

export interface HookClaudeOptions {
  /** Merge into `<dir>/.claude/settings.json` instead of printing. */
  write?: boolean | undefined;
  /** Project directory (default: current directory). */
  dir?: string | undefined;
}

/** Prints the snippet (stdout stays pure JSON) or, with --write, merges it into the project. */
export async function runHookClaude(options: HookClaudeOptions = {}): Promise<void> {
  if (!options.write) {
    console.log(JSON.stringify(claudeHookSnippet(), null, 2));
    console.error(
      "Add this to .claude/settings.json (or run `vibesafe hook claude --write` to merge it).\n" +
        "Claude Code then re-scans after every edit and is told about deploy-blocking findings.\n" +
        "Requires VibeSafe installed in the project: npm install -D @talaljaber/vibesafe-cli",
    );
    return;
  }

  const root = path.resolve(process.cwd(), options.dir ?? ".");
  const settingsPath = path.join(root, ".claude", "settings.json");
  let existing: unknown = {};
  try {
    const st = await fs.lstat(settingsPath);
    if (st.isSymbolicLink() || !st.isFile()) {
      console.error(`Error: refusing to write ${settingsPath}: not a regular file.`);
      process.exitCode = 1;
      return;
    }
    const raw = await fs.readFile(settingsPath, "utf-8");
    try {
      existing = raw.trim() === "" ? {} : JSON.parse(raw);
    } catch {
      console.error(
        `Error: ${settingsPath} is not valid JSON; leaving it untouched. Fix it or add the snippet from \`vibesafe hook claude\` by hand.`,
      );
      process.exitCode = 1;
      return;
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code !== "ENOENT") {
      console.error(`Error: cannot read ${settingsPath}: ${(error as Error).message}`);
      process.exitCode = 1;
      return;
    }
  }

  let merged: ReturnType<typeof mergeClaudeHook>;
  try {
    merged = mergeClaudeHook(existing);
  } catch (error) {
    console.error(
      `Error: cannot merge into ${settingsPath}: ${(error as Error).message}; leaving it untouched.`,
    );
    process.exitCode = 1;
    return;
  }
  if (!merged.changed) {
    console.error(`${settingsPath} already runs vibesafe scan from a PostToolUse hook; no change.`);
    return;
  }
  await fs.mkdir(path.dirname(settingsPath), { recursive: true });
  await fs.writeFile(settingsPath, JSON.stringify(merged.settings, null, 2) + "\n", "utf-8");
  console.error(`Added the VibeSafe PostToolUse hook to ${settingsPath}.`);
}
