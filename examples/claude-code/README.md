# VibeSafe hook for Claude Code

`settings.json` in this folder is a [Claude Code hooks](https://docs.claude.com/en/docs/claude-code/hooks) snippet. After every `Edit`, `MultiEdit` or `Write`, it re-scans the project:

- deploy status `safe` or `warning`: the scan passes (exit 0) and Claude is not interrupted;
- deploy status `danger` or `blocker`: the hook exits 2, so Claude Code shows the scan's Markdown summary to Claude, which can then fix the blocking findings. The edit itself is never blocked.

## Install

1. Add VibeSafe to the project: `npm install -D @talaljaber/vibesafe-cli`.
2. Merge the hook into `.claude/settings.json`:

   ```bash
   npx vibesafe hook claude --write
   ```

   This keeps every existing setting and hook, does nothing when a `vibesafe scan` PostToolUse hook is already there, and refuses to touch a `.claude/settings.json` that is not valid JSON. `npx vibesafe hook claude` without `--write` only prints the snippet.

The hook runs an offline scan (no `--online`, no `--deep`), so nothing leaves the machine. Scans of large projects can take a few seconds; the hook has a 120 s timeout.
