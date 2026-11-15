# Attack Mode booth runbook

A runbook for one presenter at a booth, on a Windows laptop, using PowerShell. The live part takes about 90 seconds: VibeSafe flags a vulnerable app, proves two of the flags with live requests and shows that a third flag is a false alarm. Claude Code then fixes the app, and a retest shows the holes are closed and the rightful owner still has access.

Everything runs on the laptop. Only Claude Code needs Wi-Fi.

## The story (30 seconds, before you type anything)

> "AI writes code fast, and it writes security holes just as fast. Scanners report hundreds of possible issues and people stop reading them. VibeSafe tells you which ones are real. It sends a few safe requests to your own dev server and proves the problem: here, Alice can read Bob's private note. It also tells you when a flag is a false alarm. Then your AI agent fixes the real issues and VibeSafe checks the fix. More than 900 people have downloaded the npm packages, and more than 980 have installed the VS Code extension from Open VSX."

Three points to make while it runs:

1. **Proof, not guesses.** Static flagged 4. The live test confirmed 2, refuted 1 and could not safely test 1.
2. **Safe by design.** It only talks to your own machine (loopback), sends only GET requests with no bodies, at 5 requests per second, and at most 300 per run. Reports show response shapes (status codes and key names), never the data itself.
3. **A closed loop with your agent.** `attack-report.md` is written for Claude Code. `--retest` proves the fix worked and checks that the owner can still read their own data.

## The day before (with network)

Open PowerShell in your VibeSafe clone. `$VS` is the path of that clone, and every command below uses it.

```powershell
$VS = "C:\path\to\Vibesafe"          # your clone
cd $VS
git pull
pnpm install
pnpm build
pnpm demo:smoke                       # must end with: PASS  demo flow works end to end

node scripts/create-attack-demo.mjs C:\demo\vibesafe-demo
cd C:\demo\vibesafe-demo
npm install                           # booth package.json: next, react, react-dom
```

Make `vibesafe` a command in every PowerShell window. The npm release does not include Attack Mode yet, so it must run from your build:

```powershell
notepad $PROFILE
# add these two lines, save, then open a new PowerShell window:
$VS = "C:\path\to\Vibesafe"
function vibesafe { node "$VS\packages\cli\dist\bin.js" @args }
```

Then run one full rehearsal (the live flow below), reset (see "Between visitors"), and run two more timed rehearsals. Record one good run as a 90-second screen video (Win+Alt+R starts and stops Xbox Game Bar recording) and keep it on the desktop.

## At the booth (5 minutes before the first visitor)

Terminal 1 (the app):

```powershell
cd C:\demo\vibesafe-demo
npm run dev                           # Next.js on http://127.0.0.1:3000, wait for "Ready"
```

Terminal 2 (VibeSafe):

```powershell
cd C:\demo\vibesafe-demo
node "$VS\scripts\attack-prewarm.mjs" .   # compiles every route once; must end with "Warm."
git status                                # on branch main, no changes to app/
```

Claude Code: start it in `C:\demo\vibesafe-demo` and switch it to accept edits automatically (press Shift+Tab until it shows "accept edits on"), so it does not stop to ask for permission on stage. The demo folder has its own `CLAUDE.md`, which tells Claude to fix what the report says and not to run the attack itself.

Arrange the windows: Terminal 2 large on the left, Claude Code on the right, browser behind. Terminal 1 can stay minimised.

## Live flow (about 90 seconds)

| Time  | Where       | Do this                                              | What the audience sees                                                                                                            |
| ----- | ----------- | ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| 0:00  | Terminal 2  | `vibesafe attack --open-report`                      | Banner, then **CONFIRMED: Alice read Bob's note**, **CONFIRMED: a logged-out visitor read /api/admin/users**, REFUTED, NOT TESTED |
| 0:05  | Browser     | Point at the ledger                                  | "Static flagged 4 · live confirmed 2 · refuted 1 · couldn't test 1", static and live evidence side by side                        |
| 0:15  | Claude Code | Type: `Fix the issues in .vibesafe/attack-report.md` | Claude reads the report and adds the owner check and the admin check (allow up to 60 s)                                           |
| ~1:15 | Terminal 2  | `vibesafe attack --retest --open-report`             | **BLOCKED**: Alice can no longer read Bob's note, "owner access still works ✓"; admin/users BLOCKED; invoices still refuted       |
| ~1:30 | Browser     | Point at the before/after view                       | The retest view of the HTML report                                                                                                |

What to say at each step:

- **Baseline:** "The static scan found four suspicious spots. VibeSafe signed in as Alice and asked for Bob's note, and it got it back. That's a real leak, not a guess. The invoices flag looked the same in the code, but the live test shows the app refuses it, so you don't waste time on it. The PATCH route writes data, so VibeSafe refuses to test it and says so."
- **Fix:** "The report is written for the agent: which route, which file, and what the fix must keep working. No secrets or user data are in it."
- **Retest:** "Same attacks, replayed. Blocked, and Bob can still read his own note. A fix that locks everyone out would show up as BROKEN."
- **Exit codes, if asked:** the baseline exits 1 (confirmed issues), the retest exits 0, so it can gate a deploy.

Claude may end with "run `npx vibesafe attack --retest`". Ignore that and use the `vibesafe` command from your profile.

## Between visitors (reset, about 10 seconds)

In Terminal 2:

```powershell
git checkout -f main                                   # drops the agent's edits (or leaves the fixed branch)
git reset --hard (git rev-list --max-parents=0 HEAD)   # main back to "vulnerable demo", even if the agent committed
Remove-Item .vibesafe\attack-* -ErrorAction SilentlyContinue
git status                                             # on main; only node_modules/, .next/ and package-lock.json untracked
```

`next dev` reloads the routes by itself. If you are on the harness, restart it (Ctrl+C, then `node server.mjs --port 3000`). Run `/clear` in Claude Code so the next visitor starts fresh.

## Fallbacks

| Problem                                                   | Do this                                                                                                                                                                            |
| --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Claude Code stalls, or there is no Wi-Fi                  | In Terminal 2: `git checkout -f fixed` (the prepared fix), then `vibesafe attack --retest --open-report`. Say: "this is the fix the agent makes".                                  |
| `next dev` misbehaves or is slow                          | Ctrl+C in Terminal 1, then `node server.mjs --port 3000`: the same routes with zero dependencies. After `git checkout fixed`, restart it (Ctrl+C, run it again) before `--retest`. |
| One result needs proving again                            | `vibesafe attack --replay ATK-df44c1e8a995` (the notes leak). The ids are stable, so you can copy them from the terminal or the report.                                            |
| "A baseline exists" (exit 2)                              | You forgot the reset. Run the `Remove-Item` line above, or use `vibesafe attack --new-baseline --open-report` (archives the old one).                                              |
| "target does not look like this project" or ERROR results | The server is not running, or it is still compiling. Check Terminal 1, run `node "$VS\scripts\attack-prewarm.mjs" .`, then try again.                                              |
| Port 3000 is taken                                        | `npx next dev -H 127.0.0.1 -p 3001` (or `node server.mjs --port 3001`). Port 3001 is detected too, or pass `--target http://127.0.0.1:3001`.                                       |
| Anything else, or the laptop is struggling                | Play the recorded video and talk over it.                                                                                                                                          |

To check the whole flow at any time without touching the demo folder: `cd $VS; pnpm demo:smoke`. It runs baseline, fix and retest against the harness in a temp folder and prints PASS or FAIL in about 15 seconds.

## Questions you will get

- **"Is it safe to point at my app?"** It only accepts `127.0.0.1`, `::1` and `localhost`. It sends GET requests only, with no bodies, at 5 per second by default and at most 300 per run. GET handlers that look like they write data are skipped before any request is sent. All network code sits in one small module (`packages/attack/src/http`), and a test fails the build if network code appears anywhere else.
- **"Does it send my code or data anywhere?"** No. The static scan is offline. There are no AI calls inside VibeSafe; the fix prompt is plain text that your own agent reads.
- **"How does it know Alice and Bob?"** From `.vibesafe/sessions.json`: two test accounts and one record id each. It never invents ids.
- **"What about false positives?"** That is the point of the invoices route: the static rule flags it, and the live test shows the app refuses the request, so it is reported as refuted.
- **"Where can I get it?"** VS Code extension: search "VibeSafe" in the Marketplace or Open VSX. CLI: `npm i -g @talaljaber/vibesafe-cli`. Attack Mode is coming in the next release.
