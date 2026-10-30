<div align="center">
  <h1>🛡️ VibeSafe</h1>
  <p><strong>The Pre-Deploy Safety Scanner for Vibe-Coded Apps</strong></p>
  <p>
    <a href="https://marketplace.visualstudio.com/items?itemName=talaljaber.vibeguard-scanner"><img src="https://img.shields.io/visual-studio-marketplace/v/talaljaber.vibeguard-scanner?style=flat-square&color=blueviolet" alt="VS Code Marketplace"></a>
    <img src="https://img.shields.io/badge/License-MIT-green.svg?style=flat-square" alt="License">
  </p>
</div>

<hr />

## 🚨 The "Vibe Coding" Problem

"Vibe coding" with AI tools (like Cursor, GitHub Copilot, or Claude) is incredibly fast and fun, but it often leads to messy codebases, exposed secrets, and subtle security flaws.

**VibeSafe** acts as your automated security engineer. It scans your code before you deploy and tells you exactly what to fix, complete with copy-pasteable AI prompts and one-click auto-fixes.

---

### Before / After

- **Before:** Secrets hardcoded, empty `.env.example`, missing dependency declarations.
- **After:** Clean `.env.example`, safer configurations, and fewer obvious deployment risks.

### Dashboard and CLI Reports

<p align="center">
  <img src="packages/vscode/report.png" alt="VibeSafe Report Dashboard" width="45%">
  <img src="packages/vscode/report1.png" alt="VibeSafe Detail View" width="45%">
</p>

<p align="center">
  <img src="packages/vscode/Cli.png" alt="VibeSafe CLI Output" width="60%">
</p>

---

## 📦 Installation & Usage

### 💻 Command Line Interface (CLI)

The CLI is published on npm as `@talaljaber/vibesafe-cli` (Node 20 or newer). Run it without installing:

```bash
npx @talaljaber/vibesafe-cli scan .
```

Or install it globally to get the `vibesafe` command:

```bash
npm i -g @talaljaber/vibesafe-cli
vibesafe scan .
```

> [!NOTE]
> The packages are published by hand. Until the first release of `@talaljaber/vibesafe-cli` shows up on npm, build VibeSafe from source instead. Packages in the `@vibesafe` npm scope belong to someone else and are not this tool.

To build from source:

```bash
git clone https://github.com/Talaljaber/Vibesafe.git
cd Vibesafe
pnpm install
pnpm build
node packages/cli/dist/bin.js scan /path/to/your/app
```

To get a global `vibesafe` command from your local build, link the CLI package:

```bash
cd packages/cli
npm link
# then, in any project:
vibesafe scan . --html
```

The examples below use `vibesafe`; with a plain build, run `node packages/cli/dist/bin.js` instead.

**`vibesafe scan [dir]`** (directory defaults to `.`)

| Option                                   | What it does                                                                                                                                                                                                                                                                                                                                                                                                         |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| _(none)_                                 | Prints the score, deploy status and a prioritized **Repair Plan** to the terminal.                                                                                                                                                                                                                                                                                                                                   |
| `--html`                                 | Also writes a `vibesafe-report.html` dashboard to the scanned directory.                                                                                                                                                                                                                                                                                                                                             |
| `--open-report`                          | Writes the HTML dashboard and opens it in your default browser.                                                                                                                                                                                                                                                                                                                                                      |
| `--format json\|sarif\|markdown`         | Pure machine-readable output on stdout: JSON, SARIF 2.1.0, or a markdown summary for PR comments. `-j` / `--json` is an alias of `--format json`.                                                                                                                                                                                                                                                                    |
| `--output <file>`                        | Writes the report to a file instead of stdout (JSON unless `--format` says otherwise).                                                                                                                                                                                                                                                                                                                               |
| `-i`, `--interactive`                    | After the scan, offers to walk through the findings one by one (apply the safe auto-fix, skip, or quit). Needs an interactive terminal; the scan's exit code stays.                                                                                                                                                                                                                                                  |
| `--deep` / `--no-deep`                   | Also scan git history for leaked secrets (slower), or turn that off even if the config file enables it.                                                                                                                                                                                                                                                                                                              |
| `--include-tests` / `--no-include-tests` | Also scan test files and fixtures (excluded by default), or exclude them even if the config file includes them.                                                                                                                                                                                                                                                                                                      |
| `--no-config`                            | Ignore any `.vibesafe.config.*` file.                                                                                                                                                                                                                                                                                                                                                                                |
| `--trust-config`                         | Allow `.ts` / `.js` config files from the scanned directory to run. They execute code, so use this only for projects you trust.                                                                                                                                                                                                                                                                                      |
| `--online`                               | Also look up dependency versions in the OSV advisory database (`dependency/osv-advisory`) and check that each direct npm and PyPI dependency exists on its registry (`dependency/package-not-found`, `dependency/package-very-new`). It sends package names and versions to `api.osv.dev`, and package names to the npm and PyPI registries; this is the only network access VibeSafe has, and it is off by default. |

**`vibesafe fix [finding-id] [dir]`**

- `vibesafe fix <finding-id-or-rule-id> .` previews and applies a safe auto-fix for one finding. `-y` / `--yes` skips the confirmation (it needs an exact finding id or a single match).
- `vibesafe fix --all .` (`-a`) previews and applies every auto-fixable finding after a single confirmation. The one positional argument is then the directory.
- `vibesafe fix -i .` (`--interactive`) scans, then runs the same interactive fix wizard as `scan -i`. It has no `--deep` or `--include-tests` flags; it takes those from the config file, or use `scan -i`.
- `fix` also accepts `--no-config` and `--trust-config`.

Auto-fixes exist for `.env` files missing from `.gitignore` (`secret/env-not-ignored`), a missing `.env.example` (`structure/missing-env-example`) and leftover `console.log` statements (`code_quality/console-log`). Every other finding comes with fix steps and a copy-paste AI fix prompt.

**`vibesafe watch [dir]`**

Scans once, then re-scans on every file change and prints what got better or worse. `-j` / `--json` emits NDJSON events (`ready`, `change`, `error`), one JSON object per line. Also accepts `--include-tests` / `--no-include-tests`, `--no-config` and `--trust-config`. Git history is never scanned in watch mode.

**`vibesafe hook claude [dir]`**

Prints a [Claude Code hook](https://docs.claude.com/en/docs/claude-code/hooks) that re-scans the project after every `Edit`, `MultiEdit` or `Write` and shows Claude the markdown summary when the deploy status is `danger` or `blocker`, so it can fix the findings itself. `--write` merges the hook into `.claude/settings.json` and keeps existing settings. The hook scan is offline (no `--online`, no `--deep`). See [`examples/claude-code`](examples/claude-code/README.md).

Run `vibesafe --help` or `vibesafe <command> --help` for the full list.

**Exit codes:** `scan` exits with `1` when the deploy status is `blocker` or `danger`, so it can gate CI, and with `2` when the scan itself fails.

```text
╭────────────────────────────────────────────────────────────────────────╮
│                                                                        │
│    __     __  ___   ____    _____   ____       _      _____   _____    │
│    \ \   / / |_ _| | __ )  | ____| / ___|     / \    |  ___| | ____|   │
│     \ \ / /   | |  |  _ \  |  _|   \___ \    / _ \   | |_    |  _|     │
│      \ V /    | |  | |_) | | |___   ___) |  / ___ \  |  _|   | |___    │
│       \_/    |___| |____/  |_____| |____/  /_/   \_\ |_|     |_____|   │
│                                                                        │
│                                                                        │
╰────────────────────────────────────────────────────────────────────────╯

  The don't-deploy-that-yet tool for vibe-coded apps.

Ready to scan directory: ./my-vibecoded-app
Starting VibeSafe scan...

📊 SCAN RESULTS
Score:         4 / 100
Deploy Status: ❌ DO NOT DEPLOY
Message:       Critical security issues found. Fix these before shipping.
...
🛠️  REPAIR PLAN
Found 7 issues needing your attention. Expected fix time: ~70 mins.
...
```

### 🔍 What VibeSafe detects

VibeSafe scans `.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.cjs`, `.json`, `.py` and `.sql` files plus `.env*` files, `.gitignore`, `package.json`, lockfiles and Python manifests (`requirements*.txt`, `requirements/*.txt`, `pyproject.toml`, `Pipfile`). Infrastructure files are scanned too: Dockerfiles, docker-compose files, GitHub workflows, shell scripts, Terraform (`.tf`, `.tfvars`), Kubernetes manifests, Firebase rules files (`firestore*.rules`, `storage*.rules`, `database.rules.json`) and `supabase/config.toml`. Every finding has a rule id of the form `category/rule`, which you can use in inline ignores, the config file and `vibesafe fix`.

| Category            | Rule ids                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | What it checks                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `secret`            | `secret/sec-*` (one per pattern, e.g. `secret/sec-openai-key`, `secret/sec-aws-secret-key`), `secret/git-history-sec-*`, `secret/env-not-ignored`, `secret/django-secret-key`, `secret/django-secret-key-fallback`, `secret/k8s-secret-manifest`, `secret/k8s-configmap-credential`, `secret/terraform-literal-credential`                                                                                                                                                                                                                                                                                                                                                                                                                               | Hardcoded keys and tokens (OpenAI, Anthropic, Stripe, AWS access key ids and secret keys, GitHub, Supabase, Slack, Google Cloud, Discord, SendGrid, Mailchimp, JWTs, generic passwords and secrets) with per-pattern severity, placeholder filtering and redacted evidence; `.env` not in `.gitignore`; leaked secrets in git history with `--deep`; hardcoded Django `SECRET_KEY`; literal credentials in Kubernetes Secrets and ConfigMaps and in Terraform                                                                                                                                                                                                                                                  |
| `frontend_exposure` | `frontend_exposure/public-secret-var`, `frontend_exposure/server-env-in-client-import`, `frontend_exposure/service-role-key`, `frontend_exposure/firebase-admin`, `frontend_exposure/vite-define-process-env`, `frontend_exposure/secret-in-web-storage`, `frontend_exposure/sensitive-data-console-log`, `frontend_exposure/full-row-client-prop`                                                                                                                                                                                                                                                                                                                                                                                                       | Secrets behind public env prefixes (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`, `NUXT_PUBLIC_`, `PUBLIC_`), server env reachable from client code (import following), Supabase service role keys and the Firebase Admin SDK in client code, Vite `define` blocks that leak `process.env`; secrets in `localStorage` / `sessionStorage`, sensitive data in `console.log`, and whole sensitive rows passed from server code to client components                                                                                                                                                                                                                                                      |
| `auth`              | `auth/missing-route-auth`, `auth/stripe-webhook-unsigned`, `auth/stripe-webhook-parsed-body`, `auth/django-view-missing-auth`, `auth/django-drf-allow-any`, `auth/hardcoded-route-secret`, `auth/non-constant-time-compare`, `auth/middleware-cookie-presence-only`, `auth/middleware-matcher-gap`, `auth/jwt-decode-without-verify`, `auth/auth-disabled-outside-production`, `auth/secret-check-fails-open`, `auth/unprotected-queue-dashboard`                                                                                                                                                                                                                                                                                                        | Next.js API routes and Express routes that do risky work without an auth check; Stripe webhook handlers without `stripe.webhooks.constructEvent()` on the raw body; Django and Django REST Framework views that accept POST/PUT/PATCH/DELETE without `@login_required`, an auth mixin or `permission_classes`, and DRF write views set to `AllowAny`; hardcoded route secrets and non-constant-time comparisons; Next.js middleware that only checks that a cookie exists or whose matcher skips protected routes; unverified JWT decodes that gate access, auth middleware disabled outside production, secret checks that fail open, and queue dashboards (Bull Board, Arena, Agendash) mounted without auth |
| `authorization`     | `authorization/missing-role-check`, `authorization/supabase-missing-rls`, `authorization/supabase-permissive-policy`, `authorization/idor-unscoped-lookup`, `authorization/mass-assignment`, `authorization/auth-check-after-write`, `authorization/client-side-role-check`, `authorization/supabase-*` (`select-using-true`, `self-referential-policy`, `policy-self-promotion`, `grant-to-anon`, `security-definer-no-search-path`, `definer-missing-caller-check`), `authorization/firebase-rules-*` (`public-read`, `public-write`, `any-signed-in`, `test-mode`)                                                                                                                                                                                    | Authenticated routes without role or permission checks; Supabase tables without Row Level Security and policies that let everyone write; IDOR (lookups not scoped to the caller), mass assignment, auth checks that run after the write, role checks that only exist in the client; risky Supabase policies, grants to `anon` and `SECURITY DEFINER` functions; open Firebase rules (public read or write, test mode, any signed-in user)                                                                                                                                                                                                                                                                      |
| `validation`        | `validation/missing-body-validation`, `validation/check-then-act-race`, `validation/client-trusted-price`, `validation/upload-no-size-limit`, `validation/upload-no-type-check`, `validation/upload-unsafe-filename`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Next.js and Express routes that read request input without validation (Zod, express-validator, celebrate, ...); check-then-act races on balances and stock, and prices or amounts trusted from the client; file uploads without a size limit or type check and stored file names taken from the uploader                                                                                                                                                                                                                                                                                                                                                                                                       |
| `security_config`   | `security_config/cors-*` (`reflected-origin`, `wildcard-credentials`, `wildcard-header`, `default-with-cookies`), `security_config/missing-helmet`, `security_config/missing-security-headers`, `security_config/missing-rate-limit`, `security_config/django-*`, `security_config/docker-*`, `security_config/compose-*`, `security_config/gha-*`, `security_config/shell-*`, `security_config/nextjs-*`, `security_config/error-stack-leak`, `security_config/gitignore-env-variants`, `security_config/tf-*`, `security_config/k8s-*`, `security_config/supabase-*`, `security_config/session-cookie-*` (`no-httponly`, `not-secure`, `samesite-none`), `security_config/csrf-cookie-session-unprotected`, `security_config/celery-pickle-serializer` | Insecure CORS, Express apps without helmet and Next.js apps without security headers, auth / AI / email and SMS endpoints without rate limiting, insecure Django settings (`DEBUG`, `ALLOWED_HOSTS`, CORS, cookies, HTTPS redirect, HSTS, `SESSION_COOKIE_HTTPONLY`, `X_FRAME_OPTIONS`, `SECURE_PROXY_SSL_HEADER`) and `csrf_exempt` views; Dockerfiles (root user, unpinned base image, secrets in `ENV`, missing `.dockerignore`), docker-compose (exposed database ports, default passwords, privileged services), GitHub workflows (`pull_request_target` checkouts, unpinned actions, `write-all` permissions), shell scripts (`curl                                                                      | sh`, hardcoded credentials), Next.js config (browser source maps, ignored build errors, wildcard image hosts), stack traces in error responses, Terraform (public S3 buckets, open ingress, wildcard IAM and OIDC trust, publicly accessible or unencrypted storage, plain-HTTP CloudFront), Kubernetes manifests (privileged containers, host namespaces and paths, root users, cluster-admin and wildcard RBAC, plain-HTTP ingress, mutable image tags), `supabase/config.toml`auth settings, session cookies without`HttpOnly`/`Secure`or with`SameSite=None`, cookie-session Express apps without CSRF protection, Celery with the pickle serializer, and a `.gitignore`that ignores`.env` but not its variants |
| `injection`         | `injection/sql-built-from-input`, `injection/sql-built-from-parameter`, `injection/postgrest-filter-interpolation`, `injection/ssrf-user-controlled-url`, `injection/path-traversal`, `injection/dynamic-code-eval`, `injection/command-exec-interpolation`, `injection/open-redirect`, `injection/gha-script-injection`, `injection/client-dynamic-code`, `injection/client-open-redirect`, `injection/code-eval-from-parameter`, `injection/python-*` (`shell-command`, `sql-interpolation`, `unsafe-yaml-load`, `unsafe-deserialization`, `xxe-parser`, `path-traversal`), `injection/shell-eval-remote-content`, `injection/shell-sql-interpolation`                                                                                                 | Untrusted input reaching an interpreter or sink: SQL and PostgREST filters built by string interpolation, SSRF, path traversal, `eval` / `new Function`, shell commands, open redirects and GitHub Actions script injection, the same sinks in Python, and shell scripts that eval remote content or build SQL from arguments (parameterized queries stay clean)                                                                                                                                                                                                                                                                                                                                               |
| `crypto`            | `crypto/insecure-random-token`, `crypto/hardcoded-secret-fallback`, `crypto/plaintext-api-key-storage`, `crypto/plaintext-seed-password`, `crypto/weak-password-hash`, `crypto/jwt-*` (`algorithm-none`, `decode-for-auth`, `literal-secret`, `verify-without-algorithms`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | `Math.random()` tokens, `process.env.X                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | "secret"` fallbacks, plaintext API keys and seed passwords, weak password hashing and JWT misuse |
| `xss`               | `xss/dangerously-set-inner-html`, `xss/javascript-url-href`, `xss/postmessage-no-origin-check`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | `dangerouslySetInnerHTML` with dynamic content; `javascript:` hrefs and `postMessage` listeners without an origin check                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `dependency`        | `dependency/risky-install-script`, `dependency/excessive-dependencies`, `dependency/python-unpinned`, `dependency/python-insecure-version`, `dependency/known-vulnerable-version`, `dependency/typosquat-package`, `dependency/osv-advisory`, `dependency/package-not-found`, `dependency/package-very-new`                                                                                                                                                                                                                                                                                                                                                                                                                                              | Suspicious install scripts and an excessive number of dependencies in the root `package.json`; Django and other security-critical Python packages without a pin or upper bound, and end-of-life or insecure versions from a short static list (offline, no vulnerability database); known-vulnerable npm versions from a short offline list, typosquatted package names, and, only with `--online`, advisories from the OSV database and a check that each npm and PyPI dependency exists and is not brand new                                                                                                                                                                                                 |
| `code_quality`      | `code_quality/huge-file`, `code_quality/empty-catch`, `code_quality/console-log`, `code_quality/excessive-any`, `code_quality/hardcoded-localhost`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Very large files, empty `catch` blocks, leftover `console.log`, excessive `any`, hardcoded localhost URLs                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `structure`         | `structure/missing-gitignore`, `structure/missing-readme`, `structure/missing-env-example`, `structure/missing-tests`, `structure/missing-error-boundary`, `structure/placeholder-only-tests`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Missing `.gitignore`, `README.md`, `.env.example` or tests; React apps without an error boundary; test files that contain only placeholders                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |

Next.js, Vite and Express projects are detected automatically. Django projects are detected too: `.py` files are scanned, Django settings and views are checked, and Python manifests are checked offline. Python checks are line based like the rest of the scanner (no Python AST), so they can miss unusual code layouts.

Test and fixture paths (for example `**/*.test.*`, `**/*.spec.*`, `__tests__`, `tests/`, `test_*.py`, `fixtures/`) are excluded by default; pass `--include-tests` to scan them.

### 🔇 Ignoring findings

Suppress a finding with an inline comment. Without rule ids a directive applies to every rule; with one or more comma-separated rule ids it only applies to those rules.

```ts
const key = "..."; // vibesafe-disable-line secret/sec-openai-key
// vibesafe-disable-next-line auth/missing-route-auth, validation/missing-body-validation
export async function POST(req: Request) {}
// vibesafe-disable-file code_quality/console-log
```

### ⚙️ Configuration file

Create `.vibesafe.config.json` (or `vibesafe.config.json`) in the project root. It is plain JSON and is never executed.

```json
{
  "rules": { "code_quality/*": "off", "secret/sec-generic-password": "low" },
  "disabledDetectors": ["git-history-detector"],
  "categories": ["secret", "auth"],
  "exclude": ["legacy/**"],
  "includeTests": false,
  "minSeverity": "medium",
  "deep": false
}
```

- `rules` maps rule ids (exact, or with a `*` glob) to a severity or `"off"`. An exact rule id beats a glob; among globs the longest wins. Overrides run after detection, so changed severities are re-sorted and re-scored.
- `disabledDetectors` takes detector ids such as `git-history-detector`, `cors-detector` or `rate-limit-detector`. An unknown id produces a scan warning that lists the known ids.
- `exclude` and `categories` replace the defaults rather than extending them.
- Explicit CLI flags and API options always win over file values (`--deep` / `--no-deep`, `--include-tests` / `--no-include-tests`); `--no-config` ignores the file entirely. API users can skip the file with `useConfigFile: false`.
- A config file can hide findings, so every scan that applies one reports it, and how many findings it suppressed, in the scan warnings. In machine-output modes (`--json`, `--format`, `--output`) these warnings go to stderr so stdout stays a clean report; `watch --json` carries them in a `warnings` field on its `ready` and `change` events.

> [!WARNING]
> Script configs (`.vibesafe.config.ts`, `.mts`, `.js`, `.mjs`, `.cjs`) run code from the scanned directory (loaded with [jiti](https://github.com/unjs/jiti)). Because VibeSafe is meant to scan untrusted repos, they are **ignored by default** and the scan adds a warning. Opt in only for projects you trust, with `--trust-config` or `trustConfigScripts: true` in the API. The MCP server and the VS Code extension never run script configs.

TypeScript variant (`.vibesafe.config.ts`, only loaded with `--trust-config`):

```ts
import { defineConfig } from "@talaljaber/vibesafe-core";

export default defineConfig({
  rules: { "code_quality/*": "off", "secret/sec-generic-password": "low" }, // "off" or a severity; "*" globs allowed
  disabledDetectors: ["git-history-detector"],
  categories: ["secret", "auth"], // omit for all
  exclude: ["legacy/**"],
  includeTests: false,
  minSeverity: "medium",
  deep: false,
});
```

The config file applies to every command that scans, and they all accept `--no-config` / `--trust-config`:

| Command                                                                    | Config handling                                                                                                                                        |
| -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `vibesafe scan` (incl. `--format json\|sarif\|markdown`, `--output`, `-i`) | Full config. Flags: `--deep` / `--no-deep`, `--include-tests` / `--no-include-tests`. `scan -i` hands the same flags to the fix wizard.                |
| `vibesafe fix <id>`, `fix --all`, `fix -i`                                 | Full config, for both the scan that finds the fixes and the rescan after them, so the findings offered match what `scan` reports.                      |
| `vibesafe watch`                                                           | Full config, re-read on every rescan, plus `--include-tests` / `--no-include-tests`. Git history is never scanned in watch mode, so `deep` is ignored. |

### 🤖 GitHub Action

The repository ships a composite action (`action.yml`) that runs the CLI on pull requests, posts or updates one sticky PR comment with the markdown report (and the job summary), and fails the job according to `fail-on` (`blocker`, `danger`, `warning` or `none`; default `blocker`).

```yaml
name: VibeSafe
on: pull_request
permissions:
  contents: read
  pull-requests: write
jobs:
  vibesafe:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # Pin to a release tag or a full commit SHA; do not use a moving branch like @main.
      - uses: Talaljaber/Vibesafe@<release-tag-or-commit-sha>
        with:
          fail-on: danger
```

The action does not download VibeSafe from npm. It builds the CLI from the action's own source at the ref you pinned in `uses:` (a frozen-lockfile `pnpm install` from the repository's own lockfile, then a build of the CLI and its workspace packages) and runs that build, so the pinned ref is also the VibeSafe version you get. The build runs in the action's directory, ignores the scanned repository's npm config and skips dependency install scripts. It needs a `node-version` that ships corepack (Node 20.19+, 22.14+ or 24; older bundled corepack versions cannot verify pnpm downloads).

Pin the action to a release tag or commit SHA so a moved branch cannot change what runs in your CI. Inputs: `path`, `fail-on`, `comment`, `github-token`, `deep` (needs `fetch-depth: 0` on checkout) and `node-version`. The old `version` input is deprecated and ignored; choose the version with the `uses:` ref instead. Output: `status` (the deploy status). Use the plain `pull_request` trigger, not `pull_request_target`. See [`examples/github-action.yml`](examples/github-action.yml).

### 📄 SARIF and code scanning

`vibesafe scan . --format sarif --output vibesafe.sarif` writes SARIF 2.1.0 that you can upload with `github/codeql-action/upload-sarif` to see findings in GitHub code scanning.

### 🤖 MCP server

`@talaljaber/vibesafe-mcp` is a stdio [Model Context Protocol](https://modelcontextprotocol.io) server that lets AI assistants (Claude Code, Claude Desktop, ...) run VibeSafe scans.

**Tools**

| Tool                   | What it does                                                                                                                                                                                                                  |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `vibesafe_scan`        | Scan a directory (`path`, optional `minSeverity`, `category`, `includeTests`, and `deep` to also inspect git history for leaked secrets; `deep` is slower). Returns score, deploy status, scan warnings and the top findings. |
| `vibesafe_explain`     | Full explanation, fix steps and AI fix prompt for a finding ID from the last scan.                                                                                                                                            |
| `vibesafe_repair_plan` | The ordered repair plan from the last scan.                                                                                                                                                                                   |
| `vibesafe_fix`         | Preview (default, `dryRun: true`) or apply a safe auto-fix for a finding.                                                                                                                                                     |

Finding IDs are only valid until the next `vibesafe_scan`. Scans apply a JSON config file in the scanned directory; script configs are never run.

**Scan roots and writes.** By default `vibesafe_scan` only accepts directories inside the server's working directory, and `vibesafe_fix` with `dryRun: false` only returns a preview. Change this with server arguments or environment variables:

| Setting                                                                                  | Effect                                                    |
| ---------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| `--root <dir>` (repeatable) or `VIBESAFE_MCP_ROOTS` (separated by the OS path delimiter) | Directories that may be scanned (subtrees).               |
| `--allow-fix` or `VIBESAFE_MCP_ALLOW_FIX=1`                                              | Allow `vibesafe_fix` to write files when `dryRun: false`. |

**From npm.** The server is published as `@talaljaber/vibesafe-mcp` (same manual-release note as the CLI). Point your MCP client at `npx`:

```bash
claude mcp add vibesafe -- npx -y @talaljaber/vibesafe-mcp
```

```json
{
  "mcpServers": {
    "vibesafe": {
      "command": "npx",
      "args": ["-y", "@talaljaber/vibesafe-mcp"]
    }
  }
}
```

**From source.** The server runs from `dist/`, so build first (from the repo root):

```bash
pnpm install && pnpm build
```

**Claude Code** — the repo ships a `.mcp.json` that uses the relative path `packages/mcp/dist/index.js`, so start Claude Code from the repo root after building. To use it from any project, add it with an absolute path:

```bash
claude mcp add vibesafe -- node /absolute/path/to/Vibesafe/packages/mcp/dist/index.js
```

**Claude Desktop** — add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "vibesafe": {
      "command": "node",
      "args": ["/absolute/path/to/Vibesafe/packages/mcp/dist/index.js"]
    }
  }
}
```

> [!WARNING]
> Scan results include text taken from the scanned repository (file names, code snippets, comments). Treat tool output as untrusted data, not as instructions.

### 🔌 VS Code Extension

Prefer working entirely within your editor? Install the **VibeSafe** extension!

1. Search for **VibeSafe by Talal Jaber** (`talaljaber.vibeguard-scanner`) in the VS Code Extensions marketplace and click Install.
2. Open the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`).
3. Run **`VibeSafe: Scan Project`**.
4. View issues in the sidebar and as inline diagnostics, hover a finding for its explanation and AI fix prompt, and apply safe auto-fixes from quick fixes.

The extension applies a JSON config file but never runs script configs. Settings: `vibesafe.enabledCategories`, `vibesafe.minSeverity`, `vibesafe.scanOnOpen`, `vibesafe.scanOnSave`, `vibesafe.focusProblemsOnScan` (see the [extension README](packages/vscode/README.md)).

---

## ⚠️ Known Limitations

VibeSafe is in early release and is meant to catch the most common "vibe-coding" mistakes. Please be aware of the following:

- **Rule Engine Scope:** Detectors are heuristic (regex and light structural analysis). Cross-file data flow tracking is not implemented, so some findings can be false positives or misses.
- **Frameworks:** Best coverage is for Next.js, Vite and Express. Django support covers settings, view authentication and Python manifests, using line-based heuristics (no Python AST); auth applied by custom middleware or in other modules is not always seen, and other Python frameworks (Flask, FastAPI) are not covered. Rate limiting does not see CDN/WAF limits, Next.js server actions, NextAuth, or Hono/Fastify/Koa.
- **Auto-fixes:** Only three rules have auto-fixes. Review the preview before applying, since a fix can still touch code you meant to keep.
- **Performance:** Scanning very large monorepos with hundreds of thousands of lines of code may take longer than expected. We are actively working on performance optimizations.

---

## 🗺️ Roadmap

- [x] Config file, SARIF and markdown output, watch mode, batch and interactive fixes, GitHub Action.
- [x] Security configuration checks: CORS, security headers, rate limiting, Supabase Row Level Security.
- [x] Django scanning ([#19](https://github.com/Talaljaber/Vibesafe/issues/19)): project detection, settings (including HTTPS/HSTS), `csrf_exempt`, view authentication and offline Python dependency checks.
- [ ] Other Python frameworks (Flask, FastAPI) and Python auto-fixes.
- [ ] More framework-specific rules (Vue, Svelte, Hono, Fastify, Koa).
- [ ] Custom, user-defined rules.
- [ ] **v1.0:** Stable release with comprehensive reporting and enterprise-grade speed.

---

## 🤝 Contributing

We love contributions! Whether it's adding new detectors, fixing bugs, or improving documentation, your help is welcome.

Please see our [Contributing Guide](CONTRIBUTING.md) for details on how to get started.

## 🏗️ Monorepo Structure

This project is structured as a `pnpm` monorepo:

- `packages/core`: The main scanning engine, detectors and fixers (`@talaljaber/vibesafe-core`).
- `packages/shared`: Shared types, constants and finding id helpers (`@talaljaber/vibesafe-shared`).
- `packages/cli`: The command-line interface (`@talaljaber/vibesafe-cli`).
- `packages/mcp`: The stdio MCP server (`@talaljaber/vibesafe-mcp`).
- `packages/vscode`: The Visual Studio Code extension (published as `talaljaber.vibeguard-scanner`).

Package versions are kept aligned with `node scripts/sync-versions.mjs` (see [CONTRIBUTING](CONTRIBUTING.md#6-versioning)).

## 🛠️ Local Development

To run VibeSafe locally:

1. Clone the repository:

   ```bash
   git clone https://github.com/Talaljaber/Vibesafe.git
   cd Vibesafe
   ```

2. Install dependencies using `pnpm`:

   ```bash
   pnpm install
   ```

3. Build all packages:

   ```bash
   pnpm run build
   ```

4. Run the CLI locally:
   ```bash
   pnpm --filter @talaljaber/vibesafe-cli exec vibesafe scan .
   ```

## 📝 License

[MIT](LICENSE)
