# Changelog

All notable changes to VibeSafe will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Detectors**
  - New `security_config` category; `.py` and `.sql` files are now discovered (#77).
  - Insecure CORS configuration: reflected origins without an allowlist, wildcard origins with credentials, any-origin `cors()` in cookie-based apps and `Access-Control-Allow-Origin: *` (`security_config/cors-*`, #78).
  - Firebase Admin SDK imported in client code (`frontend_exposure/firebase-admin`, #79). Thanks to @i-am-paradox.
  - Vite project detection and Vite `define` blocks that leak `process.env` into the bundle (`frontend_exposure/vite-define-process-env`, #80).
  - AWS secret access keys, with placeholder filtering for AWS keys (`secret/sec-aws-secret-key`, #83).
  - Missing rate limiting on auth, AI/LLM and email/SMS endpoints in Next.js route handlers and Express (`security_config/missing-rate-limit`, #84).
  - Express routes in the auth and validation detectors (`auth/missing-route-auth`, `validation/missing-body-validation`, #85).
  - Stripe webhook handlers that skip signature verification or parse the body first (`auth/stripe-webhook-unsigned`, `auth/stripe-webhook-parsed-body`, #86). Thanks to @i-am-paradox.
  - Express apps without helmet and Next.js apps without security headers (`security_config/missing-helmet`, `security_config/missing-security-headers`, #87).
  - Supabase tables without Row Level Security and policies that let everyone write (`authorization/supabase-missing-rls`, `authorization/supabase-permissive-policy`, #89).
  - Django/Python MVP: Django project detection, Python test discovery and insecure Django settings (`DEBUG`, `SECRET_KEY`, `ALLOWED_HOSTS`, CORS, cookies, `csrf_exempt`) (`security_config/django-*`, `secret/django-secret-key*`, #92).
  - `dangerouslySetInnerHTML` with dynamic content (`xss/dangerously-set-inner-html`, #25). Thanks to @i-am-paradox.
  - Hardcoded localhost URLs (`code_quality/hardcoded-localhost`, #21). Thanks to @AlexMnrs.
  - Missing React error boundary (`structure/missing-error-boundary`, #22). Thanks to @kamakshi-mehta.
  - Git history secret scan with `--deep` (`secret/git-history-*`, #23).
- **Config file** (#81): `.vibesafe.config.json` / `vibesafe.config.json` with rule overrides (exact ids or globs, `"off"` or a severity), `disabledDetectors`, `categories`, `exclude`, `includeTests`, `minSeverity` and `deep`. It applies to `scan`, `fix`, `fix --all`, `fix -i` and `watch`. Script configs (`.ts`, `.js`, ...) are ignored unless `--trust-config` is passed; `--no-config` ignores the file. Applied configs and suppressed findings are reported as scan warnings.
- **CLI**
  - `scan --format json|sarif|markdown` and `--output <file>` (#90, #91). SARIF 2.1.0 works with GitHub code scanning; markdown is a PR-comment summary.
  - `fix --all` previews and applies every auto-fix after one confirmation (#82).
  - `fix -i` interactive fix wizard; `scan -i` offers it after a scan (#93).
  - `watch` re-scans on file changes and prints what got better or worse, with `--json` NDJSON events (#88).
  - `--deep` / `--no-deep`, `--include-tests` / `--no-include-tests`, `--no-config`, `--trust-config`, real scan progress and scan warnings.
- **GitHub Action** (#91): composite `action.yml` that posts or updates one sticky PR comment and the job summary, and fails the job by `fail-on`; usage example in `examples/github-action.yml`. The action builds the CLI from its own source at the pinned ref and runs that build; the `version` input is deprecated and ignored.
- **Inline ignores**: `vibesafe-disable-line`, `-next-line` and `-file` directives accept comma-separated rule ids.
- **MCP server (`@vibesafe/mcp`)**: `vibesafe_scan`, `vibesafe_explain`, `vibesafe_repair_plan`, `vibesafe_fix`; `deep` and `includeTests` scan options; `--root` / `VIBESAFE_MCP_ROOTS` and `--allow-fix` / `VIBESAFE_MCP_ALLOW_FIX` server settings.
- **Dashboard**: redesigned HTML report (`--html`) and VS Code dashboard, with screenshots in the README.
- **VS Code**: editor hovers with the problem, why it matters, fix steps and the AI fix prompt; settings, menus, multi-root scans, startup activation, sidebar icon, `.vscodeignore`, `includeTests` default, scan warnings, unit tests, a launch configuration and a webview content security policy.
- Test and fixture paths are excluded from scans by default.
- Repository hygiene: `.gitattributes` (LF), `pnpm format:check` in CI, `scripts/sync-versions.mjs` with `pnpm version:check`, a README rewrite and a canonical repository URL.

### Changed

- Finding ids are deterministic (`PREFIX-<10 hex>`) and the `CATEGORY_PREFIX` map is authoritative.
- Secret severity is per pattern; frontend exposure follows imports and supports all public env prefixes; auth, authorization and validation detectors are more precise about routes, middleware and line numbers.
- Dependency and error-boundary detectors use the root `package.json`; the git history scan streams its output and works from subdirectories.
- Evidence is sanitized and truncated in every detector.
- The error-boundary rule was renamed and dead code and exports were cleaned up.
- All packages share one version (0.3.0), kept in sync by `scripts/sync-versions.mjs`.
- GitHub Action: the build installs only the CLI and its workspace dependencies (`--config.dedupe-peer-dependents=false`) and caches its private pnpm store with `actions/cache`, keyed on the action's lockfile, OS and architecture; `packageManager` pins pnpm with its sha512 hash; a `uses: ./` self-test workflow runs the action on Ubuntu, Windows and macOS; CI reads the pnpm version from `packageManager` (#97).

### Fixed

- Scan timeout is enforced, lines are counted correctly and truncation produces a warning.
- `fix --yes` and non-TTY handling, `--version`, and `targetFiles` handling in the VS Code extension.
- The console.log fixer only comments out standalone statements; `.env.example` generation no longer copies secrets.
- Reduced false positives in the error-boundary, localhost, HTML and codebase-mess detectors.
- CI passes on a clean checkout.
- Documentation: monorepo structure, marketplace id (`talaljaber.vibeguard-scanner`), repository and screenshot links, install instructions.

### Security

- Fixer target paths are validated to stay inside the project root.
- Trusted commands in VS Code hover markdown are restricted.
- MCP scans are limited to allowed roots and file writes are opt-in.
- Git is run with a hardened configuration during history scans.
- The GitHub Action runs the CLI from the action's own source rather than an npm package the project does not publish (`@vibesafe/cli` on npm belongs to an unrelated package). Its build ignores the scanned repository's npm config, uses the action's lockfile and skips dependency install scripts.
- Detector evidence is redacted so secrets are not echoed in reports.
- Script config files are not executed unless explicitly trusted; the MCP server and VS Code extension never execute them.

## [0.1.0] - 2026-06-29

### Added

- **Core Engine**: Deterministic static analysis pipeline.
- **Detectors**:
  - `SecretDetector`: Finds leaked API keys (OpenAI, Anthropic, Stripe, AWS, Supabase, JWTs).
  - `FrontendExposureDetector`: Identifies server-side secrets exposed to the client.
  - `MissingAuthDetector`: Flags unprotected Next.js API routes.
  - `MissingAuthorizationDetector`: Highlights authenticated routes missing role/permission checks.
  - `MissingValidationDetector`: Spots raw request body usage without validation (e.g. Zod).
  - `DependencyDetector`: Analyzes dependencies and suspicious install scripts.
  - `CodebaseMessDetector`: Catches code smells like large files, massive components, or excessive `any` usage.
  - `ProjectStructureDetector`: Checks for missing standard files like `.env.example`, `.gitignore`, and `README.md`.
- **Scoring & Repair Plan**: Dynamic scoring of deploy readiness (0-100) and an automated repair plan prioritizing security fixes.
- **Auto-Fixes**: Safe auto-fixes for `.gitignore` inclusion, `.env.example` creation, and `console.log` removal.
- **CLI (`@vibesafe/cli`)**: Terminal output, HTML dashboard generation, and quick fix prompts.
- **VS Code Extension**: Sidebar UI, inline diagnostics, and quick-fix context menus.

### Changed

- Standardized the monorepo structure utilizing `pnpm` and `Turborepo`.
- Shared constants and models moved to `@vibesafe/shared`.

### Security

- Introduced regex and AST-level checks for the most common security pitfalls made during vibe coding.
