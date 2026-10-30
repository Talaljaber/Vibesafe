# Changelog

All notable changes to VibeSafe will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Scaffold the `@talaljaber/vibesafe-attack` package (types, API stubs, network chokepoint lint rule and test) for Attack Mode.
- Add the Attack Mode self-contained HTML report with the precision ledger and retest before/after view.

### Changed

### Fixed

### Security

## [0.5.0] - 2026-10-30

Harborline hardening. This release adds a third benchmark, Harborline, a multi-language monorepo whose 151-issue answer key came from three independent AI reviews, and closes many of the gaps it exposed: Python, shell, Terraform, Kubernetes, Firebase and Supabase config, cookies and uploads. Measured on main at 8d61453: on Harborline the strict catch rate went from 44/151 (0.4.0) to 78/151. The internal shopsaas benchmark stays at 66/70 strict. On the blind holdout app it went from 52/90 to 56/90 strict, with the decoy hits unchanged at 4/18. Everything below is static, offline analysis; the only network access is the opt-in `--online` flag (OSV advisories and, new in this release, the package-existence check on the npm and PyPI registries).

### Added

- **Python** (#122)
  - New request-taint tracking for Python (Django, DRF and Flask sources, bounded per function) behind `injection/python-shell-command`, `python-sql-interpolation`, `python-unsafe-yaml-load`, `python-unsafe-deserialization`, `python-xxe-parser` and `python-path-traversal`.
  - Celery configured with the pickle serializer (`security_config/celery-pickle-serializer`).
- **Terraform and Kubernetes** (#126): `*.tf`, `*.tfvars` and Kubernetes manifests are now discovered and scanned.
  - Credentials: `secret/terraform-literal-credential`, `secret/k8s-secret-manifest` (the decoded value is never shown) and `secret/k8s-configmap-credential`.
  - Terraform: `security_config/tf-public-s3-acl`, `tf-s3-public-access-unblocked`, `tf-s3-public-policy`, `tf-db-publicly-accessible`, `tf-open-ingress`, `tf-iam-wildcard-policy`, `tf-oidc-wildcard-subject`, `tf-storage-unencrypted`, `tf-cloudfront-allows-http`, `tf-mutable-image-tags`.
  - Kubernetes: `security_config/k8s-privileged-container`, `k8s-host-namespace`, `k8s-host-path-mount`, `k8s-runs-as-root`, `k8s-cluster-admin-binding`, `k8s-wildcard-rbac`, `k8s-debug-enabled`, `k8s-ingress-plain-http`, `k8s-mutable-image-tag`.
- **Shell scripts** (#125)
  - Remote content passed to `eval` and SQL built from script arguments (`injection/shell-eval-remote-content`, `injection/shell-sql-interpolation`).
  - Pipes of remote scripts into a shell and public cloud uploads (`security_config/shell-remote-script-pipe`, `security_config/shell-public-cloud-upload`).
- **Authentication** (#124)
  - `auth/jwt-decode-without-verify` (unverified token claims gating access), `auth/auth-disabled-outside-production` (auth middleware skipped by an env check), `auth/secret-check-fails-open` (`if (SECRET && x !== SECRET)`) and `auth/unprotected-queue-dashboard` (Bull Board, Arena or Agendash mounted without auth).
- **Firebase rules** (#129): Firestore, Cloud Storage and Realtime Database rules files (`firestore*.rules`, `storage*.rules`, `database.rules.json`, and the files named in `firebase.json`) are now scanned: `authorization/firebase-rules-public-write`, `firebase-rules-public-read`, `firebase-rules-any-signed-in`, `firebase-rules-test-mode`.
- **Supabase config** (#130): `supabase/config.toml` auth settings: `security_config/supabase-email-confirm-off`, `supabase-weak-password`, `supabase-signup-no-captcha`, `supabase-password-change-unsafe`, `supabase-long-jwt-expiry`, `supabase-email-change-unconfirmed`. Untouched `supabase init` defaults stay silent unless the file drives a deployed project.
- **Cookies and CSRF** (#131): session cookies without `HttpOnly` or `Secure`, or with `SameSite=None`, and Express apps that use cookie sessions without CSRF protection (`security_config/session-cookie-no-httponly`, `session-cookie-not-secure`, `session-cookie-samesite-none`, `csrf-cookie-session-unprotected`).
- **File uploads** (#128): `validation/upload-no-size-limit`, `validation/upload-no-type-check` and `validation/upload-unsafe-filename` for multer, busboy, express-fileupload, formidable and Next.js handlers writing to S3, Supabase Storage, GCS and Vercel Blob.
- **Code evaluation** (#123): `injection/code-eval-from-parameter` for exported functions whose parameter reaches `eval`, `new Function` or `vm`.
- **Dependencies** (#132): with `--online`, each direct npm and PyPI dependency is checked against its registry: `dependency/package-not-found` (made-up, removed or placeholder packages) and `dependency/package-very-new` (published under 30 days ago with almost no use). Only package names are sent; requests are bounded and failures become warnings, never findings. Offline scans are unchanged.

### Changed

- Supply-chain severity (#125): an install script that downloads and runs remote code (`curl | sh`, `sh -c "$(curl ...)"`, `npx -y <url>`) is now critical (`dependency/risky-install-script`, same finding id), and a transposed, doubled or dropped letter of a top package name is a high-severity typosquat.
- File discovery now includes Terraform (`.tf`, `.tfvars`), Kubernetes manifests, Firebase rules files and `supabase/config.toml` (#126, #129, #130); `vibesafe watch` re-scans on changes to them.
- The `--online` help, CLI notice and MCP `online` option now name both uses: OSV advisories and the npm and PyPI existence check (#132).
- All packages share one version, 0.5.0.

### Fixed

- Git history scans (#133): the `git` availability and root probes now allow 30 s instead of 5 s and 10 s, so `--deep` no longer silently skips history on a loaded machine.
- Injection sinks hidden behind TypeScript generic type arguments, bare project query wrappers (`query`, `execute`, `*Query`) and queue job payloads (bullmq, bull, agenda, pg-boss and others) are now found (#123).
- Removed the `.github/workflows` files so the root `action.yml` can be listed on GitHub Marketplace; the local gate is the CI (#133).

## [0.4.0] - 2026-10-30

Detection hardening (epic #106). On the internal shopsaas benchmark the strict catch rate went from 18/70 to 66/70 (67/70 lenient). On a blind holdout app that no implementing agent saw, it went from 13/90 to 52/90 strict (22/90 to 58/90 lenient), with the decoy hits unchanged at 4/18. Engine time on shopsaas with `--deep` is about 0.6 s. Everything below is static, offline analysis; the only network access is the opt-in `--online` flag.

### Added

- **Infrastructure** (`security_config`)
  - Dockerfile: `security_config/docker-runs-as-root`, `docker-unpinned-base-image`, `docker-secret-in-env`, `docker-copy-without-dockerignore`.
  - docker-compose: `security_config/compose-db-port-exposed`, `compose-default-db-password`, `compose-privileged-service`.
  - GitHub workflows: `security_config/gha-pull-request-target-checkout`, `gha-unpinned-action`, `gha-write-all-permissions`.
  - Shell scripts: `security_config/shell-curl-pipe-sh`, `shell-hardcoded-credential`.
  - Next.js config: `security_config/nextjs-browser-source-maps`, `nextjs-ignore-build-errors`, `nextjs-image-wildcard-host`.
  - Error responses that leak stack traces or internals (`security_config/error-stack-leak`).
- **Injection** (new `injection` category): untrusted input reaching an interpreter or sink, with taint tracking from request input.
  - SQL: `injection/sql-built-from-input`, `injection/sql-built-from-parameter`, `injection/postgrest-filter-interpolation`. Parameterized queries stay clean.
  - SSRF (`injection/ssrf-user-controlled-url`), path traversal (`injection/path-traversal`), code execution (`injection/dynamic-code-eval`), command execution (`injection/command-exec-interpolation`) and open redirects (`injection/open-redirect`).
  - GitHub Actions script injection (`injection/gha-script-injection`).
- **Client code**
  - Dynamic code and open redirects in the browser (`injection/client-dynamic-code`, `injection/client-open-redirect`).
  - `javascript:` hrefs (`xss/javascript-url-href`) and `postMessage` listeners without an origin check (`xss/postmessage-no-origin-check`).
  - Secrets in `localStorage`/`sessionStorage` and sensitive data in `console.log` (`frontend_exposure/secret-in-web-storage`, `frontend_exposure/sensitive-data-console-log`).
  - Role checks that only run in the client (`authorization/client-side-role-check`).
- **Authorization and auth**
  - IDOR on unscoped lookups (`authorization/idor-unscoped-lookup`), mass assignment (`authorization/mass-assignment`) and auth checks that run after the write (`authorization/auth-check-after-write`).
  - Hardcoded route secrets and non-constant-time comparisons (`auth/hardcoded-route-secret`, `auth/non-constant-time-compare`).
  - Middleware gaps: cookie-presence-only checks and matchers that skip protected routes (`auth/middleware-cookie-presence-only`, `auth/middleware-matcher-gap`).
- **Crypto** (new `crypto` category)
  - Insecure random tokens (`crypto/insecure-random-token`) and hardcoded secret fallbacks such as `process.env.X || "dev-secret"` (`crypto/hardcoded-secret-fallback`).
  - Plaintext credentials: `crypto/plaintext-api-key-storage`, `crypto/plaintext-seed-password`, `crypto/weak-password-hash`.
  - JWT misuse: `crypto/jwt-algorithm-none`, `crypto/jwt-decode-for-auth`, `crypto/jwt-literal-secret`, `crypto/jwt-verify-without-algorithms`.
- **Supabase** (`authorization`): `authorization/supabase-select-using-true`, `supabase-self-referential-policy`, `supabase-policy-self-promotion`, `supabase-grant-to-anon`, `supabase-security-definer-no-search-path`, `supabase-definer-missing-caller-check`.
- **Dependencies**
  - Offline npm advisories (`dependency/known-vulnerable-version`) and typosquatted package names (`dependency/typosquat-package`).
  - `--online`: opt-in lookup of dependency versions in the OSV advisory database (`dependency/osv-advisory`). It sends package names and versions to `api.osv.dev` and is the only network access VibeSafe has; it is off by default.
- **Tooling and hygiene**
  - Placeholder-only tests (`structure/placeholder-only-tests`) and `.gitignore` files that ignore `.env` but not its variants (`security_config/gitignore-env-variants`).
  - Provider keys, database URLs and admin keys under public env prefixes (extends `frontend_exposure/public-secret-var`) and whole sensitive rows passed from server code to client components (`frontend_exposure/full-row-client-prop`).
  - Check-then-act races (`validation/check-then-act-race`) and prices trusted from the client (`validation/client-trusted-price`).
  - `vibesafe hook claude` prints a Claude Code `PostToolUse` hook that re-scans after each edit (`--write` merges it into `.claude/settings.json`), with an example in `examples/claude-code/`.
- **Engine**
  - Precedence: a specific finding hides the generic one reported for the same problem, so one issue is not reported twice.
  - File kinds: detectors only read the files they apply to (Dockerfiles, compose files, workflows, shell scripts, SQL, route files, client files).
  - `pnpm bench`: a harness that measures a scan against a seeded app and its answer key, with a baseline delta and decoy tracking.

### Changed

- New categories `injection` and `crypto` are available in config `categories`, the MCP `category` filter, reports and the VS Code extension.
- All packages share one version, 0.4.0.

## [0.3.1] - 2026-10-29

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
  - Django views and DRF views that change data without authentication, and DRF write views with `permission_classes = [AllowAny]`; honours `DEFAULT_PERMISSION_CLASSES`, `LoginRequiredMiddleware` and `login_required(...)` in `urls.py` (`auth/django-view-missing-auth`, `auth/django-drf-allow-any`, #104).
  - Django HTTPS and cookie settings: `SECURE_SSL_REDIRECT` off or missing, `SECURE_HSTS_SECONDS` 0 or missing, `SESSION_COOKIE_HTTPONLY = False`, `X_FRAME_OPTIONS = "ALLOW..."` and a malformed `SECURE_PROXY_SSL_HEADER`, in non-dev settings modules only; a value set only inside `if DEBUG:` does not count as configured (`security_config/django-ssl-redirect-*`, `security_config/django-hsts-*`, #104).
  - Offline Python dependency checks for `requirements*.txt`, `requirements/*.txt`, `pyproject.toml` (PEP 621 and Poetry) and `Pipfile`: unpinned security-critical packages and a short static list of end-of-life or insecure versions (`dependency/python-unpinned`, `dependency/python-insecure-version`, #104).
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
- **MCP server (`@talaljaber/vibesafe-mcp`)**: `vibesafe_scan`, `vibesafe_explain`, `vibesafe_repair_plan`, `vibesafe_fix`; `deep` and `includeTests` scan options; `--root` / `VIBESAFE_MCP_ROOTS` and `--allow-fix` / `VIBESAFE_MCP_ALLOW_FIX` server settings.
- **Dashboard**: redesigned HTML report (`--html`) and VS Code dashboard, with screenshots in the README.
- **VS Code**: editor hovers with the problem, why it matters, fix steps and the AI fix prompt; settings, menus, multi-root scans, startup activation, sidebar icon, `.vscodeignore`, `includeTests` default, scan warnings, unit tests, a launch configuration and a webview content security policy.
- Test and fixture paths are excluded from scans by default.
- Repository hygiene: `.gitattributes` (LF), `pnpm format:check` in CI, `scripts/sync-versions.mjs` with `pnpm version:check`, a README rewrite and a canonical repository URL.

### Changed

- Python manifests `requirements*.txt`, `requirements/*.txt` and `Pipfile` are now discovered and watched; Django cookie and CORS allow-all settings inside a top-level `if DEBUG:` block are no longer reported, nor are conditional cookie and HTTPS values such as `False if DEBUG else True` (#104).
- Finding ids are deterministic (`PREFIX-<10 hex>`) and the `CATEGORY_PREFIX` map is authoritative.
- Secret severity is per pattern; frontend exposure follows imports and supports all public env prefixes; auth, authorization and validation detectors are more precise about routes, middleware and line numbers.
- Dependency and error-boundary detectors use the root `package.json`; the git history scan streams its output and works from subdirectories.
- Evidence is sanitized and truncated in every detector.
- The error-boundary rule was renamed and dead code and exports were cleaned up.
- All packages share one version (0.3.1), kept in sync by `scripts/sync-versions.mjs`. 0.3.1 is the first complete npm release under `@talaljaber/vibesafe-*`; `@talaljaber/vibesafe-core@0.3.0` never left npm staging, so 0.3.0 of the CLI and MCP server cannot be installed.
- GitHub Action: the build installs only the CLI and its workspace dependencies (`--config.dedupe-peer-dependents=false`) and caches its private pnpm store with `actions/cache`, keyed on the action's lockfile, pnpm version, OS and architecture; `packageManager` pins pnpm with its sha512 hash; a `uses: ./` self-test workflow runs the action on Ubuntu, Windows and macOS; CI reads the pnpm version from `packageManager` (#100).
- `scan` prints the deep-scan notice when the config file turns on `deep`, not only for `--deep` (#99).
- CI pins its third-party actions to full commit SHAs.
- The npm packages moved to the `@talaljaber` scope, because the `@vibesafe` scope on npm belongs to someone else: `@vibesafe/shared`, `@vibesafe/core`, `@vibesafe/cli` and `@vibesafe/mcp` are now `@talaljaber/vibesafe-shared`, `@talaljaber/vibesafe-core`, `@talaljaber/vibesafe-cli` and `@talaljaber/vibesafe-mcp` (#101). The `vibesafe` and `vibesafe-mcp` commands and the VS Code extension id are unchanged. The packages are publish-ready (public access, only `dist` plus a README and LICENSE in the tarball, repository links) and the README documents `npx @talaljaber/vibesafe-cli` and `npx @talaljaber/vibesafe-mcp`; releases are published by hand.

### Fixed

- Django settings continued with a backslash or written as multi-line triple-quoted strings (for example a multi-line `SECRET_KEY`) are now checked (#104).
- Auth and validation checks no longer flag signature-verified Stripe webhook routes (Next.js and Express); an Express route is exempt only with route-level Stripe evidence, so other webhook routes in the same file stay covered (#95, #98).
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
- The GitHub Action runs the CLI from the action's own source rather than an npm package the project does not publish (`@vibesafe/cli` on npm belongs to an unrelated package, #96). Its build ignores the scanned repository's npm config, uses the action's lockfile and skips dependency install scripts.
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
