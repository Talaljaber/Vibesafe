# Changelog

All notable changes to VibeSafe will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Detectors**: insecure CORS configuration, missing helmet / security headers, missing rate limiting on sensitive endpoints, Supabase Row Level Security, Express route auth and validation, Django/Python settings (with `.py` / `.sql` discovery and a `security_config` category), Vite project detection with a `define` `process.env` leak check, Firebase Admin SDK in client code, Stripe webhook signature verification, and broader AWS key detection that ignores placeholders. Also `dangerouslySetInnerHTML` XSS, hardcoded localhost, React error boundary and git history detectors.
- **Config file**: `.vibesafe.config.json` with rule overrides, disabled detectors, excludes, `includeTests`, `minSeverity` and `deep`; script configs only with `--trust-config`.
- **Inline ignores**: `vibesafe-disable-line`, `-next-line` and `-file` directives accept rule ids.
- **CLI**: `--format json|sarif|markdown` with `--output`, `watch`, `fix --all`, `fix --interactive`, `--include-tests`, real scan progress, scan warnings, `--deep` and tests for the CLI.
- **GitHub Action**: composite action that posts a sticky PR comment and fails on `fail-on`.
- **MCP server (`@vibesafe/mcp`)**: `vibesafe_scan`, `vibesafe_explain`, `vibesafe_repair_plan`, `vibesafe_fix`; `deep` and `includeTests` options, `--root` / `--allow-fix` server arguments.
- **VS Code**: settings, menus, multi-root scans, startup activation, sidebar icon, `.vscodeignore`, `includeTests` default, unit tests, launch configuration and a webview content security policy.
- Test and fixture paths are excluded from scans by default.
- Repository hygiene: `.gitattributes` (LF), `pnpm format:check` in CI, `scripts/sync-versions.mjs`, README rewrite and a canonical repository URL.

### Changed

- Finding ids are deterministic (`PREFIX-<10 hex>`) and the `CATEGORY_PREFIX` map is authoritative.
- Secret severity is per pattern; frontend exposure follows imports and supports all public env prefixes; auth, authorization and validation detectors are more precise about routes, middleware and line numbers.
- Dependency and error-boundary detectors use the root `package.json`; the git history scan streams its output and works from subdirectories.
- Evidence is sanitized and truncated in every detector.
- The error-boundary rule was renamed and dead code and exports were cleaned up.

### Fixed

- Scan timeout is enforced, lines are counted correctly and truncation produces a warning.
- `fix --yes` and non-TTY handling, `--version`, and `targetFiles` handling in the VS Code extension.
- The console.log fixer only comments out standalone statements; `.env.example` generation no longer copies secrets.
- Reduced false positives in the error-boundary, localhost, HTML and codebase-mess detectors.
- CI passes on a clean checkout.
- Documentation: monorepo structure, marketplace id and repository and screenshot links.

### Security

- Fixer target paths are validated to stay inside the project root.
- Trusted commands in VS Code hover markdown are restricted.
- MCP scans are limited to allowed roots and file writes are opt-in.
- Git is run with a hardened configuration during history scans.
- Detector evidence is redacted so secrets are not echoed in reports.

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
