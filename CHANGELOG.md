# Changelog

All notable changes to VibeSafe will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
