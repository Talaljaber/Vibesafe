# Contributing to VibeSafe

First off, thank you for considering contributing to VibeSafe! It's people like you that make VibeSafe such a great tool.

## 1. Where do I go from here?

If you've noticed a bug or have a feature request, make one! It's generally best if you get confirmation of your bug or approval for your feature request this way before starting to code.

## 2. Fork & create a branch

If this is something you think you can fix, then fork VibeSafe and create a branch with a descriptive name.

A good branch name would be (where issue #325 is the ticket you're working on): `fix/325-memory-leak`.

## 3. Local Development

VibeSafe is a monorepo using `pnpm`.

1. Clone the repository:

   ```bash
   git clone https://github.com/Talaljaber/Vibesafe.git
   cd Vibesafe
   ```

2. Install dependencies:

   ```bash
   pnpm install
   ```

3. Build the project:

   ```bash
   pnpm build
   ```

4. Run tests:

   ```bash
   pnpm test
   ```

5. Typecheck the codebase:
   ```bash
   pnpm typecheck
   ```

## 4. Implement your fix or feature

At this point, you're ready to make your changes! Feel free to ask for help; everyone is a beginner at first.

Make sure your changes adhere to the codebase's existing style.

## 5. Make a Pull Request

Before opening the pull request, make sure your branch is up to date with VibeSafe's `main` branch and that the full gate passes:

```bash
pnpm build && pnpm typecheck && pnpm lint && pnpm test && pnpm format:check && pnpm version:check
```

Then push your branch to GitHub and create a Pull Request against `main` in [Talaljaber/Vibesafe](https://github.com/Talaljaber/Vibesafe). Use Conventional Commits with a package scope, for example `feat(core): ...` or `fix(cli): ...`.

## 6. Versioning

All workspace packages (and `VIBESAFE_VERSION` in `@talaljaber/vibesafe-shared`) share one version. Run `node scripts/sync-versions.mjs <version>` to align them (omit the version to use the highest current one) and `pnpm version:check` (same as `node scripts/sync-versions.mjs --check`) to verify.

## 7. Formatting and line endings

The repository uses Prettier and LF line endings (enforced by `.gitattributes`). Run `pnpm format:check` before pushing; `pnpm format` fixes formatting.

If you cloned the repository on Windows before `.gitattributes` was added, files checked out with `core.autocrlf=true` may still have CRLF endings and fail `pnpm format:check`. Check the files out again once after pulling. Commit or stash your work first, because `git reset --hard` discards uncommitted changes:

```bash
git rm --cached -r -q .   # empty the index
git reset --hard          # check the files out again with LF endings
```

## 8. Keeping it Honest

VibeSafe is still pre-1.0. We aim to keep our documentation and claims honest. When adding features, do not overhype them. Be transparent about known limitations!
