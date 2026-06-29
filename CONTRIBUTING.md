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
   git clone https://github.com/talaljaber/vibesafe.git
   cd vibesafe
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

At this point, you should switch back to your master branch and make sure it's up to date with VibeSafe's master branch:

Then push your branch to GitHub and create a Pull Request against the main `vibesafe` repository.

## 6. Keeping it Honest

VibeSafe is currently in its v0.1 stage. We aim to keep our documentation and claims honest. When adding features, do not overhype them. Be transparent about known limitations!
