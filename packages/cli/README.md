# @talaljaber/vibesafe-cli

The `vibesafe` command line tool: a pre-deploy security scanner for vibe-coded JavaScript and TypeScript apps. It scans a project offline, prints a 0-100 deploy-readiness score, a deploy status (`blocker`, `danger`, `warning` or `safe`) and a prioritized Repair Plan with copy-paste AI fix prompts, and can apply a few safe auto-fixes.

```bash
npx @talaljaber/vibesafe-cli scan .

# or install the `vibesafe` command globally
npm i -g @talaljaber/vibesafe-cli
vibesafe scan . --html
vibesafe fix --all
vibesafe watch
```

Requires Node.js 20 or newer. Releases are published by hand; if this package is not on npm yet, build it from source.

Full documentation, options and the config file format: [github.com/Talaljaber/Vibesafe](https://github.com/Talaljaber/Vibesafe#readme).

## License

[MIT](LICENSE)
