# @talaljaber/vibesafe-core

The VibeSafe scanning engine: file discovery, detectors, scoring, the Repair Plan and safe auto-fixes. It powers the [`@talaljaber/vibesafe-cli`](https://www.npmjs.com/package/@talaljaber/vibesafe-cli) command line tool, the [`@talaljaber/vibesafe-mcp`](https://www.npmjs.com/package/@talaljaber/vibesafe-mcp) server and the VS Code extension.

```ts
import { ScannerPipeline, createDefaultRegistry, defineConfig } from "@talaljaber/vibesafe-core";
```

`defineConfig` types a `.vibesafe.config.ts` file. Most users want the CLI instead of this package.

Full documentation: [github.com/Talaljaber/Vibesafe](https://github.com/Talaljaber/Vibesafe#readme).

## License

[MIT](LICENSE)
