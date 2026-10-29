# @talaljaber/vibesafe-mcp

A stdio [Model Context Protocol](https://modelcontextprotocol.io) server that lets AI assistants (Claude Code, Claude Desktop, ...) run VibeSafe scans. It provides the `vibesafe_scan`, `vibesafe_explain`, `vibesafe_repair_plan` and `vibesafe_fix` tools.

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

By default scans are limited to the server's working directory and `vibesafe_fix` only previews changes. Use `--root <dir>` / `VIBESAFE_MCP_ROOTS` and `--allow-fix` / `VIBESAFE_MCP_ALLOW_FIX=1` to change that.

Requires Node.js 20 or newer. Releases are published by hand; if this package is not on npm yet, build it from source.

Full documentation: [github.com/Talaljaber/Vibesafe](https://github.com/Talaljaber/Vibesafe#readme).

## License

[MIT](LICENSE)
