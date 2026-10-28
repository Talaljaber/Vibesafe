#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// VibeSafe MCP server — stdio transport.
//
// ⚠️  THE STDOUT RULE: stdio MCP transport uses stdout exclusively for
// JSON-RPC framing. A single stray console.log corrupts the stream and
// breaks every client connected to this server. All diagnostics in this
// package go to console.error (stderr) — never console.log / process.stdout.
// ─────────────────────────────────────────────────────────────────────────────

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createServer } from "./server.js";

async function main(): Promise<void> {
  const server = await createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error("[vibesafe-mcp] server started, listening on stdio");
}

main().catch((error: unknown) => {
  console.error("[vibesafe-mcp] fatal error:", error);
  process.exit(1);
});
