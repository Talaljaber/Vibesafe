#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// VibeSafe MCP server — stdio transport.
//
// ⚠️  THE STDOUT RULE: stdio MCP transport uses stdout exclusively for
// JSON-RPC framing. A single stray console.log corrupts the stream and
// breaks every client connected to this server. All diagnostics in this
// package go to console.error (stderr) — never console.log / process.stdout.
// ─────────────────────────────────────────────────────────────────────────────

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createScanState } from "./state.js";
import { registerScanTool } from "./tools/scan.js";
import { registerExplainTool } from "./tools/explain.js";
import { registerRepairPlanTool } from "./tools/repair-plan.js";
import { registerFixTool } from "./tools/fix.js";

export async function createServer(): Promise<McpServer> {
  const server = new McpServer({
    name: "vibesafe",
    version: "0.1.0",
  });

  const state = createScanState();

  registerScanTool(server, state);
  registerExplainTool(server, state);
  registerRepairPlanTool(server, state);
  registerFixTool(server, state);

  return server;
}

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
