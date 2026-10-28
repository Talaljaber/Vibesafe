import { createRequire } from "node:module";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createScanState } from "./state.js";
import { defaultPolicy, type ServerPolicy } from "./policy.js";
import { registerScanTool } from "./tools/scan.js";
import { registerExplainTool } from "./tools/explain.js";
import { registerRepairPlanTool } from "./tools/repair-plan.js";
import { registerFixTool } from "./tools/fix.js";

/** Server version, read from this package's package.json (works from src/ and dist/). */
export function readServerVersion(): string {
  try {
    const require = createRequire(import.meta.url);
    const pkg = require("../package.json") as { version?: string };
    return pkg.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

export async function createServer(policy: ServerPolicy = defaultPolicy()): Promise<McpServer> {
  const server = new McpServer({
    name: "vibesafe",
    version: readServerVersion(),
  });

  const state = createScanState();

  registerScanTool(server, state, policy);
  registerExplainTool(server, state);
  registerRepairPlanTool(server, state);
  registerFixTool(server, state, policy);

  return server;
}
