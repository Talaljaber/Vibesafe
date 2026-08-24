import path from "node:path";
import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { ScannerPipeline, createDefaultRegistry } from "@vibesafe/core";
import type { FindingCategory, Severity } from "@vibesafe/shared";
import type { ScanState } from "../state.js";
import { setScanResult } from "../state.js";
import { formatScanSummaryText, summarizeScanResult } from "../format.js";

const SEVERITIES = ["critical", "high", "medium", "low"] as const;
const CATEGORIES = [
  "secret",
  "auth",
  "authorization",
  "frontend_exposure",
  "validation",
  "dependency",
  "code_quality",
  "structure",
] as const;

export const scanInputShape = {
  path: z.string().describe("Directory to scan. Absolute, or relative to the MCP server's working directory."),
  minSeverity: z
    .enum(SEVERITIES)
    .optional()
    .describe("Only include findings at or above this severity (critical > high > medium > low)."),
  category: z
    .enum(CATEGORIES)
    .optional()
    .describe("Restrict the scan to a single finding category instead of running all detectors."),
};

export function registerScanTool(server: McpServer, state: ScanState): void {
  server.registerTool(
    "vibesafe_scan",
    {
      title: "Scan a project for vibe-coding issues",
      description:
        "Scans a project directory for security, quality, and structural issues (leaked secrets, missing auth, " +
        "exposed env vars, etc). Returns a summarized report — score, deploy status, severity counts, and the " +
        "top 10 findings. Call vibesafe_explain with a finding ID for full detail, or vibesafe_repair_plan for " +
        "the prioritized fix order.",
      inputSchema: scanInputShape,
    },
    async ({ path: targetPath, minSeverity, category }) => {
      const rootPath = path.resolve(process.cwd(), targetPath);

      let result;
      try {
        const registry = createDefaultRegistry();
        const pipeline = new ScannerPipeline(registry);
        // NOTE: no onProgress callback — the CLI's progress reporting writes
        // to stdout, which would corrupt the stdio JSON-RPC stream.
        result = await pipeline.scan({
          rootPath,
          minSeverity: minSeverity as Severity | undefined,
          enabledCategories: category ? ([category] as FindingCategory[]) : undefined,
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.error(`[vibesafe_scan] scan failed for ${rootPath}: ${message}`);
        return {
          isError: true,
          content: [{ type: "text", text: `Scan failed: ${message}` }],
        };
      }

      setScanResult(state, rootPath, result);

      const summary = summarizeScanResult(result);
      const text = formatScanSummaryText(summary);

      return {
        content: [
          { type: "text", text },
          { type: "text", text: JSON.stringify(summary, null, 2) },
        ],
      };
    },
  );
}
