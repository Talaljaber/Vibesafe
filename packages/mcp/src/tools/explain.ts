import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ScanState } from "../state.js";

export const explainInputShape = {
  findingId: z.string().describe('The finding ID returned by vibesafe_scan (e.g. "SEC-001-a1b2c3").'),
};

export function registerExplainTool(server: McpServer, state: ScanState): void {
  server.registerTool(
    "vibesafe_explain",
    {
      title: "Explain a VibeSafe finding in detail",
      description:
        "Returns the full plain-English explanation, why it matters, ordered fix steps, and an AI-ready fix " +
        "prompt for one finding from the most recent vibesafe_scan. Call vibesafe_scan first.",
      inputSchema: explainInputShape,
    },
    async ({ findingId }) => {
      if (!state.result) {
        return {
          isError: true,
          content: [{ type: "text", text: "No scan has been run yet. Call vibesafe_scan first." }],
        };
      }

      const finding = state.findingsById.get(findingId);
      if (!finding) {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text:
                `Unknown finding ID "${findingId}". Finding IDs are cached from the most recent vibesafe_scan ` +
                "and may be stale if the project has changed since. Call vibesafe_scan again to refresh.",
            },
          ],
        };
      }

      const lines: string[] = [
        `${finding.title} [${finding.severity.toUpperCase()}] — ${finding.category}`,
        finding.file
          ? `Location: ${finding.file}${finding.line ? `:${finding.line}` : ""}`
          : "Location: (project-level)",
        "",
        `Problem: ${finding.plainEnglishProblem}`,
        "",
        `Why it matters: ${finding.whyItMatters}`,
        "",
        "Fix steps:",
        ...finding.fixSteps.map((step, i) => `  ${i + 1}. ${step}`),
      ];

      if (finding.aiFixPrompt) {
        lines.push("", "AI fix prompt (copy-paste to an AI coding agent):", finding.aiFixPrompt);
      }

      lines.push(
        "",
        finding.autoFixAvailable
          ? "VibeSafe can auto-fix this mechanically — call vibesafe_fix with this finding ID."
          : "No mechanical auto-fix is available for this finding; follow the fix steps above manually.",
      );

      return {
        content: [
          { type: "text", text: lines.join("\n") },
          { type: "text", text: JSON.stringify(finding, null, 2) },
        ],
      };
    },
  );
}
