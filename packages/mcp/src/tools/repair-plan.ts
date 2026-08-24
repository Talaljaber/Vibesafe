import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ScanState } from "../state.js";

export function registerRepairPlanTool(server: McpServer, state: ScanState): void {
  server.registerTool(
    "vibesafe_repair_plan",
    {
      title: "Get the ordered repair plan",
      description:
        "Returns the prioritized, ordered repair plan from the most recent vibesafe_scan, so fixes are applied " +
        "in the right sequence (e.g. rotate a leaked secret before moving the code that used it). Call " +
        "vibesafe_scan first.",
    },
    async () => {
      if (!state.result) {
        return {
          isError: true,
          content: [{ type: "text", text: "No scan has been run yet. Call vibesafe_scan first." }],
        };
      }

      const plan = state.result.repairPlan;
      const lines: string[] = [
        plan.summary,
        "",
        ...plan.steps.map(
          (s) =>
            `${s.order}. [${s.severity.toUpperCase()}] ${s.title} (${s.findingId})` +
            (s.file ? ` — ${s.file}${s.line ? `:${s.line}` : ""}` : ""),
        ),
      ];

      return {
        content: [
          { type: "text", text: lines.join("\n") },
          { type: "text", text: JSON.stringify(plan, null, 2) },
        ],
      };
    },
  );
}
