import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createDefaultFixRegistry } from "@vibesafe/core";
import type { ScanState } from "../state.js";

export const fixInputShape = {
  findingId: z.string().describe("The finding ID to fix, from the most recent vibesafe_scan."),
  dryRun: z
    .boolean()
    .default(true)
    .describe(
      "When true (the default), preview the fix without modifying any files. Set to false to actually apply it.",
    ),
};

export function registerFixTool(server: McpServer, state: ScanState): void {
  server.registerTool(
    "vibesafe_fix",
    {
      title: "Apply or preview an automatic fix",
      description:
        "Applies a mechanical auto-fix for a finding from the most recent vibesafe_scan. Defaults to " +
        "dryRun: true, which previews the change without touching any files — call again with dryRun: false " +
        "to actually apply it. Not every finding has an auto-fix; check autoFixAvailable via vibesafe_explain.",
      inputSchema: fixInputShape,
    },
    async ({ findingId, dryRun }) => {
      if (!state.result || !state.rootPath) {
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
                "and may be stale. Call vibesafe_scan again to refresh.",
            },
          ],
        };
      }

      if (!finding.autoFixAvailable) {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text:
                `No auto-fix is available for "${finding.title}" (${finding.ruleId}). ` +
                "Follow the manual fix steps from vibesafe_explain instead.",
            },
          ],
        };
      }

      const fixRegistry = createDefaultFixRegistry();
      const fixer = fixRegistry.getFixer(finding.ruleId);
      if (!fixer || !fixer.canFix(finding)) {
        return {
          isError: true,
          content: [{ type: "text", text: `No registered fixer can handle rule "${finding.ruleId}".` }],
        };
      }

      if (dryRun) {
        const preview = await fixer.preview(finding, state.rootPath);
        const lines: string[] = ["Dry run — no files were modified.", "", preview.description];

        if (preview.filesToCreate.length > 0) {
          lines.push("", "Files that would be created:", ...preview.filesToCreate.map((f) => `  + ${f}`));
        }
        if (preview.filesToModify.length > 0) {
          lines.push("", "Files that would be modified:", ...preview.filesToModify.map((f) => `  ~ ${f}`));
        }
        if (preview.diff) {
          lines.push("", "Diff:", preview.diff);
        }
        lines.push("", "Call vibesafe_fix again with dryRun: false to apply this change.");

        return {
          content: [
            { type: "text", text: lines.join("\n") },
            { type: "text", text: JSON.stringify(preview, null, 2) },
          ],
        };
      }

      const result = await fixer.apply(finding, state.rootPath);
      const text = result.success
        ? `Fix applied: ${result.message}\n` +
          `Files modified: ${result.filesModified.join(", ") || "none"}\n` +
          `Files created: ${result.filesCreated.join(", ") || "none"}\n\n` +
          "Call vibesafe_scan again to verify the finding is resolved."
        : `Fix failed: ${result.message}${result.error ? `\n${result.error}` : ""}`;

      return {
        isError: !result.success,
        content: [
          { type: "text", text },
          { type: "text", text: JSON.stringify(result, null, 2) },
        ],
      };
    },
  );
}
