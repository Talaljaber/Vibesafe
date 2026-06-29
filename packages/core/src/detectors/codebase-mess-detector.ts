// ─────────────────────────────────────────────────────────────────────────────
// Codebase Mess Detector
//
// Scans for code quality issues that make a codebase hard to maintain
// or indicative of "vibe coding" run amok.
// ─────────────────────────────────────────────────────────────────────────────

import type { Detector, Finding, ScanContext } from "@vibeguard/shared";
import crypto from "crypto";

const MAX_FILE_LINES = 500;
const MAX_REACT_COMPONENT_LINES = 300;

export class CodebaseMessDetector implements Detector {
  id = "codebase-mess-detector";
  name = "Codebase Mess Detection";
  category = "code_quality" as const;
  description = "Detects overly large files, excessive 'any' usage, leftover console.logs, and empty catch blocks.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    let totalAnyCount = 0;
    
    for (const filePath of context.files) {
      // Only check code files
      if (!filePath.endsWith(".ts") && !filePath.endsWith(".tsx") && !filePath.endsWith(".js") && !filePath.endsWith(".jsx")) {
        continue;
      }

      const content = await context.readFile(filePath);
      const lines = content.split("\n");

      // 1. File size checks
      if (lines.length > MAX_FILE_LINES) {
        findings.push({
          id: `QUAL-${crypto.randomBytes(3).toString("hex")}`,
          ruleId: "code_quality/huge-file",
          title: "Huge file detected",
          severity: "low",
          category: "code_quality",
          deployBlocking: false,
          confidence: "high",
          file: filePath,
          evidence: `${lines.length} lines`,
          plainEnglishProblem: `This file is ${lines.length} lines long, which is very hard to read and maintain.`,
          whyItMatters: "Huge files usually mean a component or function is doing too many things. This leads to bugs and makes it difficult for AI or humans to understand the code.",
          fixSteps: [
            "Break this file down into smaller, focused modules or components.",
            "Move helper functions to a separate `utils.ts` file."
          ],
          autoFixAvailable: false,
          aiFixPrompt: "This file is too large and does too many things. Please refactor it by extracting smaller, reusable components/functions into separate files."
        });
      }

      // Track 'any' usage per file
      const anyMatches = content.match(/\bany\b/g);
      if (anyMatches) {
        totalAnyCount += anyMatches.length;
      }

      // Line-by-line checks
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!line) continue;

        // 2. Empty catch blocks
        if (line.includes("catch") && line.includes("{}") || (line.includes("catch") && lines[i+1]?.trim() === "}")) {
          findings.push({
            id: `QUAL-${crypto.randomBytes(3).toString("hex")}`,
            ruleId: "code_quality/empty-catch",
            title: "Empty catch block",
            severity: "medium",
            category: "code_quality",
            deployBlocking: false,
            confidence: "medium",
            file: filePath,
            line: i + 1,
            evidence: line.trim(),
            plainEnglishProblem: "You are catching an error but doing nothing with it (swallowing the error).",
            whyItMatters: "If this code fails, you will never know. The app might break silently, making it impossible to debug.",
            fixSteps: [
              "Add at least a `console.error(error)` inside the catch block.",
              "If the error is expected, add a comment explaining why it's ignored."
            ],
            autoFixAvailable: false,
            aiFixPrompt: "Please fix this empty catch block by adding proper error logging or handling."
          });
        }

        // 3. console.log leftovers
        if (line.includes("console.log(")) {
          findings.push({
            id: `QUAL-${crypto.randomBytes(3).toString("hex")}`,
            ruleId: "code_quality/console-log",
            title: "Leftover console.log",
            severity: "low",
            category: "code_quality",
            deployBlocking: false,
            confidence: "high",
            file: filePath,
            line: i + 1,
            evidence: line.trim(),
            plainEnglishProblem: "You left a `console.log` statement in your code.",
            whyItMatters: "While harmless, excessive logging in production clutters the console and can occasionally leak sensitive information if you log full objects.",
            fixSteps: ["Remove the `console.log` statement."],
            autoFixAvailable: true,
          });
        }
      }
    }

    // Flag if there are too many 'any's globally (arbitrary threshold for demo: 20)
    if (totalAnyCount > 20) {
      findings.push({
        id: `QUAL-${crypto.randomBytes(3).toString("hex")}`,
        ruleId: "code_quality/excessive-any",
        title: "Excessive use of 'any' types",
        severity: "medium",
        category: "code_quality",
        deployBlocking: false,
        confidence: "high",
        evidence: `${totalAnyCount} uses of 'any' across the project`,
        plainEnglishProblem: `Your project uses the 'any' type ${totalAnyCount} times.`,
        whyItMatters: "Using 'any' defeats the purpose of TypeScript. It hides potential crashes and bugs until your code is running in production.",
        fixSteps: [
          "Define proper TypeScript interfaces for your data.",
          "Use `unknown` instead of `any` if you aren't sure of the type."
        ],
        autoFixAvailable: false,
      });
    }

    return findings;
  }
}
