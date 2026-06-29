// ─────────────────────────────────────────────────────────────────────────────
// Project Structure Detector
//
// Scans the overall shape of the project for missing standard files
// like .gitignore, README, or tests.
// ─────────────────────────────────────────────────────────────────────────────

import type { Detector, Finding, ScanContext } from "@vibeguard/shared";
import crypto from "crypto";

export class ProjectStructureDetector implements Detector {
  id = "project-structure-detector";
  name = "Project Structure Detection";
  category = "structure" as const;
  description = "Detects missing standard files like .gitignore, README.md, or a test directory.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // 1. Missing .gitignore
    if (!context.projectContext.hasGitignore) {
      findings.push({
        id: `STRUCT-${crypto.randomBytes(3).toString("hex")}`,
        ruleId: "structure/missing-gitignore",
        title: "Missing .gitignore file",
        severity: "high",
        category: "structure",
        deployBlocking: false,
        confidence: "high",
        plainEnglishProblem: "Your project doesn't have a `.gitignore` file.",
        whyItMatters: "Without a .gitignore, you will accidentally commit node_modules, build files, and sensitive environment variables to your git repository.",
        fixSteps: [
          "Create a file named `.gitignore` in the root of your project.",
          "Add `node_modules`, `.env`, and your build output folders to it."
        ],
        autoFixAvailable: false,
      });
    }

    // 2. Missing README
    if (!context.projectContext.hasReadme) {
      findings.push({
        id: `STRUCT-${crypto.randomBytes(3).toString("hex")}`,
        ruleId: "structure/missing-readme",
        title: "Missing README.md",
        severity: "low",
        category: "structure",
        deployBlocking: false,
        confidence: "high",
        plainEnglishProblem: "There is no README.md file in the root of your project.",
        whyItMatters: "A README explains what your project does and how to run it. Without it, other developers (and future you) will struggle to understand the codebase.",
        fixSteps: [
          "Create a `README.md` file.",
          "Add a title, description, and instructions on how to install and run the project."
        ],
        autoFixAvailable: false,
        aiFixPrompt: "Please write a comprehensive README.md for this project based on the code provided."
      });
    }

    // 3. No tests
    if (!context.projectContext.hasTests) {
      findings.push({
        id: `STRUCT-${crypto.randomBytes(3).toString("hex")}`,
        ruleId: "structure/missing-tests",
        title: "No tests found",
        severity: "low",
        category: "structure",
        deployBlocking: false,
        confidence: "low", // It's possible tests exist in a way we didn't detect
        plainEnglishProblem: "We couldn't find any test files in your project.",
        whyItMatters: "Shipping code without tests means you rely entirely on manual clicking to verify things work. This guarantees bugs will slip into production as your app grows.",
        fixSteps: [
          "Install a test runner like Vitest or Jest.",
          "Create a `tests/` directory or add `.test.ts` files next to your components."
        ],
        autoFixAvailable: false,
      });
    }

    return findings;
  }
}
