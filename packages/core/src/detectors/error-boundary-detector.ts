import type { Detector, Finding, ScanContext } from "@vibesafe/shared";
import crypto from "crypto";

export class ErrorBoundaryDetector implements Detector {
  id = "error-boundary-detector";
  name = "Missing Error Boundary Detector";
  category = "structure" as const;
  description = "Detects React applications that do not implement an Error Boundary.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const isReactProject =
      context.files.some((file) => file.endsWith(".tsx")) ||
      context.files.some((file) => file === "package.json");

    if (!isReactProject) {
      return [];
    }
    const findings: Finding[] = [];

    const reactFiles = context.files.filter(
      (file) => file.endsWith(".tsx") || file.endsWith(".jsx"),
    );

    if (reactFiles.length === 0) {
      return [];
    }

    let hasErrorBoundary = false;

    for (const file of reactFiles) {
      const content = await context.readFile(file);

      if (
        content.includes("componentDidCatch") ||
        content.includes("getDerivedStateFromError") ||
        content.includes("react-error-boundary") ||
        content.match(/<ErrorBoundary\b/) ||
        content.match(/from\s+['"]react-error-boundary['"]/)
      ) {
        hasErrorBoundary = true;
        break;
      }
    }

    if (!hasErrorBoundary) {
      findings.push({
        id: `ERR-${crypto.randomBytes(3).toString("hex")}`,
        ruleId: "react/missing-error-boundary",
        title: "Missing React Error Boundary",
        severity: "medium",
        category: "structure",
        deployBlocking: false,
        confidence: "medium",
        file: reactFiles.length > 0 ? reactFiles[0] : "package.json",
        plainEnglishProblem: "Your React application does not appear to use an Error Boundary.",
        whyItMatters:
          "Without an Error Boundary, a runtime error can crash the entire React application and show users a blank screen.",
        fixSteps: [
          "Create an ErrorBoundary component.",
          "Wrap your application's root component with the ErrorBoundary.",
          "Display a fallback UI when an unexpected error occurs.",
        ],
        autoFixAvailable: false,
        aiFixPrompt:
          "Generate a reusable React ErrorBoundary component and wrap the application's root component.",
      });
    }
    return findings;
  }
}
