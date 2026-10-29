import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { CATEGORY_PREFIX, createFindingId } from "@talaljaber/vibesafe-shared";

export class ErrorBoundaryDetector implements Detector {
  id = "error-boundary-detector";
  name = "Missing Error Boundary Detector";
  category = "structure" as const;
  description = "Detects React applications that do not implement an Error Boundary.";

  async detect(context: ScanContext): Promise<Finding[]> {
    let isReactProject = false;

    // Check package.json for react dependency
    // Prefer the already-parsed project context; otherwise use the root package.json only
    const ctxDeps = {
      ...(context.projectContext?.dependencies ?? {}),
      ...(context.projectContext?.devDependencies ?? {}),
    };
    if (ctxDeps["react"]) {
      isReactProject = true;
    }

    const packageJsonPath = context.files.find((f) => f.replace(/\\/g, "/") === "package.json");

    if (!isReactProject && packageJsonPath) {
      try {
        const raw = await context.readFile(packageJsonPath);
        const pkg = JSON.parse(raw);
        const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
        if (deps["react"]) {
          isReactProject = true;
        }
      } catch {
        // Ignore unparseable package.json
      }
    }

    // Fallback: check if there are any .tsx or .jsx files
    if (!isReactProject) {
      isReactProject = context.files.some((file) => file.endsWith(".tsx") || file.endsWith(".jsx"));
    }

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

    // Next.js app router error boundaries (error.tsx / global-error.tsx) count as boundaries
    let hasErrorBoundary = context.files.some((file) =>
      /(^|\/)app\/(.*\/)?(global-)?error\.(tsx|jsx|js)$/.test(file.replace(/\\/g, "/")),
    );

    for (const file of hasErrorBoundary ? [] : reactFiles) {
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
      // Next.js App Router: boundaries are file conventions (app/error.tsx, app/global-error.tsx),
      // not a component wrapped around the root.
      const posix = (f: string): string => f.replace(/\\/g, "/");
      const appLayout = reactFiles.find((f) =>
        /(^|\/)(src\/)?app\/layout\.(tsx|jsx|js)$/.test(posix(f)),
      );
      const appRouter =
        appLayout !== undefined ||
        reactFiles.some((f) => /(^|\/)(src\/)?app\/(.*\/)?page\.(tsx|jsx|js)$/.test(posix(f)));
      const appDir = appLayout ? posix(appLayout).replace(/layout\.(tsx|jsx|js)$/, "") : "app/";
      findings.push({
        id: createFindingId(CATEGORY_PREFIX.structure, "structure/missing-error-boundary"),
        ruleId: "structure/missing-error-boundary",
        title: "Missing React Error Boundary",
        severity: "medium",
        category: "structure",
        deployBlocking: false,
        confidence: "medium",
        file: appLayout ?? (reactFiles.length > 0 ? reactFiles[0] : "package.json"),
        plainEnglishProblem: appRouter
          ? "Your Next.js App Router app has no `error.tsx` or `global-error.tsx` error boundary."
          : "Your React application does not appear to use an Error Boundary.",
        whyItMatters:
          "Without an Error Boundary, a runtime error can crash the entire React application and show users a blank screen.",
        fixSteps: appRouter
          ? [
              `Create \`${appDir}error.tsx\`: a \`"use client"\` component that receives \`{ error, reset }\`, shows a friendly message and a "Try again" button calling \`reset()\`.`,
              `Create \`${appDir}global-error.tsx\` for errors thrown in the root layout; it replaces the layout, so it must render its own \`<html>\` and \`<body>\`.`,
              "Add nested `error.tsx` files in route segments that need their own fallback, and log the error (for example to your monitoring service) instead of showing its message to users.",
            ]
          : [
              "Create an ErrorBoundary component.",
              "Wrap your application's root component with the ErrorBoundary.",
              "Display a fallback UI when an unexpected error occurs.",
            ],
        autoFixAvailable: false,
        aiFixPrompt: appRouter
          ? 'This Next.js App Router project has no error boundary. Create app/error.tsx as a "use client" component that receives { error, reset }, logs the error, shows a friendly message (not the error text) and a "Try again" button that calls reset(). Also create app/global-error.tsx, which must render its own <html> and <body> because it replaces the root layout. Match the styling already used in the app.'
          : "Generate a reusable React ErrorBoundary component and wrap the application's root component.",
      });
    }
    return findings;
  }
}
