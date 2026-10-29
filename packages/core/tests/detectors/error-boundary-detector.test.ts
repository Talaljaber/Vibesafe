import { describe, it, expect } from "vitest";
import { ErrorBoundaryDetector } from "../../src/detectors/error-boundary-detector.js";
import type { ScanContext } from "@talaljaber/vibesafe-shared";

describe("ErrorBoundaryDetector", () => {
  const detector = new ErrorBoundaryDetector();

  const createContext = (files: Record<string, string>): ScanContext => ({
    rootPath: "/fake/path",
    projectContext: {} as any,
    files: Object.keys(files),
    config: {} as any,
    readFile: async (file) => files[file] || "",
  });

  it("should report missing error boundary", async () => {
    const context = createContext({
      "App.tsx": `
        export default function App() {
          return <div>Hello</div>;
        }
      `,
    });

    const findings = await detector.detect(context);

    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("structure/missing-error-boundary");
  });

  it("should not report when ErrorBoundary exists", async () => {
    const context = createContext({
      "ErrorBoundary.tsx": `
        class ErrorBoundary extends React.Component {
          componentDidCatch() {}
          render() {
            return this.props.children;
          }
        }
      `,
      "App.tsx": `
        export default function App() {
          return <div>Hello</div>;
        }
      `,
    });

    const findings = await detector.detect(context);

    expect(findings).toHaveLength(0);
  });

  it("should not report for non-React project with a package.json", async () => {
    const context = createContext({
      "package.json": JSON.stringify({
        name: "my-backend",
        dependencies: {
          express: "^4.17.1",
        },
      }),
      "server.js": `
        const express = require('express');
        const app = express();
        app.listen(3000);
      `,
    });

    const findings = await detector.detect(context);

    expect(findings).toHaveLength(0);
  });

  it("should report missing error boundary for React project defined in package.json", async () => {
    const context = createContext({
      "package.json": JSON.stringify({
        name: "my-frontend",
        dependencies: {
          react: "^18.2.0",
        },
      }),
      "App.jsx": `
        export default function App() {
          return <div>Hello</div>;
        }
      `,
    });

    const findings = await detector.detect(context);

    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("structure/missing-error-boundary");
  });

  describe("Next.js App Router", () => {
    const layout = `export default function RootLayout({ children }) {
  return <html><body>{children}</body></html>;
}`;

    it("advises app/error.tsx and app/global-error.tsx instead of wrapping a root component", async () => {
      const findings = await detector.detect(
        createContext({
          "app/layout.tsx": layout,
          "app/page.tsx": "export default () => <main />;",
        }),
      );
      expect(findings).toHaveLength(1);
      const f = findings[0]!;
      expect(f.file).toBe("app/layout.tsx");
      expect(f.plainEnglishProblem).toContain("App Router");
      expect(f.fixSteps.join("\n")).toContain("app/error.tsx");
      expect(f.fixSteps.join("\n")).toContain("app/global-error.tsx");
      expect(f.aiFixPrompt).toContain("global-error.tsx");
      expect(f.aiFixPrompt).not.toContain("wrap the application's root component");
    });

    it("uses the src/app directory when the app lives there", async () => {
      const findings = await detector.detect(
        createContext({ "src/app/layout.tsx": layout, "src/app/page.tsx": "x" }),
      );
      expect(findings[0]!.fixSteps[0]).toContain("src/app/error.tsx");
    });

    it("keeps the same finding id as before for a given project shape", async () => {
      const [appRouter] = await detector.detect(createContext({ "app/layout.tsx": layout }));
      const [plain] = await detector.detect(createContext({ "App.tsx": "<div />" }));
      expect(appRouter!.id).toBe(plain!.id);
    });

    it("does not report when app/error.tsx exists", async () => {
      const findings = await detector.detect(
        createContext({ "app/layout.tsx": layout, "app/error.tsx": '"use client";' }),
      );
      expect(findings).toEqual([]);
    });

    it("keeps the component advice for non-Next React apps", async () => {
      const findings = await detector.detect(createContext({ "src/App.tsx": "<div />" }));
      expect(findings[0]!.fixSteps[1]).toContain("Wrap your application's root component");
    });
  });
});
