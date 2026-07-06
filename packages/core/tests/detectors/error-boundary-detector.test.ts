import { describe, it, expect } from "vitest";
import { ErrorBoundaryDetector } from "../../src/detectors/error-boundary-detector.js";
import type { ScanContext } from "@vibesafe/shared";

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
    expect(findings[0].ruleId).toBe("react/missing-error-boundary");
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
    expect(findings[0].ruleId).toBe("react/missing-error-boundary");
  });
});
