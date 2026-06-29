import { describe, it, expect } from "vitest";
import path from "node:path";
import { ProjectContextBuilder } from "../../src/scanner/project-context.js";

describe("ProjectContextBuilder", () => {
  const fixturePath = path.resolve(__dirname, "../../../../fixtures/nextjs-vibecoded-bad-app");

  it("should detect project context for Next.js fixture", async () => {
    const builder = new ProjectContextBuilder(fixturePath);
    const context = await builder.build();

    expect(context.framework).toBe("nextjs");
    expect(context.language).toBe("typescript");
    expect(context.packageManager).toBe("npm"); // Default fallback since no lockfile is present
    expect(context.hasEnvFile).toBe(true);
    expect(context.hasGitignore).toBe(true);
    expect(context.hasTypeScript).toBe(true);
    expect(context.dependencies["next"]).toBe("14.0.0");
    expect(context.nextjsVersion).toBe("14.0.0");
  });
});
