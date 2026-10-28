import { describe, it, expect } from "vitest";
import fs from "node:fs";
import os from "node:os";
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

describe("ProjectContextBuilder vite.config detection", () => {
  const make = (files: Record<string, string>): string => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vibesafe-vite-"));
    for (const [name, body] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), body);
    return dir;
  };

  it.each(["ts", "mts", "js", "mjs", "cjs"])("detects vite.config.%s as a Vite signal", async (ext) => {
    const dir = make({ "package.json": "{}", [`vite.config.${ext}`]: "export default {};" });
    try {
      expect((await new ProjectContextBuilder(dir).build()).framework).toBe("vite");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("stays unknown without a config or vite dependency", async () => {
    const dir = make({ "package.json": "{}" });
    try {
      expect((await new ProjectContextBuilder(dir).build()).framework).toBe("unknown");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("keeps Next.js when both next and a vite config are present", async () => {
    const dir = make({ "package.json": JSON.stringify({ dependencies: { next: "14.0.0" } }), "vite.config.ts": "" });
    try {
      expect((await new ProjectContextBuilder(dir).build()).framework).toBe("nextjs");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
