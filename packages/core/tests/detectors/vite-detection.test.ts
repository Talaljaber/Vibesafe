import { describe, it, expect } from "vitest";
import { FrontendExposureDetector } from "../../src/detectors/frontend-exposure-detector";
import { isClientFile } from "../../src/detectors/utils/file-classifier";
import type { ScanContext } from "@vibesafe/shared";

const detector = new FrontendExposureDetector();

const ctx = (files: Record<string, string>, framework: string = "vite"): ScanContext => ({
  rootPath: "/fake/path",
  projectContext: { framework } as never,
  files: Object.keys(files),
  config: {} as never,
  readFile: async (file) => files[file] ?? "",
});

describe("isClientFile in Vite projects", () => {
  const vite = { framework: "vite" as const };
  it("treats src code as client", () => {
    for (const p of ["src/main.tsx", "src/lib/a.ts", "src/x.js", "src/x.jsx", "app/src/main.ts"]) {
      expect(isClientFile(p, "", vite)).toBe(true);
    }
  });
  it("excludes config, server dirs and *.server.* files", () => {
    for (const p of [
      "vite.config.ts",
      "src/vite.config.ts",
      "src/server/db.ts",
      "src/api/users.ts",
      "src/db.server.ts",
      "scripts/build.ts",
      "src/styles.css",
    ]) {
      expect(isClientFile(p, "", vite)).toBe(false);
    }
  });
  it("does not apply Vite rules to other frameworks or without context", () => {
    expect(isClientFile("src/main.tsx", "", { framework: "express" })).toBe(false);
    expect(isClientFile("src/main.tsx", "")).toBe(false);
  });
});

describe("FrontendExposureDetector in Vite projects", () => {
  it("flags a service role key in plain src code of a Vite project", async () => {
    const f = await detector.detect(ctx({ "src/lib/supa.ts": `const k = import.meta.env.SUPABASE_SERVICE_ROLE_KEY;\n` }));
    expect(f.map((x) => x.ruleId)).toContain("frontend_exposure/service-role-key");
  });
  it("does not flag the same code in src/server of a Vite project or in a non-Vite project", async () => {
    expect(await detector.detect(ctx({ "src/server/supa.ts": `const k = process.env.SUPABASE_SERVICE_ROLE_KEY;\n` }))).toHaveLength(0);
    expect(await detector.detect(ctx({ "src/lib/supa.ts": `const k = process.env.SUPABASE_SERVICE_ROLE_KEY;\n` }, "express"))).toHaveLength(0);
  });
  it("follows imports from Vite src files to server-only secrets", async () => {
    const f = await detector.detect(
      ctx({
        "src/main.tsx": `import { db } from "./db";\n`,
        "src/db.ts": `export const db = connect(process.env.DATABASE_PASSWORD);\n`,
      }),
    );
    expect(f.some((x) => x.ruleId === "frontend_exposure/server-env-in-client-import")).toBe(true);
  });
});

describe("vite.config define leaks", () => {
  const rule = "frontend_exposure/vite-define-process-env";
  const run = async (name: string, body: string) => detector.detect(ctx({ [name]: body }));

  it("flags define: { 'process.env': process.env } as critical and blocking", async () => {
    const f = await run(
      "vite.config.ts",
      `import { defineConfig } from "vite";\nexport default defineConfig({\n  define: {\n    "process.env": process.env,\n  },\n});\n`,
    );
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ ruleId: rule, severity: "critical", deployBlocking: true, category: "frontend_exposure", line: 4 });
  });

  it("flags every supported config extension", async () => {
    for (const n of ["vite.config.ts", "vite.config.mts", "vite.config.js", "vite.config.mjs", "vite.config.cjs"]) {
      expect(await run(n, `export default { define: { 'process.env': process.env } };\n`)).toHaveLength(1);
    }
  });

  it("flags JSON.stringify(process.env) and spreads", async () => {
    expect(await run("vite.config.ts", `export default { define: { "process.env": JSON.stringify(process.env) } };`)).toHaveLength(1);
    expect(await run("vite.config.ts", `export default { define: { ...process.env, A: "1" } };`)).toHaveLength(1);
  });

  it("flags nested define and in a non-Vite-framework context (config file is the signal)", async () => {
    const f = await detector.detect(
      ctx({ "apps/web/vite.config.ts": `export default { define: { "process.env": process.env } };` }, "unknown"),
    );
    expect(f).toHaveLength(1);
  });

  it("does not flag safe define usage", async () => {
    const safe = [
      `export default { define: { __APP_VERSION__: JSON.stringify(process.env.npm_package_version) } };`,
      `export default { define: { "process.env.NODE_ENV": JSON.stringify("production") } };`,
      `export default { define: { "process.env": {} } };`,
      `export default { define: { ...process.env.FOO } };`,
      `export default { define: { "process.env": process.env.NODE_ENV } };`,
      `export default { plugins: [], server: { proxy: {} } };\nconst x = process.env;`,
      `// define: { "process.env": process.env }\nexport default {};`,
    ];
    for (const s of safe) expect(await run("vite.config.ts", s)).toHaveLength(0);
  });

  it("does not run the define check on non-config files", async () => {
    expect(await run("src/other.ts", `const c = { define: { "process.env": process.env } };`)).toHaveLength(0);
  });
});
