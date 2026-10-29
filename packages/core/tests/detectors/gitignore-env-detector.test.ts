import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { GitignoreEnvDetector } from "../../src/detectors/gitignore-env-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const detector = new GitignoreEnvDetector();

async function run(gitignore: string | null, opts: { deps?: string[]; extra?: string[] } = {}) {
  const files: Record<string, string> = {};
  if (gitignore !== null) files[".gitignore"] = gitignore;
  for (const e of opts.extra ?? []) files[e] = "A=1\n";
  const deps = Object.fromEntries((opts.deps ?? []).map((d) => [d, "1.0.0"]));
  const ctx = {
    rootPath: "/fake",
    projectContext: { dependencies: deps, devDependencies: {} },
    files: Object.keys(files),
    config: { rootPath: "/fake" },
    readFile: async (f: string) => files[f] ?? "",
  } as unknown as ScanContext;
  const findings = await detector.detect(ctx);
  expectRubric(findings);
  return findings;
}

describe("GitignoreEnvDetector", () => {
  it("fires at the .env line with medium severity when a framework is present", async () => {
    const f = await run("node_modules\n.env\n", { deps: ["next"] });
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({
      ruleId: "security_config/gitignore-env-variants",
      file: ".gitignore",
      line: 2,
      severity: "medium",
      autoFixAvailable: true,
    });
  });

  it("stays silent when an unignored variant file exists (env-not-ignored covers it)", async () => {
    const f = await run("node_modules\n.env\n", { deps: ["next"], extra: [".env.local"] });
    expect(f).toHaveLength(0);
  });

  it("handles a root-anchored /.env with vite", async () => {
    const f = await run("/.env\n", { deps: ["vite"] });
    expect(f[0]?.line).toBe(1);
  });

  it("has stable ids across runs", async () => {
    const a = await run(".env\n", { deps: ["next"] });
    const b = await run(".env\n", { deps: ["next"] });
    expect(a[0]?.id).toBe(b[0]?.id);
  });

  it.each([
    ["wildcard", ".env*\n"],
    ["env plus .env*.local", ".env\n.env*.local\n"],
    ["env plus .env.* and negation", ".env\n.env.*\n!.env.example\n"],
    ["env plus *.local", ".env\n*.local\n"],
    ["explicit variants", ".env\n.env.local\n.env.*.local\n"],
    ["no .env line", "node_modules\n.next\n"],
    ["comment only", "# .env\nnode_modules\n"],
  ])("is silent for %s", async (_n, gi) => {
    expect(await run(gi, { deps: ["next"] })).toEqual([]);
  });

  it("is silent without a framework or variant file", async () => {
    expect(await run(".env\n", { deps: ["express"] })).toEqual([]);
  });

  it("is silent when .gitignore is not in the file list", async () => {
    expect(await run(null, { deps: ["next"] })).toEqual([]);
  });
});
