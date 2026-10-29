import { describe, it, expect } from "vitest";
import type { Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { NextjsConfigDetector } from "../../src/detectors/nextjs-config-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const createContext = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake",
  projectContext: {} as ScanContext["projectContext"],
  files: Object.keys(files),
  config: { rootPath: "/fake" },
  readFile: async (f) => files[f] ?? "",
});

const run = async (files: Record<string, string>): Promise<Finding[]> => {
  const findings = await new NextjsConfigDetector().detect(createContext(files));
  expectRubric(findings);
  return findings;
};

const byRule = (findings: Finding[], rule: string): Finding[] =>
  findings.filter((f) => f.ruleId === `security_config/${rule}`);

const BAD = [
  "/** @type {import('next').NextConfig} */",
  "const nextConfig = {",
  "  productionBrowserSourceMaps: true,",
  "  images: {",
  "    remotePatterns: [",
  "      { protocol: 'https', hostname: '**' },",
  "      new URL('https://*/**'),",
  "    ],",
  "  },",
  "  typescript: { ignoreBuildErrors: true },",
  "};",
  "module.exports = nextConfig;",
].join("\n");

const SAFE = [
  "const nextConfig = {",
  "  // productionBrowserSourceMaps: true,",
  "  productionBrowserSourceMaps: false,",
  "  images: {",
  "    remotePatterns: [",
  "      { protocol: 'https', hostname: '**.example.com' },",
  "      { protocol: 'https', hostname: 'cdn.example.com', pathname: '/img/**' },",
  "      new URL('https://assets.example.com/**'),",
  "    ],",
  "  },",
  "  /* typescript: { ignoreBuildErrors: true }, */",
  "  typescript: { ignoreBuildErrors: process.env.CI !== 'true' },",
  "  description: 'hostname: \"**\" is not allowed here',",
  "};",
  "export default nextConfig;",
].join("\n");

describe("NextjsConfigDetector", () => {
  it("flags source maps, wildcard image hosts and ignoreBuildErrors", async () => {
    const findings = await run({ "next.config.js": BAD });
    expect(byRule(findings, "nextjs-browser-source-maps").map((f) => [f.line, f.severity])).toEqual(
      [[3, "medium"]],
    );
    expect(byRule(findings, "nextjs-image-wildcard-host").map((f) => [f.line, f.severity])).toEqual(
      [
        [6, "medium"],
        [7, "medium"],
      ],
    );
    expect(byRule(findings, "nextjs-ignore-build-errors").map((f) => [f.line, f.severity])).toEqual(
      [[10, "low"]],
    );
  });

  it("covers every next.config extension, including .mts and nested apps", async () => {
    for (const file of [
      "next.config.mjs",
      "next.config.ts",
      "next.config.mts",
      "apps/web/next.config.cjs",
    ]) {
      const findings = await run({
        [file]: "export default { productionBrowserSourceMaps: true };\n",
      });
      expect(
        findings.map((f) => f.ruleId),
        file,
      ).toEqual(["security_config/nextjs-browser-source-maps"]);
    }
  });

  it("ignores false values, scoped hosts, comments and strings", async () => {
    expect(await run({ "next.config.mjs": SAFE })).toEqual([]);
  });

  it("ignores other files", async () => {
    expect(
      await run({ "lib/config.ts": BAD, "vite.config.ts": BAD, "docs/next.config.md": BAD }),
    ).toEqual([]);
  });

  it("gives stable ids and never throws", async () => {
    const a = await run({ "next.config.js": BAD });
    const b = await run({ "next.config.js": BAD });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
    await expect(run({ "next.config.js": "`${'*'\n/* " })).resolves.toBeDefined();
  });
});
