import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createFindingId, CATEGORY_PREFIX } from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "../../..");
const read = (rel: string): string => fs.readFileSync(path.join(repoRoot, rel), "utf8");

const sync = (await import("../../../scripts/sync-versions.mjs")) as {
  syncVersions: (
    root: string,
    opts?: { version?: string; check?: boolean },
  ) => { target: string; mismatched: unknown[]; changed: string[] };
  collectVersions: (root: string) => Array<{ name: string; version: string }>;
  compare: (a: string, b: string) => number;
};

describe("docs hygiene", () => {
  const docs = ["README.md", "CONTRIBUTING.md", "packages/vscode/README.md"];

  it("uses one canonical repository URL", () => {
    for (const f of docs.concat("packages/vscode/package.json")) {
      const text = read(f);
      expect(text, f).not.toMatch(/github\.com\/talaljaber\//);
      expect(text, f).not.toMatch(/Vibeguard\//);
    }
    expect(read("README.md")).toContain("https://github.com/Talaljaber/Vibesafe");
  });

  it("uses the real marketplace id", () => {
    for (const f of ["README.md", "packages/vscode/README.md"]) {
      const text = read(f);
      expect(text, f).not.toContain("talaljaber.vibesafe");
      expect(text, f).toContain("talaljaber.vibeguard-scanner");
    }
    const pkg = JSON.parse(read("packages/vscode/package.json")) as {
      name: string;
      publisher: string;
    };
    expect(`${pkg.publisher}.${pkg.name}`).toBe("talaljaber.vibeguard-scanner");
  });

  it("screenshots in the root README are repo-relative and exist", () => {
    const srcs = [...read("README.md").matchAll(/<img src="([^"]+)"/g)].map((m) => m[1]!);
    const screenshots = srcs.filter((s) => s.endsWith(".png"));
    expect(screenshots.length).toBeGreaterThan(0);
    for (const s of screenshots) {
      expect(s.startsWith("http"), s).toBe(false);
      expect(fs.existsSync(path.join(repoRoot, s)), s).toBe(true);
    }
  });

  it("marketplace README screenshots point at the real repo and existing files", () => {
    const text = read("packages/vscode/README.md");
    const urls = [
      ...text.matchAll(/raw\.githubusercontent\.com\/Talaljaber\/Vibesafe\/main\/([^"]+\.png)/g),
    ];
    expect(urls.length).toBeGreaterThan(0);
    for (const m of urls) expect(fs.existsSync(path.join(repoRoot, m[1]!)), m[1]).toBe(true);
  });

  it("README lists every workspace package", () => {
    const readme = read("README.md");
    for (const dir of fs.readdirSync(path.join(repoRoot, "packages"))) {
      expect(readme, dir).toContain(`packages/${dir}`);
    }
  });

  it("CHANGELOG has an Unreleased section with all four headings", () => {
    const cl = read("CHANGELOG.md");
    const start = cl.indexOf("## [Unreleased]");
    expect(start).toBeGreaterThan(-1);
    const next = cl.indexOf("\n## [", start + 1);
    const unreleased = cl.slice(start, next === -1 ? undefined : next);
    expect(unreleased.length).toBeGreaterThan(0);
    for (const h of ["### Added", "### Changed", "### Fixed", "### Security"]) {
      expect(unreleased, h).toContain(h);
    }
  });

  it("example finding ids match the real id format", () => {
    const id = createFindingId(CATEGORY_PREFIX.secret, "secret/x", "a.ts", 1);
    expect(id).toMatch(/^SEC-[0-9a-f]{10}$/);
    const src = read("packages/mcp/src/tools/explain.ts");
    const example = /e\.g\. "([A-Z]+-[^"]+)"/.exec(src)?.[1];
    expect(example, "example id not found in explain.ts").toBeDefined();
    expect(example).toMatch(/^[A-Z]+-[0-9a-f]{10}$/);
    expect(src).not.toContain("SEC-001");
  });

  it("repository ships .gitattributes forcing LF and CI checks formatting", () => {
    expect(read(".gitattributes")).toMatch(/^\* text=auto eol=lf$/m);
    expect(read(".github/workflows/ci.yml")).toContain("pnpm format:check");
  });
});

describe("sync-versions", () => {
  let tmp: string;
  const write = (rel: string, content: string): void => {
    const f = path.join(tmp, rel);
    fs.mkdirSync(path.dirname(f), { recursive: true });
    fs.writeFileSync(f, content);
  };
  const pkg = (name: string, version: string): string =>
    JSON.stringify({ name, version }, null, 2) + "\n";

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vs-sync-"));
    write("packages/a/package.json", pkg("a", "0.1.5"));
    write("packages/b/package.json", pkg("b", "0.1.0"));
    write("packages/shared/package.json", pkg("shared", "0.1.6"));
    write("packages/shared/src/constants.ts", 'export const VIBESAFE_VERSION = "0.1.5";\n');
  });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it("--check reports mismatches without writing", () => {
    const r = sync.syncVersions(tmp, { check: true });
    expect(r.target).toBe("0.1.6");
    expect(r.mismatched).toHaveLength(3);
    expect(r.changed).toHaveLength(0);
    expect(fs.readFileSync(path.join(tmp, "packages/b/package.json"), "utf8")).toContain("0.1.0");
  });

  it("aligns packages and the constant to the highest version by default", () => {
    const r = sync.syncVersions(tmp);
    expect(r.changed).toHaveLength(3);
    for (const e of sync.collectVersions(tmp)) expect(e.version).toBe("0.1.6");
    expect(sync.syncVersions(tmp, { check: true }).mismatched).toHaveLength(0);
  });

  it("aligns to an explicit version and preserves other fields", () => {
    sync.syncVersions(tmp, { version: "1.0.0" });
    const json = JSON.parse(fs.readFileSync(path.join(tmp, "packages/a/package.json"), "utf8"));
    expect(json).toEqual({ name: "a", version: "1.0.0" });
    expect(fs.readFileSync(path.join(tmp, "packages/shared/src/constants.ts"), "utf8")).toContain(
      '"1.0.0"',
    );
  });

  it("treats a stable release as higher than its prerelease", () => {
    expect(sync.compare("1.0.0", "1.0.0-rc.1")).toBeGreaterThan(0);
    expect(sync.compare("1.0.0-rc.1", "1.0.0")).toBeLessThan(0);
    expect(sync.compare("1.0.0-rc.2", "1.0.0-rc.10")).toBeLessThan(0);
    expect(sync.compare("1.0.0-alpha", "1.0.0-alpha.1")).toBeLessThan(0);
    expect(sync.compare("1.0.1-rc.1", "1.0.0")).toBeGreaterThan(0);
    write("packages/c/package.json", pkg("c", "0.1.6-rc.1"));
    expect(sync.syncVersions(tmp, { check: true }).target).toBe("0.1.6");
  });

  it("rejects a package.json without a version", () => {
    write("packages/nov/package.json", JSON.stringify({ name: "nov" }));
    expect(() => sync.syncVersions(tmp, { check: true })).toThrow(/Missing "version"/);
  });

  it("works without a constants file", () => {
    fs.rmSync(path.join(tmp, "packages/shared/src"), { recursive: true });
    expect(sync.collectVersions(tmp).map((e) => e.name)).not.toContain("VIBESAFE_VERSION");
  });

  it("README does not pin the GitHub Action to a mutable branch", () => {
    expect(read("README.md")).not.toMatch(/Talaljaber\/Vibesafe@(main|master)/);
  });

  it("rejects invalid versions", () => {
    expect(() => sync.syncVersions(tmp, { version: "v1" })).toThrow(/Invalid version/);
    expect(() => sync.syncVersions(tmp, { version: "1.0" })).toThrow(/Invalid version/);
  });
});
