import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ALL_CATEGORIES, createFindingId, CATEGORY_PREFIX } from "../src/index.js";

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

  it("repository ships .gitattributes forcing LF and a format check script", () => {
    expect(read(".gitattributes")).toMatch(/^\* text=auto eol=lf$/m);
    const root = JSON.parse(read("package.json")) as { scripts: Record<string, string> };
    expect(root.scripts["format:check"]).toBeDefined();
  });

  it("ships no workflow files, so the root action.yml can be listed on GitHub Marketplace", () => {
    expect(fs.existsSync(path.join(repoRoot, ".github/workflows"))).toBe(false);
    expect(fs.existsSync(path.join(repoRoot, "action.yml"))).toBe(true);
  });

  it("README and the example workflow do not pin the GitHub Action to a mutable branch", () => {
    for (const f of ["README.md", "examples/github-action.yml"]) {
      const text = read(f);
      expect(text, f).toContain("Talaljaber/Vibesafe@");
      expect(text, f).not.toMatch(/Talaljaber\/Vibesafe@(main|master)\b/);
    }
  });

  it("the GitHub Action builds the CLI from its own source instead of an npm package", () => {
    const action = read("action.yml");
    // The action runs the pinned source, never a package fetched from npm.
    expect(action).not.toMatch(/\bnpx\b/);
    expect(action).not.toMatch(/\bnpm (exec|install|i)\b/);
    expect(action).not.toMatch(/@vibesafe\/cli/);
    expect(action).not.toContain("@talaljaber/vibesafe-cli@");
    expect(action).toContain("working-directory: ${{ github.action_path }}");
    expect(action).toContain("corepack pnpm install --frozen-lockfile --ignore-scripts");
    expect(action).toContain('--filter "@talaljaber/vibesafe-cli..."');
    expect(action).toContain('"$GITHUB_ACTION_PATH/packages/cli/dist/bin.js"');
    expect(action).toContain("NPM_CONFIG_USERCONFIG=");
    expect(action).toContain("scan --format markdown");
    // The filter and the corepack pnpm version must match the workspace.
    const cli = JSON.parse(read("packages/cli/package.json")) as { name: string };
    expect(cli.name).toBe("@talaljaber/vibesafe-cli");
    const root = JSON.parse(read("package.json")) as { packageManager: string };
    expect(root.packageManager).toMatch(/^pnpm@9\./);
    // Only the CLI and its workspace dependencies are installed (pnpm 9 defaults to true).
    expect(action).toContain("--config.dedupe-peer-dependents=false");
    // Third-party actions are pinned by full commit SHA.
    const uses = [...action.matchAll(/^\s*uses:\s*(\S+)/gm)].map((m) => m[1]!);
    expect(uses.length).toBeGreaterThan(0);
    for (const u of uses) expect(u, u).toMatch(/@[0-9a-f]{40}$/);
    // The old npm version input is accepted but ignored.
    const version = /^ {2}version:\n((?: {4}.*\n)+)/m.exec(action)?.[1] ?? "";
    expect(version).toContain("deprecationMessage:");
    expect(version).not.toContain("default:");
  });

  it("the GitHub Action caches its private pnpm store keyed on its own lockfile", () => {
    const action = read("action.yml");
    const cacheStep = /- name: Cache the VibeSafe pnpm store\n((?: {6}.*\n)+)/.exec(action)?.[1];
    expect(cacheStep, "cache step not found").toBeDefined();
    expect(cacheStep).toMatch(/uses: actions\/cache@[0-9a-f]{40} # v\d+\.\d+\.\d+\n/);
    // The cached path is the --store-dir the build step installs into.
    expect(cacheStep).toContain("path: ${{ runner.temp }}/vibesafe-build/store");
    expect(action).toContain('builddir="$RUNNER_TEMP/vibesafe-build"');
    expect(action).toContain('--store-dir "$builddir/store"');
    // hashFiles() cannot read the action directory when it is outside GITHUB_WORKSPACE,
    // so the key comes from a step that hashes the action's own lockfile.
    expect(action).not.toMatch(/\$\{\{[^}]*hashFiles\(/);
    expect(cacheStep).toContain("key: ${{ steps.cache-key.outputs.key }}");
    const keyStep = /- name: Compute the VibeSafe build cache key\n((?: {6}.*\n)+)/.exec(
      action,
    )?.[1];
    expect(keyStep, "cache key step not found").toBeDefined();
    expect(keyStep).toContain("id: cache-key");
    expect(keyStep).toContain("working-directory: ${{ github.action_path }}");
    expect(keyStep).toContain('readFileSync("pnpm-lock.yaml")');
    expect(keyStep).toContain("${RUNNER_OS}-${RUNNER_ARCH}-${hash}");
    // The cache is restored before the build step installs into it.
    const order = ["Compute the VibeSafe build cache key", "Cache the VibeSafe pnpm store"].map(
      (s) => action.indexOf(`- name: ${s}`),
    );
    const build = action.indexOf("- name: Build VibeSafe from the action source");
    expect(order[0]).toBeGreaterThan(-1);
    expect(order[0]).toBeLessThan(order[1]!);
    expect(order[1]).toBeLessThan(build);
  });

  it("the cache key step hashes the lockfile bytes plus the pinned pnpm version", async () => {
    const action = read("action.yml");
    const script = /node -e '([^']+)'/.exec(action)?.[1];
    expect(script, "node -e hash script not found").toBeDefined();
    const { execFileSync } = await import("node:child_process");
    const { createHash } = await import("node:crypto");
    const out = execFileSync(process.execPath, ["-e", script!], {
      cwd: repoRoot,
      encoding: "utf8",
    });
    const expected = createHash("sha256")
      .update(fs.readFileSync(path.join(repoRoot, "pnpm-lock.yaml")))
      .update(String(JSON.parse(read("package.json")).packageManager))
      .digest("hex");
    expect(out).toBe(expected);
    expect(JSON.parse(read("package.json")).packageManager).toMatch(/^pnpm@/);
  });

  it("packageManager pins pnpm with an integrity hash corepack can verify", () => {
    const root = JSON.parse(read("package.json")) as { packageManager: string };
    // corepack format: <name>@<version>+<algo>.<hex digest of the registry tarball>.
    const m = /^pnpm@(\d+\.\d+\.\d+)\+(sha1|sha224|sha256|sha512)\.([0-9a-f]+)$/.exec(
      root.packageManager,
    );
    expect(m, root.packageManager).not.toBeNull();
    const hexLength = { sha1: 40, sha224: 56, sha256: 64, sha512: 128 }[m![2] as "sha512"];
    expect(m![3]).toHaveLength(hexLength);
  });

  it("CONTRIBUTING renormalizes line endings without the redundant git add step", () => {
    const text = read("CONTRIBUTING.md");
    expect(text).not.toContain("git add --renormalize");
    expect(text).toContain("git rm --cached -r -q .");
    expect(text).toContain("git reset --hard");
    expect(text).toMatch(/Commit or stash your work first/);
  });

  it("CHANGELOG detector entries each name their pull request", () => {
    const cl = read("CHANGELOG.md");
    const start = cl.indexOf("- **Detectors**\n");
    expect(start).toBeGreaterThan(-1);
    const block = cl.slice(start).split("\n").slice(1);
    const bullets = block.slice(
      0,
      block.findIndex((l) => !l.startsWith("  - ")),
    );
    expect(bullets.length).toBeGreaterThan(10);
    for (const b of bullets) expect(b, b).toMatch(/#\d+/);
    // The early contributed detectors each get their own bullet and pull request.
    const refs: Record<string, string> = {
      "xss/dangerously-set-inner-html": "#25",
      "code_quality/hardcoded-localhost": "#21",
      "structure/missing-error-boundary": "#22",
      "secret/git-history-": "#23",
    };
    for (const [rule, ref] of Object.entries(refs)) {
      const hits = bullets.filter((b) => b.includes(rule));
      expect(hits, rule).toHaveLength(1);
      expect(hits[0], rule).toContain(`${ref})`);
      for (const other of Object.keys(refs).filter((r) => r !== rule)) {
        expect(hits[0], `${rule} shares a bullet with ${other}`).not.toContain(other);
      }
    }
  });

  it("docs describe the source-built Action and the npm install under the new scope", () => {
    const readme = read("README.md");
    expect(readme).not.toMatch(/Do not use it until/);
    expect(readme).toContain("builds the CLI from the action's own source");
    expect(readme).toContain("npx @talaljaber/vibesafe-cli scan .");
    expect(readme).toContain("npm i -g @talaljaber/vibesafe-cli");
    expect(readme).toContain("npx -y @talaljaber/vibesafe-mcp");
    // Releases are manual, so the README still points at the source build until one exists.
    expect(readme).toMatch(/published by hand/);
    expect(readme).toMatch(/`@vibesafe` npm scope belong to someone else/);
    const example = read("examples/github-action.yml");
    expect(example).not.toMatch(/^\s*version:/m);
    expect(example).not.toContain("npx");
  });

  it("no file outside the CHANGELOG still uses the old @vibesafe npm scope", async () => {
    const { execFileSync } = await import("node:child_process");
    // Tracked files only: untracked local notes (an agent guide, scratch files) are not repo
    // content and must not turn the local gate red.
    const files = execFileSync("git", ["ls-files", "-z", "--cached"], {
      cwd: repoRoot,
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
    })
      .split("\0")
      .filter((f) => f !== "" && f !== "CHANGELOG.md" && fs.existsSync(path.join(repoRoot, f)))
      .filter((f) => !/\.(png|jpe?g|gif|ico|vsix|tgz)$/i.test(f));
    expect(files.length).toBeGreaterThan(100);
    const oldScope = /@vibesafe\/(?:shared|core|cli|mcp)\b/;
    const offenders = files.filter((f) => oldScope.test(read(f)));
    expect(offenders).toEqual([]);
  });

  it("publishable packages use the @talaljaber scope and pack only their build", () => {
    type Manifest = {
      name: string;
      version: string;
      private?: boolean;
      license?: string;
      files?: string[];
      bin?: Record<string, string>;
      publishConfig?: { access?: string };
      repository?: { url?: string; directory?: string };
      homepage?: string;
      bugs?: { url?: string };
      dependencies?: Record<string, string>;
    };
    const manifest = (dir: string): Manifest =>
      JSON.parse(read(`packages/${dir}/package.json`)) as Manifest;
    const publishable: Record<string, string> = {
      shared: "@talaljaber/vibesafe-shared",
      core: "@talaljaber/vibesafe-core",
      cli: "@talaljaber/vibesafe-cli",
      mcp: "@talaljaber/vibesafe-mcp",
      attack: "@talaljaber/vibesafe-attack",
    };
    const names = new Set(Object.values(publishable));
    expect(read("LICENSE")).toMatch(/^MIT License/);
    for (const [dir, name] of Object.entries(publishable)) {
      const pkg = manifest(dir);
      expect(pkg.name, dir).toBe(name);
      expect(pkg.private, dir).toBeUndefined();
      expect(pkg.publishConfig?.access, dir).toBe("public");
      expect(pkg.license, dir).toBe("MIT");
      expect(read(`packages/${dir}/LICENSE`), dir).toBe(read("LICENSE"));
      expect(fs.existsSync(path.join(repoRoot, `packages/${dir}/README.md`)), dir).toBe(true);
      // Only the build output (plus README and LICENSE) goes into the tarball.
      expect(pkg.files, dir).toContain("dist");
      // Source maps point at ../src, which is not shipped, so they stay out of the tarball.
      expect(pkg.files, dir).toContain("!dist/**/*.map");
      for (const f of pkg.files ?? []) {
        expect(f, dir).toMatch(/^(!?dist(\/.*)?|README\.md|LICENSE)$/);
      }
      expect(pkg.repository?.url, dir).toBe("git+https://github.com/Talaljaber/Vibesafe.git");
      expect(pkg.repository?.directory, dir).toBe(`packages/${dir}`);
      expect(pkg.homepage, dir).toMatch(/^https:\/\/github\.com\/Talaljaber\/Vibesafe\b/);
      expect(pkg.bugs?.url, dir).toBe("https://github.com/Talaljaber/Vibesafe/issues");
      // pnpm pack rewrites workspace:* to the real version, so every workspace dependency must
      // be another publishable package in the same scope.
      for (const [dep, range] of Object.entries(pkg.dependencies ?? {})) {
        if (range.startsWith("workspace:")) expect(names.has(dep), `${dir} -> ${dep}`).toBe(true);
      }
    }
    // Command names stay the same after the rename.
    expect(Object.keys(manifest("cli").bin ?? {})).toEqual(["vibesafe"]);
    expect(Object.keys(manifest("mcp").bin ?? {})).toEqual(["vibesafe-mcp"]);
  });

  it("every CLI and MCP flag in the README exists in the source", () => {
    const sources = ["packages/cli/src", "packages/mcp/src"]
      .flatMap((dir) =>
        fs
          .readdirSync(path.join(repoRoot, dir), { recursive: true, encoding: "utf8" })
          .filter((p) => p.endsWith(".ts"))
          .map((p) => read(path.join(dir, p))),
      )
      .join("\n");
    // Flags that belong to other tools (pnpm, commander's built-in help).
    const external = new Set(["--filter", "--help"]);
    const flags = [...new Set(read("README.md").match(/--[a-z][a-z-]*/g) ?? [])].filter(
      (f) => !external.has(f),
    );
    expect(flags.length).toBeGreaterThan(10);
    for (const flag of flags) expect(sources, flag).toMatch(new RegExp(`${flag}(?![a-z-])`));
  });

  it("README rule ids and detector ids exist in core", () => {
    const dir = path.join(repoRoot, "packages/core/src/detectors");
    const core = fs
      .readdirSync(dir, { recursive: true, encoding: "utf8" })
      .filter((p) => p.endsWith(".ts"))
      .map((p) => fs.readFileSync(path.join(dir, p), "utf8"))
      .join("\n");
    const readme = read("README.md");
    const ruleIds = [
      ...new Set(
        readme.match(
          new RegExp(`\\b(?:${ALL_CATEGORIES.join("|")})\\/[a-z0-9-]*[a-z0-9](?![a-z0-9*-])`, "g"),
        ) ?? [],
      ),
    ];
    expect(ruleIds.length).toBeGreaterThan(20);
    for (const id of ruleIds) {
      const [category, rule] = id.split("/") as [string, string];
      // Pattern-based ids are built from a prefix (`secret/${pattern.id}`, `security_config/cors-${rule}`).
      const known =
        core.includes(`"${id}"`) ||
        core.includes(`id: "${rule}"`) ||
        (rule.startsWith("git-history-") && core.includes(`id: "${rule.slice(12)}"`)) ||
        (category === "security_config" &&
          rule.startsWith("cors-") &&
          core.includes(`"${rule.slice(5)}"`));
      expect(known, id).toBe(true);
    }
    for (const m of readme.matchAll(/`([a-z-]+-detector)`/g)) {
      expect(core, m[1]).toContain(`id = "${m[1]}"`);
    }
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

  it("rejects invalid versions", () => {
    expect(() => sync.syncVersions(tmp, { version: "v1" })).toThrow(/Invalid version/);
    expect(() => sync.syncVersions(tmp, { version: "1.0" })).toThrow(/Invalid version/);
  });
});
