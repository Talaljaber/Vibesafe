import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const repoRoot = path.resolve(import.meta.dirname, "..", "..", "..");
const script = path.join(repoRoot, "scripts", "create-attack-demo.mjs");
const overlayRoot = path.join(repoRoot, "fixtures", "attack-demo-app-fixed");

function run(args: string[]) {
  return spawnSync(process.execPath, [script, ...args], { encoding: "utf-8" });
}

function git(cwd: string, args: string[]): string {
  return execFileSync("git", args, { cwd, encoding: "utf-8" }).trim();
}

function listFiles(dir: string, base = dir): string[] {
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...listFiles(full, base));
    else out.push(path.relative(base, full).split(path.sep).join("/"));
  }
  return out;
}

describe("scripts/create-attack-demo.mjs", () => {
  let sandbox: string;
  let outDir: string;

  beforeAll(() => {
    sandbox = fs.mkdtempSync(path.join(os.tmpdir(), "vs-attack-demo-test-"));
    outDir = path.join(sandbox, "demo", "app");
    const res = run([outDir]);
    expect(res.status, res.stderr).toBe(0);
  });

  afterAll(() => {
    fs.rmSync(sandbox, { recursive: true, force: true });
  });

  it("creates main (vulnerable) and fixed branches, ending on main", () => {
    const branches = git(outDir, ["branch", "--format=%(refname:short)"]).split("\n").sort();
    expect(branches).toEqual(["fixed", "main"]);
    expect(git(outDir, ["rev-parse", "--abbrev-ref", "HEAD"])).toBe("main");
    expect(git(outDir, ["log", "-1", "--format=%s", "main"])).toBe("vulnerable demo");
    expect(git(outDir, ["status", "--porcelain"])).toBe("");
  });

  it("fixed differs from main exactly by the overlay files", () => {
    const changed = git(outDir, ["diff", "--name-only", "main", "fixed"]).split("\n").sort();
    expect(changed).toEqual(listFiles(overlayRoot).sort());

    const mainNotes = git(outDir, ["show", "main:app/api/notes/[id]/route.js"]);
    const fixedNotes = git(outDir, ["show", "fixed:app/api/notes/[id]/route.js"]);
    expect(mainNotes).not.toContain("user_id");
    expect(fixedNotes).toContain('.eq("user_id", session.userId)');
  });

  it("copies the app (dotfiles, booth package.json) and writes the demo CLAUDE.md", () => {
    for (const f of [
      "server.mjs",
      "package.json",
      "public/.env",
      ".vibesafe/sessions.json",
      "app/api/invoices/[id]/route.js",
    ]) {
      expect(fs.existsSync(path.join(outDir, f)), f).toBe(true);
    }
    const claude = fs.readFileSync(path.join(outDir, "CLAUDE.md"), "utf-8");
    expect(claude).toContain(".vibesafe/attack-report.md");
    expect(claude).toContain("Do not run vibesafe attack yourself");
    expect(claude.toLowerCase()).not.toContain("deliberately insecure");
    // CLAUDE.md is part of the vulnerable commit on both branches
    expect(git(outDir, ["show", "main:CLAUDE.md"])).toBe(claude.trim());
    expect(git(outDir, ["show", "fixed:CLAUDE.md"])).toBe(claude.trim());
  });

  it("writes nothing outside outDir", () => {
    expect(fs.readdirSync(sandbox)).toEqual(["demo"]);
    expect(fs.readdirSync(path.join(sandbox, "demo"))).toEqual(["app"]);
  });

  it("refuses a non-empty existing outDir and leaves it untouched", () => {
    const res = run([outDir]);
    expect(res.status).not.toBe(0);
    expect(res.stderr).toContain("refusing");

    const other = path.join(sandbox, "occupied");
    fs.mkdirSync(other);
    fs.writeFileSync(path.join(other, "keep.txt"), "keep");
    expect(run([other]).status).not.toBe(0);
    expect(fs.readdirSync(other)).toEqual(["keep.txt"]);
  });

  it("accepts an existing empty outDir", () => {
    const empty = path.join(sandbox, "empty");
    fs.mkdirSync(empty);
    expect(run([empty]).status).toBe(0);
    expect(fs.existsSync(path.join(empty, ".git"))).toBe(true);
  });

  it("--harness-only copies the app without git or CLAUDE.md", () => {
    const dir = path.join(sandbox, "harness");
    expect(run([dir, "--harness-only"]).status).toBe(0);
    expect(fs.existsSync(path.join(dir, "server.mjs"))).toBe(true);
    expect(fs.existsSync(path.join(dir, ".git"))).toBe(false);
    expect(fs.existsSync(path.join(dir, "CLAUDE.md"))).toBe(false);
  });
});
