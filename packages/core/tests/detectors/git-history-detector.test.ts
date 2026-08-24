import { describe, it, expect, afterEach } from "vitest";
import { execFileSync } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { GitHistoryDetector } from "../../src/detectors/git-history-detector";
import type { ScanContext, ScanConfig } from "@vibesafe/shared";

// Assembled at runtime so this file never itself contains a literal matching a
// secret-scanning pattern, while still producing a value that the OpenAI rule
// in SECRET_PATTERNS ("sk-" + 48 alphanumerics) matches.
const FAKE_OPENAI_KEY = "sk-" + "1234567890".repeat(5).slice(0, 48).padEnd(48, "0");

function run(cwd: string, args: string[]) {
  execFileSync("git", args, { cwd, stdio: "pipe" });
}

function initRepo(dir: string) {
  run(dir, ["init", "--quiet"]);
  run(dir, ["config", "user.email", "test@vibesafe.local"]);
  run(dir, ["config", "user.name", "VibeSafe Test"]);
  run(dir, ["config", "commit.gpgsign", "false"]);
}

function commitAll(dir: string, message: string) {
  run(dir, ["add", "-A"]);
  run(dir, ["commit", "--quiet", "-m", message]);
}

async function makeTempRepo(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "vibesafe-git-hist-"));
  initRepo(dir);
  return dir;
}

function createContext(rootPath: string, files: string[], deep: boolean): ScanContext {
  const config: ScanConfig = { rootPath, deep } as ScanConfig;
  return {
    rootPath,
    projectContext: {} as any,
    files,
    config,
    readFile: async (relativePath: string) => {
      try {
        return await fs.readFile(path.join(rootPath, relativePath), "utf-8");
      } catch {
        return "";
      }
    },
  };
}

describe("GitHistoryDetector", () => {
  const detector = new GitHistoryDetector();
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it("flags a secret that was committed and then deleted as critical/recoverable", async () => {
    const dir = await makeTempRepo();
    tempDirs.push(dir);

    await fs.writeFile(path.join(dir, "config.ts"), `const key = "${FAKE_OPENAI_KEY}";\n`);
    commitAll(dir, "add key");

    await fs.writeFile(path.join(dir, "config.ts"), `const key = "removed";\n`);
    commitAll(dir, "remove key");

    const context = createContext(dir, ["config.ts"], true);
    const findings = await detector.detect(context);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("critical");
    expect(findings[0]?.title.toLowerCase()).toContain("recoverable");
    expect(findings[0]?.autoFixAvailable).toBe(false);
    expect(findings[0]?.category).toBe("secret");
  });

  it("flags a secret still present in the working tree as high, not critical", async () => {
    const dir = await makeTempRepo();
    tempDirs.push(dir);

    await fs.writeFile(path.join(dir, "config.ts"), `const key = "${FAKE_OPENAI_KEY}";\n`);
    commitAll(dir, "add key");

    const context = createContext(dir, ["config.ts"], true);
    const findings = await detector.detect(context);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("high");
  });

  it("dedupes the same secret across many commits into exactly one finding", async () => {
    const dir = await makeTempRepo();
    tempDirs.push(dir);

    for (let i = 0; i < 10; i++) {
      await fs.writeFile(
        path.join(dir, "config.ts"),
        `const key = "${FAKE_OPENAI_KEY}"; // revision ${i}\n`,
      );
      commitAll(dir, `revision ${i}`);
    }
    // Delete it on the 11th commit so we exercise the "recoverable" path too.
    await fs.writeFile(path.join(dir, "config.ts"), `const key = "gone";\n`);
    commitAll(dir, "remove key");

    const context = createContext(dir, ["config.ts"], true);
    const findings = await detector.detect(context);

    expect(findings).toHaveLength(1);
  });

  it("returns [] without throwing for a directory that is not a git repo", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "vibesafe-not-git-"));
    tempDirs.push(dir);
    await fs.writeFile(path.join(dir, "config.ts"), `const key = "${FAKE_OPENAI_KEY}";\n`);

    const context = createContext(dir, ["config.ts"], true);
    const findings = await detector.detect(context);

    expect(findings).toEqual([]);
  });

  it("returns [] and never spawns git when deep is not true", async () => {
    const dir = await makeTempRepo();
    tempDirs.push(dir);
    await fs.writeFile(path.join(dir, "config.ts"), `const key = "${FAKE_OPENAI_KEY}";\n`);
    commitAll(dir, "add key");

    const context = createContext(dir, ["config.ts"], false);
    const findings = await detector.detect(context);

    expect(findings).toEqual([]);
  });

  it("never leaks the raw secret value into the serialized finding", async () => {
    const dir = await makeTempRepo();
    tempDirs.push(dir);

    await fs.writeFile(path.join(dir, "config.ts"), `const key = "${FAKE_OPENAI_KEY}";\n`);
    commitAll(dir, "add key");
    await fs.writeFile(path.join(dir, "config.ts"), `const key = "removed";\n`);
    commitAll(dir, "remove key");

    const context = createContext(dir, ["config.ts"], true);
    const findings = await detector.detect(context);

    expect(findings.length).toBeGreaterThan(0);
    const serialized = JSON.stringify(findings);
    expect(serialized).not.toContain(FAKE_OPENAI_KEY);
    // Sanity: the redacted evidence should still carry a recognizable prefix.
    expect(findings[0]?.evidence).toContain("sk-1");
  });
});
