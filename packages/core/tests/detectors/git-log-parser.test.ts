import { describe, it, expect } from "vitest";
import {
  buildGitEnv,
  buildGitLogArgs,
  parseGitLogOutput,
  unquoteGitPath,
} from "../../src/detectors/utils/git-log-parser";

const M = "\x1eVIBESAFE-COMMIT\x1e";
const S = "\x1f";

function commit(sha: string, body: string): string {
  return `${M}${sha}${S}Ada${S}2024-01-01T00:00:00+00:00${S}subject ${sha}\n\n${body}`;
}

function fileDiff(path: string, lines: string[], header = `+++ b/${path}`): string {
  const adds = lines.map((l) => `+${l}`).join("\n");
  return [
    `diff --git a/${path} b/${path}`,
    "new file mode 100644",
    "index 0000000..1111111",
    "--- /dev/null",
    header,
    `@@ -0,0 +1,${lines.length} @@`,
    adds,
    "",
  ].join("\n");
}

describe("parseGitLogOutput", () => {
  it("returns [] for empty output", () => {
    expect(parseGitLogOutput("")).toEqual([]);
  });

  it("parses commit metadata, file and added lines", () => {
    const out = commit("abc123", fileDiff("src/a.ts", ["one", "two"]));
    const hunks = parseGitLogOutput(out);
    expect(hunks).toHaveLength(1);
    expect(hunks[0]).toMatchObject({ sha: "abc123", author: "Ada", file: "src/a.ts" });
    expect(hunks[0]?.addedLines.map((l) => l.line)).toEqual(["one", "two"]);
  });

  it("keeps added lines that start with ++ or +++", () => {
    const out = commit("abc", fileDiff("a.ts", ["++counter;", "++ b/x", "plain"]));
    const hunks = parseGitLogOutput(out);
    expect(hunks[0]?.addedLines.map((l) => l.line)).toEqual(["++counter;", "++ b/x", "plain"]);
  });

  it("handles paths containing ' b/' using the +++ header", () => {
    const out = commit("abc", fileDiff("dir b/file.ts", ["x"]));
    expect(parseGitLogOutput(out)[0]?.file).toBe("dir b/file.ts");
  });

  it("strips the trailing tab git adds for paths with spaces", () => {
    const out = commit("abc", fileDiff("my file.ts", ["x"], "+++ b/my file.ts\t"));
    expect(parseGitLogOutput(out)[0]?.file).toBe("my file.ts");
  });

  it("unquotes quoted paths", () => {
    const out = commit("abc", fileDiff("x", ["k"], '+++ "b/caf\\303\\251 \\"q\\".ts"'));
    expect(parseGitLogOutput(out)[0]?.file).toBe('café "q".ts');
    expect(unquoteGitPath('"a\\tb"')).toBe("a\tb");
    expect(unquoteGitPath("plain")).toBe("plain");
  });

  it("splits hunks per commit and per file", () => {
    const out =
      commit("c2", fileDiff("a.ts", ["a2"]) + fileDiff("b.ts", ["b2"])) +
      "\n" +
      commit("c1", fileDiff("a.ts", ["a1"]));
    const hunks = parseGitLogOutput(out);
    expect(hunks.map((h) => `${h.sha}:${h.file}`)).toEqual(["c2:a.ts", "c2:b.ts", "c1:a.ts"]);
  });

  it("ignores removed and context lines", () => {
    const diff = [
      "diff --git a/a.ts b/a.ts",
      "index 1..2 100644",
      "--- a/a.ts",
      "+++ b/a.ts",
      "@@ -1,2 +1,2 @@",
      " context",
      "-old",
      "+new",
      "",
    ].join("\n");
    const hunks = parseGitLogOutput(commit("abc", diff));
    expect(hunks[0]?.addedLines.map((l) => l.line)).toEqual(["new"]);
  });
});

describe("git invocation hardening", () => {
  it("passes hardened args to git log", () => {
    const args = buildGitLogArgs(10);
    expect(args).toContain("--no-textconv");
    expect(args).toContain("--no-ext-diff");
    for (const pair of ["core.fsmonitor=false", "core.pager=cat", "diff.external="]) {
      const i = args.indexOf(pair);
      expect(i).toBeGreaterThan(0);
      expect(args[i - 1]).toBe("-c");
    }
    expect(args.indexOf("log")).toBeGreaterThan(args.indexOf("diff.external="));
    expect(args).toContain("--max-count=10");
  });

  it("sets a hardened environment and inherits the rest", () => {
    const env = buildGitEnv({ FOO: "bar" });
    expect(env.GIT_CONFIG_NOSYSTEM).toBe("1");
    expect(env.GIT_TERMINAL_PROMPT).toBe("0");
    expect(env.FOO).toBe("bar");
  });
});
