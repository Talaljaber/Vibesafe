import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import path from "node:path";
import type { Finding, ScanResult } from "@vibesafe/shared";

const scanMock = vi.hoisted(() => vi.fn());

vi.mock("@vibesafe/core", () => ({
  createDefaultRegistry: () => ({}),
  ScannerPipeline: class {
    scan = scanMock;
  },
}));
vi.mock("../src/ui/printer.js", () => ({ printScanResult: vi.fn(async () => {}) }));

import {
  formatMarkdownReport,
  escapeMarkdown,
  PR_COMMENT_MARKER,
} from "../src/ui/markdown-reporter.js";
import { runScan } from "../src/commands/scan.js";
import { shouldPrintBanner } from "../src/ui/format-args.js";

function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: "SEC-1",
    ruleId: "secret/x",
    title: "Hardcoded key",
    severity: "high",
    category: "secrets",
    deployBlocking: false,
    confidence: "high",
    file: "src/a.ts",
    line: 3,
    plainEnglishProblem: "A key is in your code.",
    whyItMatters: "Anyone can use it.",
    fixSteps: ["Move it to an env var"],
    autoFixAvailable: false,
    ...over,
  } as Finding;
}

function result(findings: Finding[], over: Partial<ScanResult> = {}): ScanResult {
  const count = (s: string) => findings.filter((f) => f.severity === s).length;
  return {
    timestamp: "t",
    projectPath: "/p",
    findings,
    score: 72,
    deployStatus: "safe",
    summary: {
      totalFindings: findings.length,
      criticalCount: count("critical"),
      highCount: count("high"),
      mediumCount: count("medium"),
      lowCount: count("low"),
      categoryCounts: {},
      filesScanned: 12,
      linesScanned: 100,
    },
    repairPlan: { steps: [] },
    durationMs: 1,
    ...over,
  } as unknown as ScanResult;
}

describe("formatMarkdownReport", () => {
  it("starts with the sticky marker and a machine-readable status", () => {
    const md = formatMarkdownReport(result([finding()], { deployStatus: "danger" }));
    expect(md.startsWith(PR_COMMENT_MARKER)).toBe(true);
    expect(md).toContain("<!-- vibesafe-status:danger -->");
  });

  it("shows score, status and counts", () => {
    const md = formatMarkdownReport(
      result([finding({ severity: "critical" }), finding({ severity: "low" })], {
        deployStatus: "blocker",
        score: 15,
      }),
    );
    expect(md).toContain("**Score:** 15/100");
    expect(md).toContain("Blocker");
    expect(md).toContain("| 1 | 0 | 0 | 1 | 2 |");
    expect(md).toContain("12 files scanned");
  });

  it("lists findings with file:line, most severe first, in a collapsed section", () => {
    const md = formatMarkdownReport(
      result([
        finding({ severity: "low", title: "Low thing", file: "z.ts", line: 9 }),
        finding({ severity: "critical", title: "Crit thing", file: "a.ts", line: 1 }),
      ]),
    );
    expect(md.indexOf("Crit thing")).toBeLessThan(md.indexOf("Low thing"));
    expect(md).toContain("`a.ts:1`");
    expect(md).toContain("<details>");
    expect(md).toContain("</details>");
    expect(md).toContain("Fix: Move it to an env var");
  });

  it("handles a clean scan without a details block", () => {
    const md = formatMarkdownReport(result([]));
    expect(md).toContain("No findings");
    expect(md).not.toContain("<details>");
    expect(md).toContain("Safe");
  });

  it("omits the line when absent and the location when there is no file", () => {
    const md = formatMarkdownReport(
      result([finding({ title: "A", line: undefined }), finding({ title: "B", file: undefined })]),
    );
    expect(md).toContain("(`src/a.ts`)");
    expect(md).not.toContain("src/a.ts:");
    expect(md).toMatch(/\*\*high\*\*: B\n/);
  });

  it("caps top findings at 10 and the detail list at 50", () => {
    const many = Array.from({ length: 60 }, (_, i) => finding({ title: `F${i}`, line: i + 1 }));
    const md = formatMarkdownReport(result(many));
    expect(md).toContain("...and 50 more");
    expect(md).toContain("All findings (60)");
    expect(md).toContain("10 more not shown");
    // 10 top bullets + 50 detail bullets
    expect(md.match(/\*\*high\*\*:/g)).toHaveLength(60);
  });

  it("drops the details block when the body would exceed GitHub's comment limit", () => {
    const big = "*".repeat(400);
    const many = Array.from({ length: 60 }, (_, i) =>
      finding({ title: big, plainEnglishProblem: big, fixSteps: [big], line: i + 1 }),
    );
    const md = formatMarkdownReport(result(many));
    expect(md.length).toBeLessThan(65536);
    expect(md).not.toContain("<details>");
    expect(md).toContain("Details omitted");
    expect(md).toContain("<!-- vibesafe-status:");
  });

  it("never includes evidence", () => {
    const md = formatMarkdownReport(result([finding({ evidence: "sk-SUPERSECRET123" })]));
    expect(md).not.toContain("SUPERSECRET");
  });

  it("escapes markdown and HTML in titles and paths", () => {
    const md = formatMarkdownReport(
      result([finding({ title: "<script>alert(1)</script> | **x**", file: "a`b.ts" })]),
    );
    expect(md).not.toContain("<script>");
    expect(md).toContain("\\<script\\>");
    expect(md).not.toContain("a`b");
    expect(md).toContain("a'b.ts");
  });

  it("notes detector errors and scan warnings", () => {
    const md = formatMarkdownReport(
      result([], {
        errors: [{ detectorId: "d", detectorName: "D", message: "m" }],
        warnings: ["file list truncated"],
      }),
    );
    expect(md).toContain("1 detector(s) failed");
    expect(md).toContain("file list truncated");
  });
});

describe("escapeMarkdown", () => {
  it("flattens newlines and escapes special characters", () => {
    expect(escapeMarkdown("a\nb *c* <d> & e")).toBe("a b \\*c\\* \\<d\\> &amp; e");
  });
});

describe("escapeMarkdown hardening", () => {
  it("defuses @mentions, autolinks and long values", () => {
    const e = escapeMarkdown("@org/team https://evil.example www.evil.example ![x](y) ~~z~~");
    expect(e).not.toContain("@org");
    expect(e).toContain("@​org/team");
    expect(e).not.toContain("https://");
    expect(e).not.toContain("www.evil");
    expect(e).toContain("\\!\\[x\\]\\(y\\)");
    expect(escapeMarkdown("a".repeat(1000)).length).toBeLessThan(400);
  });

  it("caps rendered warnings", () => {
    const warnings = Array.from({ length: 20 }, (_, i) => `warn${i}`);
    const md = formatMarkdownReport(result([], { warnings }));
    expect(md).toContain("warn4");
    expect(md).not.toContain("warn5");
    expect(md).toContain("15 more warning(s) not shown");
  });
});

describe("shouldPrintBanner", () => {
  it("suppresses the banner for json and any --format form", () => {
    expect(shouldPrintBanner(["scan", "."])).toBe(true);
    expect(shouldPrintBanner(["scan", ".", "--json"])).toBe(false);
    expect(shouldPrintBanner(["scan", ".", "-j"])).toBe(false);
    expect(shouldPrintBanner(["scan", ".", "--format", "markdown"])).toBe(false);
    expect(shouldPrintBanner(["scan", ".", "--format=markdown"])).toBe(false);
    expect(shouldPrintBanner(["scan", ".", "--format=xml"])).toBe(false);
  });

  it("suppresses the banner for --output in both forms", () => {
    expect(shouldPrintBanner(["scan", ".", "--output", "r.json"])).toBe(false);
    expect(shouldPrintBanner(["scan", ".", "--output=r.json"])).toBe(false);
  });

  it("ignores arguments after a bare --", () => {
    expect(shouldPrintBanner(["scan", "--format", "markdown", "--", "dir"])).toBe(false);
    expect(shouldPrintBanner(["scan", "--", "--json"])).toBe(true);
  });
});

describe("runScan --format", () => {
  let out: string;
  beforeEach(() => {
    out = "";
    vi.spyOn(process.stdout, "write").mockImplementation((s: string | Uint8Array) => {
      out += String(s);
      return true;
    });
    vi.spyOn(console, "log").mockImplementation((...a: unknown[]) => {
      out += a.join(" ") + "\n";
    });
    vi.spyOn(console, "error").mockImplementation(() => {});
    process.exitCode = undefined;
  });
  afterEach(() => {
    vi.restoreAllMocks();
    scanMock.mockReset();
    process.exitCode = undefined;
  });

  it("prints only markdown on stdout and keeps the CI exit code", async () => {
    scanMock.mockResolvedValue(result([finding()], { deployStatus: "blocker" }));
    await runScan(".", { format: "markdown" });
    expect(out.startsWith(PR_COMMENT_MARKER)).toBe(true);
    expect(out).not.toContain("Ready to scan");
    expect(out).not.toContain("Scan failed");
    expect(process.exitCode).toBe(1);
  });

  it("exits 0 for a safe markdown scan", async () => {
    scanMock.mockResolvedValue(result([]));
    await runScan(".", { format: "markdown" });
    expect(process.exitCode).toBe(0);
  });

  it("--format markdown wins over --json", async () => {
    scanMock.mockResolvedValue(result([finding()], { deployStatus: "blocker" }));
    await runScan(".", { json: true, format: "markdown" });
    expect(out.startsWith(PR_COMMENT_MARKER)).toBe(true);
    expect(out).not.toContain('"findings"');
  });

  it("rejects an unknown format with exit code 2 and does not scan", async () => {
    await runScan(".", { format: "xml" });
    expect(process.exitCode).toBe(2);
    expect(scanMock).not.toHaveBeenCalled();
  });
});

describe("action.yml", () => {
  const root = path.resolve(import.meta.dirname, "../../..");
  const action = fs.readFileSync(path.join(root, "action.yml"), "utf-8");

  it("declares the documented inputs", () => {
    for (const input of ["path", "fail-on", "comment", "github-token", "deep", "version"]) {
      expect(action).toMatch(new RegExp(`^  ${input}:`, "m"));
    }
    expect(action).toContain('using: "composite"');
    expect(action).toContain("@vibesafe/cli@");
    expect(action).not.toMatch(/default: "latest"/);
  });

  it("uses the same marker as the formatter and never interpolates inputs into shell", () => {
    expect(action).toContain(PR_COMMENT_MARKER);
    // Each run script is followed by the next "- name:" step (or EOF); expressions belong in env: only.
    const scripts = action
      .split(/\n\s+run: \|/)
      .slice(1)
      .map((block) => block.split(/\n    - name:/)[0] ?? "");
    expect(scripts.length).toBe(3);
    for (const script of scripts) expect(script).not.toContain("${{");
  });

  it("runs npx outside the repo with its npm config ignored and ends options with --", () => {
    expect(action).toContain("cd \"$cleandir\"");
    expect(action).toContain("NPM_CONFIG_USERCONFIG");
    expect(action).toContain("NPM_CONFIG_REGISTRY");
    expect(action).toContain("-- \"$GITHUB_WORKSPACE/$VS_PATH\"");
  });

  it("only updates comments by the token's own login that start with the marker", () => {
    expect(action).toContain("gh api user --jq .login");
    expect(action).toContain(".user.login == $me");
    expect(action).not.toContain(".user.type");
    expect(action).not.toContain("0.1.5");
    expect(action).toContain("startswith($m)");
  });

  it("ships a usage example referencing the action", () => {
    const ex = fs.readFileSync(path.join(root, "examples/github-action.yml"), "utf-8");
    expect(ex).toContain("Talaljaber/Vibesafe@");
    expect(ex).toContain("pull-requests: write");
  });
});
