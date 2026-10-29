import { describe, it, expect } from "vitest";
import type { Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { GithubWorkflowDetector } from "../../src/detectors/github-workflow-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const createContext = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake",
  projectContext: {} as ScanContext["projectContext"],
  files: Object.keys(files),
  config: { rootPath: "/fake" },
  readFile: async (f) => files[f] ?? "",
});

const run = async (files: Record<string, string>): Promise<Finding[]> => {
  const findings = await new GithubWorkflowDetector().detect(createContext(files));
  expectRubric(findings);
  return findings;
};

const byRule = (findings: Finding[], rule: string): Finding[] =>
  findings.filter((f) => f.ruleId === `security_config/${rule}`);

const yaml = (...lines: string[]): string => lines.join("\n") + "\n";
const WF = ".github/workflows/ci.yml";
const SHA = "b4ffde65f46336ab88eb53be808477a3936bae11";

describe("GithubWorkflowDetector: gha-pull-request-target-checkout", () => {
  it("flags pull_request_target that checks out and builds the PR head (critical)", async () => {
    const findings = byRule(
      await run({
        [WF]: yaml(
          "on:",
          "  push:",
          "  pull_request_target:",
          "jobs:",
          "  build:",
          "    runs-on: ubuntu-latest",
          "    steps:",
          "      - uses: actions/checkout@v4",
          "        with:",
          "          ref: ${{ github.event.pull_request.head.sha || github.sha }}",
          "      - run: npm ci && npm run build",
          "        env:",
          "          TOKEN: ${{ secrets.DEPLOY_TOKEN }}",
        ),
      }),
      "gha-pull-request-target-checkout",
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!).toMatchObject({ line: 3, severity: "critical", confidence: "high" });
    expect(findings[0]!.deployBlocking).toBe(true);
  });

  it("flags workflow_run head checkouts and gh pr checkout in run steps", async () => {
    const findings = byRule(
      await run({
        ".github/workflows/a.yml": yaml(
          "on:",
          "  workflow_run:",
          "    workflows: [CI]",
          "jobs:",
          "  deploy:",
          "    steps:",
          "      - uses: actions/checkout@v4",
          "        with:",
          "          ref: ${{ github.event.workflow_run.head_sha }}",
          "      - run: make deploy",
        ),
        ".github/workflows/b.yaml": yaml(
          "on: [pull_request_target]",
          "jobs:",
          "  test:",
          "    steps:",
          "      - run: |",
          "          gh pr checkout ${{ github.event.pull_request.number }}",
          "          npm test",
        ),
      }),
      "gha-pull-request-target-checkout",
    );
    expect(findings.map((f) => [f.file, f.line, f.severity])).toEqual([
      [".github/workflows/a.yml", 2, "critical"],
      [".github/workflows/b.yaml", 1, "critical"],
    ]);
  });

  it("downgrades label-gated jobs and checkouts that run nothing", async () => {
    const findings = byRule(
      await run({
        [WF]: yaml(
          "on:",
          "  pull_request_target:",
          "    types: [labeled]",
          "jobs:",
          "  test:",
          "    if: contains(github.event.pull_request.labels.*.name, 'safe to test')",
          "    steps:",
          "      - uses: actions/checkout@v4",
          "        with:",
          "          ref: ${{ github.event.pull_request.head.sha }}",
          "      - run: npm test",
          "  diff:",
          "    steps:",
          "      - uses: actions/checkout@v4",
          "        with:",
          "          ref: ${{ github.head_ref }}",
          "      - uses: some/labeler@" + SHA,
        ),
      }),
      "gha-pull-request-target-checkout",
    );
    expect(findings.map((f) => [f.severity, f.confidence])).toEqual([
      ["high", "medium"],
      ["high", "medium"],
    ]);
  });

  it("ignores pull_request, base checkouts, same-repo guards and comments", async () => {
    const files = {
      ".github/workflows/pr.yml": yaml(
        "on: pull_request",
        "jobs:",
        "  t:",
        "    steps:",
        "      - uses: actions/checkout@v4",
        "        with:",
        "          ref: ${{ github.event.pull_request.head.sha }}",
        "      - run: npm test",
      ),
      ".github/workflows/label.yml": yaml(
        "on: pull_request_target",
        "jobs:",
        "  label:",
        "    steps:",
        "      - uses: actions/checkout@v4",
        "      - uses: actions/labeler@v5",
        "      - run: echo done",
      ),
      ".github/workflows/guard.yml": yaml(
        "on: pull_request_target",
        "jobs:",
        "  t:",
        "    if: github.event.pull_request.head.repo.full_name == github.repository",
        "    steps:",
        "      - uses: actions/checkout@v4",
        "        with:",
        "          ref: ${{ github.event.pull_request.head.sha }}",
        "      - run: npm test",
      ),
      ".github/workflows/comment.yml": yaml(
        "on: pull_request_target",
        "jobs:",
        "  t:",
        "    steps:",
        "      # - uses: actions/checkout@v4",
        "      #   with:",
        "      #     ref: ${{ github.event.pull_request.head.sha }}",
        "      - run: echo hi",
      ),
      "docs/ci.yml": yaml(
        "on: pull_request_target",
        "jobs:",
        "  t:",
        "    steps:",
        "      - uses: actions/checkout@v4",
        "        with:",
        "          ref: ${{ github.event.pull_request.head.sha }}",
        "      - run: npm test",
      ),
    };
    expect(byRule(await run(files), "gha-pull-request-target-checkout")).toEqual([]);
  });
});

describe("GithubWorkflowDetector: gha-unpinned-action", () => {
  it("flags branch refs and missing refs; third-party medium, first-party low", async () => {
    const findings = byRule(
      await run({
        [WF]: yaml(
          "on: push",
          "jobs:",
          "  scan:",
          "    steps:",
          "      - uses: actions/checkout@main",
          "      - name: Trivy",
          "        uses: aquasecurity/trivy-action@master",
          "      - uses: someone/tool",
          "  reuse:",
          "    uses: org/workflows/.github/workflows/ci.yml@main",
        ),
      }),
      "gha-unpinned-action",
    );
    expect(findings.map((f) => [f.line, f.severity])).toEqual([
      [5, "low"],
      [7, "medium"],
      [8, "medium"],
      [10, "medium"],
    ]);
  });

  it("covers composite action.yml steps", async () => {
    const findings = byRule(
      await run({
        "action.yml": yaml(
          "name: x",
          "runs:",
          "  using: composite",
          "  steps:",
          "    - uses: third/party@master",
        ),
      }),
      "gha-unpinned-action",
    );
    expect(findings.map((f) => f.line)).toEqual([5]);
  });

  it("ignores tags, SHAs, local actions, docker images and comments", async () => {
    const findings = byRule(
      await run({
        [WF]: yaml(
          "on: push",
          "jobs:",
          "  b:",
          "    steps:",
          "      - uses: actions/checkout@v4",
          "      - uses: actions/setup-node@v4.1.0",
          `      - uses: aquasecurity/trivy-action@${SHA} # 0.28.0`,
          "      - uses: ./.github/actions/setup",
          "      - uses: docker://alpine:3.20",
          "      # - uses: someone/tool@master",
          "      - run: echo uses: someone/tool@master",
        ),
      }),
      "gha-unpinned-action",
    );
    expect(findings).toEqual([]);
  });
});

describe("GithubWorkflowDetector: gha-write-all-permissions", () => {
  it("flags write-all at workflow and job level", async () => {
    const findings = byRule(
      await run({
        [WF]: yaml(
          "on: push",
          "permissions: write-all",
          "jobs:",
          "  a:",
          "    permissions: write-all",
          "    steps:",
          "      - run: echo",
        ),
      }),
      "gha-write-all-permissions",
    );
    expect(findings.map((f) => [f.line, f.severity])).toEqual([
      [2, "medium"],
      [5, "medium"],
    ]);
  });

  it("ignores scoped and read-all permissions", async () => {
    const findings = byRule(
      await run({
        [WF]: yaml(
          "on: push",
          "permissions: read-all",
          "jobs:",
          "  a:",
          "    permissions:",
          "      contents: write",
          "      pull-requests: write",
          "    steps:",
          "      - run: echo permissions: write-all",
          "# permissions: write-all",
        ),
      }),
      "gha-write-all-permissions",
    );
    expect(findings).toEqual([]);
  });
});

describe("GithubWorkflowDetector: general", () => {
  it("gives stable ids and never throws", async () => {
    const files = {
      [WF]: yaml("on: push", "jobs:", "  a:", "    steps:", "      - uses: x/y@main"),
    };
    const a = await run(files);
    const b = await run(files);
    expect(a).toHaveLength(1);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
    await expect(run({ [WF]: "on:\n  - : [\n\tjobs: {\n" })).resolves.toBeDefined();
  });
});
