import { describe, it, expect } from "vitest";
import type { Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { GhaScriptInjectionDetector } from "../../src/detectors/gha-script-injection-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const createContext = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake",
  projectContext: {} as ScanContext["projectContext"],
  files: Object.keys(files),
  config: { rootPath: "/fake" },
  readFile: async (f) => files[f] ?? "",
});

const run = async (files: Record<string, string>): Promise<Finding[]> => {
  const findings = await new GhaScriptInjectionDetector().detect(createContext(files));
  expectRubric(findings);
  for (const f of findings) expect(f.ruleId).toBe("injection/gha-script-injection");
  return findings;
};

const yaml = (...lines: string[]): string => lines.join("\n") + "\n";
const WF = ".github/workflows/triage.yml";

describe("GhaScriptInjectionDetector", () => {
  it("flags untrusted fields expanded in run: blocks on outsider triggers (high/high)", async () => {
    const findings = await run({
      [WF]: yaml(
        "on:",
        "  issues:",
        "    types: [opened]",
        "jobs:",
        "  notify:",
        "    steps:",
        "      - name: Post",
        "        run: |",
        '          curl -X POST "${{ secrets.HOOK }}" \\',
        '            -d "{\\"text\\": \\"#${{ github.event.issue.number }}: ${{ github.event.issue.title }}\\"}"',
        "      - run: echo ${{ github.event.comment.body }}",
      ),
    });
    expect(findings.map((f) => [f.line, f.severity, f.confidence])).toEqual([
      [10, "high", "high"],
      [11, "high", "high"],
    ]);
    expect(findings[0]!.title).toContain("github.event.issue.title");
  });

  it("flags github-script script: and head_ref, medium on pull_request", async () => {
    const findings = await run({
      [WF]: yaml(
        "on: pull_request",
        "jobs:",
        "  a:",
        "    steps:",
        "      - run: git push origin ${{ github.head_ref }}",
        "      - uses: actions/github-script@v7",
        "        with:",
        "          script: |",
        "            const t = `${{ github.event.pull_request.title }}`;",
        "            const n = ${{ github.event.pull_request.number }};",
      ),
    });
    expect(findings.map((f) => [f.line, f.severity, f.confidence])).toEqual([
      [5, "medium", "high"],
      [9, "medium", "high"],
    ]);
  });

  it("ignores env:, if:, name: and with: inputs, safe fields and secrets", async () => {
    const findings = await run({
      [WF]: yaml(
        "on:",
        "  pull_request_target:",
        "  issues:",
        "jobs:",
        "  a:",
        "    if: contains(github.event.issue.title, 'bug')",
        "    steps:",
        "      - name: ${{ github.event.issue.title }}",
        "        env:",
        "          TITLE: ${{ github.event.pull_request.title }}",
        "        run: |",
        '          printf "%s" "$TITLE"',
        "          gh issue edit ${{ github.event.issue.number }} --repo ${{ github.repository }}",
        "          echo ${{ github.event.pull_request.head.sha }} ${{ secrets.TOKEN }}",
        "      - uses: some/action@v1",
        "        with:",
        "          body: ${{ github.event.issue.body }}",
        "      - uses: actions/github-script@v7",
        "        with:",
        "          script: console.log(context.payload.issue.title)",
        "      # - run: echo ${{ github.event.issue.title }}",
      ),
    });
    expect(findings).toEqual([]);
  });

  it("ignores files that are not workflows or actions", async () => {
    const body = yaml(
      "on: issues",
      "jobs:",
      "  a:",
      "    steps:",
      "      - run: echo ${{ github.event.issue.title }}",
    );
    expect(
      await run({
        "docs/example.yml": body,
        "README.md": body,
        "tests/.github/workflows/x.yml": body,
      }),
    ).toEqual([]);
  });

  it("reports composite actions at medium and keeps ids stable", async () => {
    const files = {
      "action.yml": yaml(
        "runs:",
        "  using: composite",
        "  steps:",
        "    - shell: bash",
        "      run: echo '${{ github.event.pull_request.body }}'",
      ),
    };
    const a = await run(files);
    const b = await run(files);
    expect(a.map((f) => [f.line, f.severity, f.confidence])).toEqual([[5, "medium", "medium"]]);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("lowers confidence for shell comment lines and never throws", async () => {
    const findings = await run({
      [WF]: yaml(
        "on: issue_comment",
        "jobs:",
        "  a:",
        "    steps:",
        "      - run: |",
        "          # ${{ github.event.comment.body }}",
        "          true",
      ),
    });
    expect(findings.map((f) => f.confidence)).toEqual(["medium"]);
    await expect(run({ [WF]: "${{\non: [\n" })).resolves.toBeDefined();
  });
});

describe("GhaScriptInjectionDetector: toJSON", () => {
  it("flags toJSON of an untrusted event object in run:, not of safe contexts", async () => {
    const findings = await run({
      [WF]: yaml(
        "on: issues",
        "jobs:",
        "  a:",
        "    steps:",
        "      - run: echo '${{ toJSON(github.event.issue) }}' > issue.json",
        "      - run: echo '${{ toJSON(github.event) }}'",
        "      - run: echo '${{ toJSON(matrix) }}' '${{ toJSON(github.event.repository) }}'",
        "      - env:",
        "          ISSUE: ${{ toJSON(github.event.issue) }}",
        '        run: echo "$ISSUE"',
      ),
    });
    expect(findings.map((f) => [f.line, f.severity])).toEqual([
      [5, "high"],
      [6, "high"],
    ]);
  });
});
