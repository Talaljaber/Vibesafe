import { describe, it, expect } from "vitest";
import {
  findGhExpressions,
  parseActionRef,
  parseCompose,
  parseFlowList,
  parseShortPort,
  parseWorkflow,
  scanYamlLines,
  stripYamlComment,
} from "../../src/detectors/utils/yaml-lines.js";

describe("scanYamlLines", () => {
  it("tracks key paths through mappings and sequences", () => {
    const entries = scanYamlLines(
      [
        "jobs:",
        "  build:",
        "    steps:",
        "      - uses: actions/checkout@v4",
        "        with:",
        "          ref: main",
        "      - run: npm ci",
        "  test:",
        "    runs-on: ubuntu-latest",
      ].join("\n"),
    );
    const byLine = new Map(entries.map((e) => [e.line, e]));
    expect(byLine.get(4)!.path).toEqual(["jobs", "build", "steps", "[0]", "uses"]);
    expect(byLine.get(6)!.path).toEqual(["jobs", "build", "steps", "[0]", "with", "ref"]);
    expect(byLine.get(7)!.path).toEqual(["jobs", "build", "steps", "[1]", "run"]);
    expect(byLine.get(9)!.path).toEqual(["jobs", "test", "runs-on"]);
  });

  it("handles sequences at the same indentation as their key", () => {
    const entries = scanYamlLines(["steps:", "- run: a", "- run: b", "other: 1"].join("\n"));
    expect(entries.map((e) => e.path.join("."))).toEqual([
      "steps",
      "steps.[0].run",
      "steps.[1].run",
      "other",
    ]);
  });

  it("collects block scalars (|, >, |-) and stops at the dedent", () => {
    const entries = scanYamlLines(
      [
        "a:",
        "  run: |-",
        "    echo one",
        "",
        "    echo two # not a yaml comment",
        "  next: >",
        "    folded",
        "  last: x",
      ].join("\n"),
    );
    const block = entries.filter((e) => e.kind === "block");
    expect(block.map((e) => [e.line, e.value])).toEqual([
      [3, "echo one"],
      [5, "echo two # not a yaml comment"],
      [7, "folded"],
    ]);
    expect(block[0]!.path).toEqual(["a", "run"]);
    expect(entries.find((e) => e.line === 8)!.path).toEqual(["a", "last"]);
  });

  it("accepts CRLF, tabs, quoted keys and comments", () => {
    const entries = scanYamlLines("'on':\r\n\tpush: # trigger\r\n# full comment\r\n\"x y\": 1\r\n");
    expect(entries.map((e) => [e.line, e.path.join("."), e.value])).toEqual([
      [1, "on", ""],
      [2, "on.push", ""],
      [4, "x y", "1"],
    ]);
  });

  it("treats '- \"5432:5432\"' as a scalar item, not a key", () => {
    const [, item] = scanYamlLines('ports:\n  - "5432:5432"\n');
    expect(item!.kind).toBe("item");
    expect(item!.value).toBe('"5432:5432"');
  });
});

describe("helpers", () => {
  it("stripYamlComment keeps # inside quotes", () => {
    expect(stripYamlComment('"a # b" # c')).toBe('"a # b"');
    expect(stripYamlComment("value#notcomment")).toBe("value#notcomment");
  });

  it("parseFlowList splits flow sequences", () => {
    expect(parseFlowList("[push, \"pull_request_target\", 'x']")).toEqual([
      "push",
      "pull_request_target",
      "x",
    ]);
    expect(parseFlowList("push")).toBeNull();
  });

  it("findGhExpressions returns each ${{ }}", () => {
    const ex = findGhExpressions('echo "${{ github.event.issue.title }}" ${{secrets.A}}');
    expect(ex.map((e) => e.expr)).toEqual(["github.event.issue.title", "secrets.A"]);
  });

  it("parseActionRef classifies refs", () => {
    expect(parseActionRef("actions/checkout@v4", 1).refKind).toBe("tag");
    expect(parseActionRef("a/b@" + "a".repeat(40), 1).refKind).toBe("sha");
    expect(parseActionRef("a/b@master", 1).refKind).toBe("branch");
    expect(parseActionRef("a/b", 1).refKind).toBe("none");
    expect(parseActionRef("./.github/actions/x", 1).refKind).toBe("local");
    expect(parseActionRef("docker://alpine:3", 1).refKind).toBe("docker");
    const reusable = parseActionRef("org/repo/.github/workflows/ci.yml@main", 1);
    expect([reusable.owner, reusable.repo, reusable.path, reusable.refKind]).toEqual([
      "org",
      "repo",
      ".github/workflows/ci.yml",
      "branch",
    ]);
  });

  it("parseShortPort reads host IP, published and target", () => {
    expect(parseShortPort('"5432:5432"', 1)).toMatchObject({
      hostIp: undefined,
      published: "5432",
      target: "5432",
    });
    expect(parseShortPort("127.0.0.1:6379:6379/tcp", 1)).toMatchObject({
      hostIp: "127.0.0.1",
      published: "6379",
    });
    expect(parseShortPort("[::1]:80:80", 1).hostIp).toBe("::1");
    expect(parseShortPort("${DB_BIND:-127.0.0.1}:5432:5432", 1).hostIp).toBe("127.0.0.1");
    expect(parseShortPort("5432", 1).published).toBeUndefined();
  });
});

describe("parseWorkflow", () => {
  it("reads triggers in scalar, list and mapping form", () => {
    expect(parseWorkflow("on: push\n").triggers.map((t) => t.value)).toEqual(["push"]);
    expect(parseWorkflow("on: [push, issues]\n").triggers.map((t) => t.value)).toEqual([
      "push",
      "issues",
    ]);
    const wf = parseWorkflow("'on':\n  issues:\n    types: [opened]\n  pull_request_target:\n");
    expect(wf.triggers).toEqual([
      { value: "issues", line: 2 },
      { value: "pull_request_target", line: 4 },
    ]);
  });

  it("reads jobs, steps, with, env, if and permissions", () => {
    const wf = parseWorkflow(
      [
        "permissions: write-all",
        "jobs:",
        "  build:",
        "    if: github.repository == 'a/b'",
        "    permissions:",
        "      contents: read",
        "    steps:",
        "      - name: Checkout",
        "        uses: actions/checkout@v4",
        "        with:",
        "          ref: ${{ github.event.pull_request.head.sha }}",
        "      - env:",
        "          T: ${{ github.event.issue.title }}",
        "        run: |",
        '          echo "$T"',
        "          npm test",
        "      - uses: actions/github-script@v7",
        "        with:",
        "          script: |",
        "            console.log(1)",
      ].join("\n"),
    );
    expect(wf.permissions?.value).toBe("write-all");
    const job = wf.jobs[0]!;
    expect(job.id).toBe("build");
    expect(job.if?.value).toBe("github.repository == 'a/b'");
    expect(job.permissions?.scopes["contents"]?.value).toBe("read");
    expect(job.steps).toHaveLength(3);
    expect(job.steps[0]!.name?.value).toBe("Checkout");
    expect(job.steps[0]!.uses?.repo).toBe("checkout");
    expect(job.steps[0]!.with["ref"]?.text).toContain("head.sha");
    expect(job.steps[1]!.env["T"]?.line).toBe(13);
    expect(job.steps[1]!.run?.lines.map((l) => l.line)).toEqual([15, 16]);
    expect(job.steps[2]!.with["script"]?.lines).toEqual([{ value: "console.log(1)", line: 20 }]);
  });

  it("reads a plain scalar run: that starts on the next line", () => {
    const wf = parseWorkflow(
      [
        "jobs:",
        "  a:",
        "    steps:",
        "      - run:",
        "          echo ${{ x }}",
        "      - run: b",
      ].join("\n"),
    );
    const steps = wf.jobs[0]!.steps;
    expect(steps[0]!.run?.lines).toEqual([{ value: "echo ${{ x }}", line: 5 }]);
    expect(steps[1]!.run?.text).toBe("b");
  });

  it("reads composite action steps as job 'runs'", () => {
    const wf = parseWorkflow("runs:\n  using: composite\n  steps:\n    - uses: a/b@main\n");
    expect(wf.jobs[0]!.id).toBe("runs");
    expect(wf.jobs[0]!.steps[0]!.uses?.refKind).toBe("branch");
  });
});

describe("parseCompose", () => {
  it("reads image, ports (short, flow, long), environment (map, list), privileged, volumes", () => {
    const c = parseCompose(
      [
        "services:",
        "  db:",
        "    image: postgres:15",
        "    environment:",
        "      POSTGRES_PASSWORD: postgres # default",
        "    ports:",
        '      - "5432:5432"',
        "      - target: 5433",
        "        published: 5433",
        "        host_ip: 127.0.0.1",
        "  cache:",
        "    image: redis",
        '    ports: ["6379:6379"]',
        "    environment:",
        "      - REDIS_PASSWORD=redis",
        "    privileged: true",
        "    volumes:",
        "      - /var/run/docker.sock:/var/run/docker.sock",
      ].join("\n"),
    );
    const [db, cache] = c.services;
    expect(db!.image?.value).toBe("postgres:15");
    expect(db!.environment).toEqual([{ key: "POSTGRES_PASSWORD", value: "postgres", line: 5 }]);
    expect(db!.ports.map((p) => [p.hostIp, p.published, p.line])).toEqual([
      [undefined, "5432", 7],
      ["127.0.0.1", "5433", 9],
    ]);
    expect(cache!.ports[0]!.published).toBe("6379");
    expect(cache!.environment[0]).toEqual({ key: "REDIS_PASSWORD", value: "redis", line: 15 });
    expect(cache!.privileged?.value).toBe("true");
    expect(cache!.volumes[0]!.value).toContain("docker.sock");
  });
});
