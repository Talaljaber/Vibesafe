import { describe, it, expect } from "vitest";
import {
  allAttrs,
  attrOf,
  hclBool,
  hclString,
  hclStringList,
  hclStringShape,
  parseHcl,
  policyStatements,
} from "../../src/detectors/utils/hcl.js";

const hcl = (...lines: string[]): string => lines.join("\n") + "\n";

describe("parseHcl", () => {
  it("reads blocks, labels, attributes and their lines", () => {
    const blocks = parseHcl(
      hcl(
        'resource "aws_db_instance" "main" {',
        '  engine = "postgres"',
        "  publicly_accessible = true",
        "  tags = {",
        '    Name = "x"',
        "  }",
        "  timeouts {",
        '    create = "1h"',
        "  }",
        "}",
      ),
    );
    expect(blocks).toHaveLength(1);
    const b = blocks[0]!;
    expect(b).toMatchObject({
      type: "resource",
      labels: ["aws_db_instance", "main"],
      line: 1,
      endLine: 10,
    });
    expect(b.attrs.map((a) => [a.name, a.line, a.endLine])).toEqual([
      ["engine", 2, 2],
      ["publicly_accessible", 3, 3],
      ["tags", 4, 6],
    ]);
    expect(b.blocks[0]).toMatchObject({ type: "timeouts", line: 7, endLine: 9 });
    expect(allAttrs(b).map((a) => a.name)).toContain("create");
  });

  it("skips comments, strings with braces, interpolations and heredocs", () => {
    const blocks = parseHcl(
      hcl(
        '# resource "fake" "one" {',
        "// another }",
        "/* block { comment */",
        'resource "a" "b" {',
        '  name = "has } and { braces ${lookup({ a = "}" }, "a")}"',
        "  policy = <<-EOT",
        "    { not a block }",
        "  EOT",
        '  after = "yes"',
        "}",
      ),
    );
    expect(blocks).toHaveLength(1);
    expect(blocks[0]!.attrs.map((a) => a.name)).toEqual(["name", "policy", "after"]);
    expect(attrOf(blocks[0]!, "after")!.line).toBe(9);
  });

  it("handles single-line blocks and top-level attributes (tfvars)", () => {
    const blocks = parseHcl(hcl('region = "us-east-1"', "ingress { from_port = 22 }"));
    expect(blocks[0]).toMatchObject({ type: "" });
    expect(blocks[0]!.attrs[0]).toMatchObject({ name: "region", line: 1 });
    expect(blocks[1]!.type).toBe("ingress");
    expect(blocks[1]!.attrs[0]).toMatchObject({ name: "from_port", value: "22", line: 2 });
  });

  it("never throws on malformed or hostile input", () => {
    for (const text of [
      "",
      "}",
      "{{{",
      'a = "',
      "a = [",
      "<<EOF",
      "\0",
      "a {".repeat(500),
      "}".repeat(500),
    ]) {
      expect(() => parseHcl(text), text.slice(0, 10)).not.toThrow();
    }
    expect(parseHcl("x = <<EOF\nnever closed")).toBeDefined();
  });
});

describe("literal helpers", () => {
  it("hclString returns pure literals only", () => {
    expect(hclString('"public-read"')).toBe("public-read");
    expect(hclString('"a\\"b"')).toBe('a"b');
    expect(hclString('"${var.x}"')).toBeUndefined();
    expect(hclString("var.x")).toBeUndefined();
    expect(hclString('"a" + "b"')).toBeUndefined();
    expect(hclString("<<EOF\nx\nEOF")).toBeUndefined();
  });

  it("hclStringShape keeps the shape of interpolated strings", () => {
    expect(hclStringShape('"repo:${var.org}/*"')).toBe("repo:ORG/*");
  });

  it("hclBool and hclStringList", () => {
    expect(hclBool("true")).toBe(true);
    expect(hclBool(" false ")).toBe(false);
    expect(hclBool("var.x")).toBeUndefined();
    expect(hclBool('"true"')).toBeUndefined();
    expect(hclStringList('["a", "b"]')).toEqual(["a", "b"]);
    expect(hclStringList('["a", var.b, "${c}"]')).toEqual(["a"]);
    expect(hclStringList('"solo"')).toEqual(["solo"]);
    expect(hclStringList("var.list")).toBeUndefined();
  });
});

describe("policyStatements", () => {
  it("reads a jsonencode policy with key lines", () => {
    const [policy] = parseHcl(
      hcl(
        'resource "aws_iam_role_policy" "p" {',
        "  policy = jsonencode({",
        "    Statement = [{",
        '      Effect = "Allow"',
        '      Action = ["s3:Get*", "s3:List*"]',
        '      Resource = "*"',
        '      Principal = { AWS = "*" }',
        '      Condition = { StringEquals = { "aws:sub" = "x" } }',
        "    }]",
        "  })",
        "}",
      ),
    );
    const st = policyStatements(attrOf(policy!, "policy")!);
    expect(st).toHaveLength(1);
    expect(st[0]).toMatchObject({
      effect: "Allow",
      actions: ["s3:Get*", "s3:List*"],
      resources: ["*"],
      principals: ["*"],
      line: 3,
      actionLine: 5,
      resourceLine: 6,
      principalLine: 7,
    });
    expect(st[0]!.conditions).toContain("StringEquals");
    expect(st[0]!.conditionEntries[0]).toMatchObject({ key: "aws:sub", values: ["x"], line: 8 });
  });

  it("reads heredoc JSON and quoted JSON policies", () => {
    const [heredoc] = parseHcl(
      hcl(
        'resource "aws_iam_policy" "p" {',
        "  policy = <<EOF",
        "{",
        '  "Statement": [',
        '    { "Effect": "Allow", "Action": "*", "Resource": "*" },',
        '    { "Effect": "Deny", "Action": "s3:*", "Resource": "arn:aws:s3:::b" }',
        "  ]",
        "}",
        "EOF",
        "}",
      ),
    );
    const st = policyStatements(attrOf(heredoc!, "policy")!);
    expect(st.map((s) => [s.effect, s.actions, s.actionLine])).toEqual([
      ["Allow", ["*"], 5],
      ["Deny", ["s3:*"], 6],
    ]);
    const [quoted] = parseHcl(
      hcl(
        "a {",
        '  policy = "{\\"Statement\\":{\\"Effect\\":\\"Allow\\",\\"Action\\":\\"*\\",\\"Resource\\":\\"*\\"}}"',
        "}",
      ),
    );
    expect(policyStatements(attrOf(quoted!, "policy")!)[0]).toMatchObject({ actions: ["*"] });
  });

  it("reads aws_iam_policy_document statements", () => {
    const [doc] = parseHcl(
      hcl(
        'data "aws_iam_policy_document" "d" {',
        "  statement {",
        '    effect    = "Allow"',
        '    actions   = ["sts:AssumeRoleWithWebIdentity"]',
        "    principals {",
        '      type        = "Federated"',
        '      identifiers = ["arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"]',
        "    }",
        "    condition {",
        '      test     = "StringLike"',
        '      variable = "token.actions.githubusercontent.com:sub"',
        '      values   = ["repo:acme/*"]',
        "    }",
        "  }",
        "}",
      ),
    );
    const [st] = policyStatements(doc!);
    expect(st).toMatchObject({ effect: "Allow", actionLine: 4, principalLine: 7, line: 2 });
    expect(st!.federated[0]).toContain("token.actions.githubusercontent.com");
    expect(st!.conditionEntries[0]).toMatchObject({
      operator: "StringLike",
      key: "token.actions.githubusercontent.com:sub",
      values: ["repo:acme/*"],
      line: 12,
    });
  });

  it("returns nothing for unparseable values and never throws", () => {
    const [b] = parseHcl(
      hcl("a {", "  policy = data.aws_iam_policy_document.x.json", "  other = [[[", "}"),
    );
    expect(policyStatements(attrOf(b!, "policy")!)).toEqual([]);
    expect(policyStatements(attrOf(b!, "other")!)).toEqual([]);
  });
});
