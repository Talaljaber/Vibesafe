import { describe, it, expect } from "vitest";
import type { Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { TerraformDetector } from "../../src/detectors/terraform-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const createContext = (files: Record<string, string>, includeTests = false): ScanContext => ({
  rootPath: "/fake",
  projectContext: {} as ScanContext["projectContext"],
  files: Object.keys(files),
  config: { rootPath: "/fake", includeTests },
  readFile: async (f) => files[f] ?? "",
});

const run = async (tf: string, file = "infra/main.tf"): Promise<Finding[]> => {
  const files = { [file]: tf };
  const findings = await new TerraformDetector().detect(createContext(files));
  expectRubric(findings);
  const again = await new TerraformDetector().detect(createContext(files));
  expect(again.map((f) => f.id)).toEqual(findings.map((f) => f.id));
  return findings;
};

const rule = (findings: Finding[], slug: string): Finding[] =>
  findings.filter((f) => f.ruleId === `security_config/${slug}`);

const hcl = (...lines: string[]): string => lines.join("\n") + "\n";

describe("TerraformDetector: tf-public-s3-acl", () => {
  it("flags public-read ACLs on the line of the acl", async () => {
    const f = rule(
      await run(
        hcl(
          'resource "aws_s3_bucket_acl" "docs" {',
          "  bucket = aws_s3_bucket.docs.id",
          '  acl    = "public-read"',
          "}",
        ),
      ),
      "tf-public-s3-acl",
    );
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ line: 3, severity: "high", confidence: "high" });
  });

  it("is critical for public-read-write and flags AllUsers grants", async () => {
    const f = rule(
      await run(
        hcl(
          'resource "aws_s3_bucket" "a" {',
          '  acl = "public-read-write"',
          "}",
          'resource "aws_s3_bucket_acl" "b" {',
          "  access_control_policy {",
          "    grant {",
          "      grantee {",
          '        type = "Group"',
          '        uri  = "http://acs.amazonaws.com/groups/global/AllUsers"',
          "      }",
          "    }",
          "  }",
          "}",
        ),
      ),
      "tf-public-s3-acl",
    );
    expect(f.map((x) => [x.line, x.severity])).toEqual([
      [2, "critical"],
      [9, "high"],
    ]);
  });

  it.each([
    ['resource "aws_s3_bucket_acl" "x" {\n  acl = "private"\n}'],
    ['resource "aws_s3_bucket_acl" "x" {\n  acl = "log-delivery-write"\n}'],
    ['resource "aws_s3_bucket_acl" "x" {\n  acl = var.acl\n}'],
    ['resource "aws_s3_bucket_acl" "x" {\n  # acl = "public-read"\n  acl = "private"\n}'],
    ['resource "aws_instance" "x" {\n  acl = "public-read"\n}'],
  ])("is silent for %s", async (tf) => {
    expect(rule(await run(tf + "\n"), "tf-public-s3-acl")).toEqual([]);
  });
});

describe("TerraformDetector: tf-s3-public-access-unblocked", () => {
  it("anchors on the first false flag", async () => {
    const f = rule(
      await run(
        hcl(
          'resource "aws_s3_bucket_public_access_block" "x" {',
          "  bucket = aws_s3_bucket.x.id",
          "  block_public_acls = true",
          "  block_public_policy = false",
          "  ignore_public_acls = false",
          "}",
        ),
      ),
      "tf-s3-public-access-unblocked",
    );
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ line: 4, severity: "medium", confidence: "high" });
  });

  it("covers the account-level resource", async () => {
    const f = rule(
      await run(
        hcl(
          'resource "aws_s3_account_public_access_block" "x" {',
          "  restrict_public_buckets = false",
          "}",
        ),
      ),
      "tf-s3-public-access-unblocked",
    );
    expect(f).toHaveLength(1);
  });

  it("is silent when all flags are true, variables or the resource is unrelated", async () => {
    const tf = hcl(
      'resource "aws_s3_bucket_public_access_block" "x" {',
      "  block_public_acls = true",
      "  block_public_policy = var.block",
      "  ignore_public_acls = true",
      "  restrict_public_buckets = true",
      "}",
      'resource "aws_something" "y" {',
      "  block_public_acls = false",
      "}",
    );
    expect(rule(await run(tf), "tf-s3-public-access-unblocked")).toEqual([]);
  });
});

describe("TerraformDetector: tf-s3-public-policy", () => {
  const policy = (principal: string, extra = ""): string =>
    hcl(
      'resource "aws_s3_bucket_policy" "p" {',
      "  bucket = aws_s3_bucket.b.id",
      "  policy = jsonencode({",
      "    Statement = [{",
      '      Effect = "Allow"',
      `      Principal = ${principal}`,
      '      Action = "s3:GetObject"',
      '      Resource = "arn:aws:s3:::b/*"',
      extra,
      "    }]",
      "  })",
      "}",
    );

  it("flags Principal * and AWS = * without a condition", async () => {
    for (const principal of ['"*"', '{ AWS = "*" }']) {
      const f = rule(await run(policy(principal)), "tf-s3-public-policy");
      expect(f, principal).toHaveLength(1);
      expect(f[0]).toMatchObject({ line: 6, severity: "high", confidence: "medium" });
    }
  });

  it("reads a heredoc JSON policy", async () => {
    const f = rule(
      await run(
        hcl(
          'resource "aws_s3_bucket_policy" "p" {',
          "  policy = <<POLICY",
          "{",
          '  "Statement": [{ "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*" }]',
          "}",
          "POLICY",
          "}",
        ),
      ),
      "tf-s3-public-policy",
    );
    expect(f).toHaveLength(1);
  });

  it("is silent with a Condition, a named principal or a Deny", async () => {
    const cond = '      Condition = { StringEquals = { "aws:SourceVpce" = "vpce-1" } }';
    expect(rule(await run(policy('"*"', cond)), "tf-s3-public-policy")).toEqual([]);
    expect(
      rule(await run(policy('{ AWS = "arn:aws:iam::123456789012:root" }')), "tf-s3-public-policy"),
    ).toEqual([]);
    expect(
      rule(await run(policy('"*"').replace('"Allow"', '"Deny"')), "tf-s3-public-policy"),
    ).toEqual([]);
  });
});

describe("TerraformDetector: tf-db-publicly-accessible", () => {
  it("flags publicly_accessible = true on RDS and Redshift", async () => {
    const f = rule(
      await run(
        hcl(
          'resource "aws_db_instance" "a" {',
          "  publicly_accessible = true",
          "}",
          'resource "aws_redshift_cluster" "b" {',
          "  publicly_accessible = true",
          "}",
        ),
      ),
      "tf-db-publicly-accessible",
    );
    expect(f.map((x) => x.line)).toEqual([2, 5]);
    expect(f[0]).toMatchObject({ severity: "high", confidence: "high" });
  });

  it("is silent for false, variables, other resources and comments", async () => {
    const tf = hcl(
      'resource "aws_db_instance" "a" {',
      "  publicly_accessible = false",
      "}",
      'resource "aws_db_instance" "b" {',
      "  publicly_accessible = var.public",
      "}",
      'resource "aws_instance" "c" {',
      "  publicly_accessible = true",
      "}",
      'resource "aws_db_instance" "d" {',
      "  # publicly_accessible = true",
      "}",
    );
    expect(rule(await run(tf), "tf-db-publicly-accessible")).toEqual([]);
  });
});

describe("TerraformDetector: tf-open-ingress", () => {
  const sg = (from: number, to: number, cidr: string, proto = "tcp", block = "ingress"): string =>
    hcl(
      'resource "aws_security_group" "g" {',
      `  ${block} {`,
      `    from_port = ${from}`,
      `    to_port = ${to}`,
      `    protocol = "${proto}"`,
      `    cidr_blocks = ["${cidr}"]`,
      "  }",
      "}",
    );

  it.each([
    [22, 22, "0.0.0.0/0", "tcp"],
    [5432, 5432, "0.0.0.0/0", "tcp"],
    [0, 65535, "0.0.0.0/0", "tcp"],
    [0, 0, "0.0.0.0/0", "-1"],
  ])("flags %i-%i from %s over %s on the CIDR line", async (from, to, cidr, proto) => {
    const f = rule(await run(sg(from, to, cidr, proto)), "tf-open-ingress");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ line: 6, severity: "high", confidence: "high" });
  });

  it("flags ipv6, security group rules and the vpc ingress rule resource", async () => {
    const f = rule(
      await run(
        hcl(
          'resource "aws_security_group_rule" "r" {',
          '  type = "ingress"',
          "  from_port = 3306",
          "  to_port = 3306",
          '  protocol = "tcp"',
          '  ipv6_cidr_blocks = ["::/0"]',
          "}",
          'resource "aws_vpc_security_group_ingress_rule" "v" {',
          '  cidr_ipv4 = "0.0.0.0/0"',
          '  ip_protocol = "tcp"',
          "  from_port = 6379",
          "  to_port = 6379",
          "}",
        ),
      ),
      "tf-open-ingress",
    );
    expect(f.map((x) => x.line)).toEqual([6, 9]);
  });

  it.each([
    ["web ports", sg(443, 443, "0.0.0.0/0")],
    ["http", sg(80, 80, "0.0.0.0/0")],
    ["private cidr", sg(22, 22, "10.0.0.0/8")],
    ["egress", sg(0, 0, "0.0.0.0/0", "-1", "egress")],
    ["udp", sg(0, 65535, "0.0.0.0/0", "udp")],
  ])("is silent for %s", async (_name, tf) => {
    expect(rule(await run(tf), "tf-open-ingress")).toEqual([]);
  });

  it("is silent for variable CIDRs and a rule of type egress", async () => {
    const tf = hcl(
      'resource "aws_security_group" "g" {',
      "  ingress {",
      "    from_port = 22",
      "    to_port = 22",
      '    protocol = "tcp"',
      "    cidr_blocks = var.allowed_cidrs",
      "  }",
      "}",
      'resource "aws_security_group_rule" "e" {',
      '  type = "egress"',
      "  from_port = 22",
      "  to_port = 22",
      '  protocol = "tcp"',
      '  cidr_blocks = ["0.0.0.0/0"]',
      "}",
    );
    expect(rule(await run(tf), "tf-open-ingress")).toEqual([]);
  });
});

describe("TerraformDetector: tf-iam-wildcard-policy", () => {
  const policy = (action: string, resource: string, effect = "Allow"): string =>
    hcl(
      'resource "aws_iam_role_policy" "p" {',
      "  role = aws_iam_role.r.id",
      "  policy = jsonencode({",
      "    Statement = [{",
      `      Effect = "${effect}"`,
      `      Action = ${action}`,
      `      Resource = ${resource}`,
      "    }]",
      "  })",
      "}",
    );

  it("flags Action * on Resource * and anchors on the Action line", async () => {
    const f = rule(await run(policy('"*"', '"*"')), "tf-iam-wildcard-policy");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ line: 6, severity: "high", confidence: "high" });
  });

  it("flags a list containing * and an aws_iam_policy_document statement", async () => {
    expect(
      rule(await run(policy('["s3:Get*", "*"]', '["*"]')), "tf-iam-wildcard-policy"),
    ).toHaveLength(1);
    const f = rule(
      await run(
        hcl(
          'data "aws_iam_policy_document" "d" {',
          "  statement {",
          '    effect = "Allow"',
          '    actions = ["*"]',
          '    resources = ["*"]',
          "  }",
          "}",
        ),
      ),
      "tf-iam-wildcard-policy",
    );
    expect(f).toHaveLength(1);
    expect(f[0]!.line).toBe(4);
  });

  it.each([
    ["scoped s3:*", policy('"s3:*"', '"arn:aws:s3:::b/*"')],
    ["read-only describe", policy('"ec2:Describe*"', '"*"')],
    ["deny", policy('"*"', '"*"', "Deny")],
    ["scoped resource", policy('"*"', '"arn:aws:s3:::b"')],
  ])("is silent for %s", async (_name, tf) => {
    expect(rule(await run(tf), "tf-iam-wildcard-policy")).toEqual([]);
  });
});

describe("TerraformDetector: tf-oidc-wildcard-subject", () => {
  const trust = (
    sub: string,
    op = "StringLike",
    key = "token.actions.githubusercontent.com:sub",
  ): string =>
    hcl(
      'resource "aws_iam_role" "ci" {',
      "  assume_role_policy = jsonencode({",
      "    Statement = [{",
      '      Effect = "Allow"',
      '      Action = "sts:AssumeRoleWithWebIdentity"',
      "      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }",
      "      Condition = {",
      `        ${op} = {`,
      `          "${key}" = ${sub}`,
      "        }",
      "      }",
      "    }]",
      "  })",
      "}",
    );

  it.each(['"*"', '"repo:*"', '"repo:acme/*"', '"repo:${var.org}/*"'])(
    "flags %s as high",
    async (sub) => {
      const f = rule(await run(trust(sub)), "tf-oidc-wildcard-subject");
      expect(f).toHaveLength(1);
      expect(f[0]).toMatchObject({ line: 9, severity: "high", confidence: "high" });
    },
  );

  it("flags any branch of one repo as medium/medium", async () => {
    const f = rule(await run(trust('"repo:acme/shop:*"')), "tf-oidc-wildcard-subject");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "medium", confidence: "medium" });
  });

  it("flags a GitHub OIDC trust with no :sub condition", async () => {
    const f = rule(
      await run(
        trust('"sts.amazonaws.com"', "StringEquals", "token.actions.githubusercontent.com:aud"),
      ),
      "tf-oidc-wildcard-subject",
    );
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ line: 6, severity: "high" });
  });

  it.each([
    '"repo:acme/shop:ref:refs/heads/main"',
    '"repo:acme/shop:environment:prod"',
    '["repo:acme/shop:ref:refs/heads/main", "repo:acme/shop:environment:prod"]',
  ])("is silent for %s", async (sub) => {
    expect(rule(await run(trust(sub)), "tf-oidc-wildcard-subject")).toEqual([]);
  });

  const docTrust = (
    key: string,
    values: string,
    ids = "aws_iam_openid_connect_provider.github.arn",
  ) =>
    hcl(
      'data "aws_iam_policy_document" "trust" {',
      "  statement {",
      '    actions = ["sts:AssumeRoleWithWebIdentity"]',
      "    principals {",
      '      type        = "Federated"',
      `      identifiers = [${ids}]`,
      "    }",
      "    condition {",
      '      test     = "StringLike"',
      `      variable = ${key}`,
      `      values   = ${values}`,
      "    }",
      "  }",
      "}",
      'resource "aws_iam_role" "ci" {',
      "  assume_role_policy = data.aws_iam_policy_document.trust.json",
      "}",
    );

  it.each([
    '"${local.oidc_host}:sub"',
    '"${replace(aws_iam_openid_connect_provider.github.url, \\"https://\\", \\"\\")}:sub"',
  ])("is silent for a pinned subject under the interpolated key %s (jsonencode)", async (key) => {
    const tf = trust('"repo:acme/shop:ref:refs/heads/main"').replace(
      '"token.actions.githubusercontent.com:sub"',
      key,
    );
    expect(rule(await run(tf), "tf-oidc-wildcard-subject")).toEqual([]);
  });

  it("is silent for a pinned subject under an interpolated key (policy document)", async () => {
    const tf = docTrust('"${local.oidc_host}:sub"', '["repo:acme/shop:environment:prod"]');
    expect(rule(await run(tf), "tf-oidc-wildcard-subject")).toEqual([]);
  });

  it("flags a wildcard subject under an interpolated key", async () => {
    const json = trust('"repo:acme/*"').replace(
      '"token.actions.githubusercontent.com:sub"',
      '"${local.oidc_host}:sub"',
    );
    expect(rule(await run(json), "tf-oidc-wildcard-subject")).toHaveLength(1);
    const doc = docTrust('"${local.oidc_host}:sub"', '["repo:acme/*"]');
    expect(rule(await run(doc), "tf-oidc-wildcard-subject")).toHaveLength(1);
  });

  it("flags a policy-document GitHub trust with no :sub when the provider is a reference", async () => {
    const tf = docTrust('"token.actions.githubusercontent.com:aud"', '["sts.amazonaws.com"]');
    expect(rule(await run(tf), "tf-oidc-wildcard-subject")).toHaveLength(1);
  });

  it("is silent for a service principal trust policy", async () => {
    const tf = hcl(
      'resource "aws_iam_role" "app" {',
      "  assume_role_policy = jsonencode({",
      "    Statement = [{",
      '      Effect = "Allow"',
      '      Action = "sts:AssumeRole"',
      '      Principal = { Service = "ec2.amazonaws.com" }',
      "    }]",
      "  })",
      "}",
    );
    expect(rule(await run(tf), "tf-oidc-wildcard-subject")).toEqual([]);
  });
});

describe("TerraformDetector: tf-storage-unencrypted", () => {
  it("flags literal false and an empty kms key", async () => {
    const f = rule(
      await run(
        hcl(
          'resource "aws_db_instance" "a" {',
          "  storage_encrypted = false",
          "}",
          'resource "aws_ebs_volume" "b" {',
          "  encrypted = false",
          "}",
          'resource "aws_efs_file_system" "c" {',
          '  kms_key_id = ""',
          "}",
        ),
      ),
      "tf-storage-unencrypted",
    );
    expect(f.map((x) => x.line)).toEqual([2, 5, 8]);
    expect(f[0]).toMatchObject({ severity: "medium", confidence: "high" });
  });

  it("is silent for an empty kms key when encryption is literally on", async () => {
    const tf = hcl(
      'resource "aws_db_instance" "a" {',
      "  storage_encrypted = true",
      '  kms_key_id        = ""',
      "}",
      'resource "aws_ebs_volume" "b" {',
      "  encrypted  = true",
      '  kms_key_id = ""',
      "}",
    );
    expect(rule(await run(tf), "tf-storage-unencrypted")).toEqual([]);
  });

  it("is silent when the attribute is missing, true, a variable or on another resource", async () => {
    const tf = hcl(
      'resource "aws_db_instance" "a" {',
      '  engine = "postgres"',
      "}",
      'resource "aws_ebs_volume" "b" {',
      "  encrypted = true",
      "}",
      'resource "aws_db_instance" "c" {',
      "  storage_encrypted = var.encrypt",
      "}",
      'resource "aws_instance" "d" {',
      "  encrypted = false",
      "}",
    );
    expect(rule(await run(tf), "tf-storage-unencrypted")).toEqual([]);
  });
});

describe("TerraformDetector: tf-cloudfront-allows-http", () => {
  it("flags allow-all in any cache behavior", async () => {
    const f = rule(
      await run(
        hcl(
          'resource "aws_cloudfront_distribution" "d" {',
          "  default_cache_behavior {",
          '    viewer_protocol_policy = "allow-all"',
          "  }",
          "  ordered_cache_behavior {",
          '    viewer_protocol_policy = "allow-all"',
          "  }",
          "}",
        ),
      ),
      "tf-cloudfront-allows-http",
    );
    expect(f.map((x) => x.line)).toEqual([3, 6]);
  });

  it("flags an HTTP listener that forwards instead of redirecting", async () => {
    const f = rule(
      await run(
        hcl(
          'resource "aws_lb_listener" "http" {',
          '  protocol = "HTTP"',
          "  default_action {",
          '    type = "forward"',
          "  }",
          "}",
        ),
      ),
      "tf-cloudfront-allows-http",
    );
    expect(f).toHaveLength(1);
    expect(f[0]!.line).toBe(2);
  });

  it("is silent for redirect-to-https, redirect listeners and comments", async () => {
    const tf = hcl(
      'resource "aws_cloudfront_distribution" "d" {',
      "  default_cache_behavior {",
      '    viewer_protocol_policy = "redirect-to-https"',
      '    # viewer_protocol_policy = "allow-all"',
      '    // viewer_protocol_policy = "allow-all"',
      "  }",
      "}",
      'resource "aws_lb_listener" "http" {',
      '  protocol = "HTTP"',
      "  default_action {",
      '    type = "redirect"',
      "    redirect {",
      '      protocol = "HTTPS"',
      "    }",
      "  }",
      "}",
      'resource "aws_lb_listener" "https" {',
      '  protocol = "HTTPS"',
      "}",
    );
    expect(rule(await run(tf), "tf-cloudfront-allows-http")).toEqual([]);
  });
});

describe("TerraformDetector: tf-mutable-image-tags", () => {
  it("flags MUTABLE ECR repositories as low", async () => {
    const f = rule(
      await run(
        hcl(
          'resource "aws_ecr_repository" "a" {',
          '  image_tag_mutability = "MUTABLE"',
          "}",
          'resource "aws_ecr_repository" "b" {',
          '  for_each = toset(["x"])',
          '  image_tag_mutability = "MUTABLE"',
          "}",
        ),
      ),
      "tf-mutable-image-tags",
    );
    expect(f.map((x) => x.line)).toEqual([2, 6]);
    expect(f[0]).toMatchObject({ severity: "low", confidence: "high" });
  });

  it("is silent for IMMUTABLE, variables and other resources", async () => {
    const tf = hcl(
      'resource "aws_ecr_repository" "a" {',
      '  image_tag_mutability = "IMMUTABLE"',
      "}",
      'resource "aws_ecr_repository" "b" {',
      "  image_tag_mutability = var.mutability",
      "}",
      'resource "aws_other" "c" {',
      '  image_tag_mutability = "MUTABLE"',
      "}",
    );
    expect(rule(await run(tf), "tf-mutable-image-tags")).toEqual([]);
  });
});

describe("TerraformDetector: file kinds and robustness", () => {
  const insecure = hcl('resource "aws_db_instance" "a" {', "  publicly_accessible = true", "}");

  it("ignores tfvars, JS and yaml files", async () => {
    const files = {
      "prod.tfvars": "publicly_accessible = true\n",
      "app/db.ts": insecure,
      "deploy/db.yaml": insecure,
    };
    expect(await new TerraformDetector().detect(createContext(files))).toEqual([]);
  });

  it("skips test and fixture paths unless includeTests is set", async () => {
    const files = { "tests/fixtures/db.tf": insecure };
    expect(await new TerraformDetector().detect(createContext(files))).toEqual([]);
    expect(await new TerraformDetector().detect(createContext(files, true))).toHaveLength(1);
  });

  it("never throws on malformed input", async () => {
    const junk = ['resource "a" "b" {', "  x = [", '  "unterminated', "}}}}", "<<EOF", "${"];
    for (const text of [junk.join("\n"), "{".repeat(5000), '"'.repeat(999)]) {
      await expect(run(text)).resolves.toBeDefined();
    }
  });

  it("caps findings per rule per file with a summary", async () => {
    const text = Array.from({ length: 30 }, (_, i) =>
      hcl(`resource "aws_ecr_repository" "r${i}" {`, '  image_tag_mutability = "MUTABLE"', "}"),
    ).join("\n");
    const f = rule(await run(text), "tf-mutable-image-tags");
    expect(f).toHaveLength(26);
    expect(f.at(-1)!.title).toContain("more in this file");
  });
});
