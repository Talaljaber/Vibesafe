import type {
  Confidence,
  Detector,
  Finding,
  ScanContext,
  Severity,
} from "@talaljaber/vibesafe-shared";
import { classifyPath, isTestOrFixturePath } from "./utils/file-kind.js";
import { makeFinding } from "./utils/finding.js";
import { capFindingsPerRule } from "./utils/infra-common.js";
import {
  allAttrs,
  attrOf,
  hclBool,
  hclString,
  hclStringList,
  parseHcl,
  policyStatements,
  type HclAttr,
  type HclBlock,
  type PolicyStatement,
} from "./utils/hcl.js";

interface RuleText {
  ruleId: string;
  title: string;
  problem: string;
  why: string;
  fix: string[];
  prompt: string;
}

const RULES = {
  publicAcl: {
    ruleId: "security_config/tf-public-s3-acl",
    title: "S3 bucket or object is publicly readable (ACL)",
    problem:
      "This Terraform resource sets a public ACL, so anyone on the internet can read (or write) the bucket or object.",
    why: "Public buckets are a leading source of data leaks; customer files, backups and exports are indexed and scraped within hours.",
    fix: [
      'Set the ACL to "private" (or remove it) and keep S3 Block Public Access enabled.',
      "Serve public assets through CloudFront with an origin access control instead of a public ACL.",
      "Use presigned URLs for per-user downloads.",
    ],
    prompt:
      "Review this Terraform resource. Replace the public S3 ACL with a private one, enable aws_s3_bucket_public_access_block with all four flags true, and, if the content must be public, serve it through CloudFront with origin access control.",
  },
  publicAccessBlock: {
    ruleId: "security_config/tf-s3-public-access-unblocked",
    title: "S3 Block Public Access is turned off",
    problem:
      "This public access block resource sets one or more of its four protections to false, so the bucket can be made public by an ACL or policy.",
    why: "Block Public Access is the safety net that stops a stray ACL or policy from exposing a bucket.",
    fix: [
      "Set block_public_acls, block_public_policy, ignore_public_acls and restrict_public_buckets to true.",
      "Make only the few buckets that must be public explicit exceptions, behind CloudFront.",
    ],
    prompt:
      "In this aws_s3_bucket_public_access_block, set all four flags (block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets) to true unless the bucket is deliberately public, and explain any remaining exception.",
  },
  publicPolicy: {
    ruleId: "security_config/tf-s3-public-policy",
    title: "S3 bucket policy allows everyone",
    problem:
      "This bucket policy has an Allow statement for Principal * with no condition, so any anonymous caller is granted the listed actions.",
    why: "An anonymous principal turns the bucket into a public resource; reads leak data and writes allow tampering or hosting abuse.",
    fix: [
      "Name the exact principals (accounts, roles or a CloudFront origin access control) instead of *.",
      "If anonymous access is truly intended, restrict it with a Condition (source VPC endpoint, referer or IP range) and limit the actions to s3:GetObject.",
    ],
    prompt:
      "Rewrite this S3 bucket policy so it no longer allows Principal * without a Condition. Grant access only to named principals or to CloudFront through an origin access control.",
  },
  dbPublic: {
    ruleId: "security_config/tf-db-publicly-accessible",
    title: "Database is publicly accessible",
    problem:
      "This database instance has publicly_accessible = true, which gives it a public IP address reachable from the internet.",
    why: "A database on the public internet is scanned and brute-forced constantly; one weak password or unpatched flaw exposes all its data.",
    fix: [
      "Set publicly_accessible = false and place the instance in private subnets.",
      "Reach it through the application tier, a VPN or a bastion/SSM session.",
    ],
    prompt:
      "Set publicly_accessible = false on this database, move it to private subnets, and restrict its security group to the application's security group only.",
  },
  openIngress: {
    ruleId: "security_config/tf-open-ingress",
    title: "Security group opens a sensitive port to the internet",
    problem:
      "This ingress rule allows 0.0.0.0/0 (or ::/0) to reach SSH, RDP, a database or cache port, or all protocols.",
    why: "Anyone on the internet can attempt to connect; exposed admin and data ports are the most common entry point for attackers.",
    fix: [
      "Restrict the CIDR to your office/VPN range or reference another security group.",
      "Use SSM Session Manager instead of public SSH and keep databases in private subnets.",
    ],
    prompt:
      "Change this security group ingress so it no longer allows 0.0.0.0/0 or ::/0 on administrative or data ports. Reference the application's security group or a specific trusted CIDR instead.",
  },
  iamWildcard: {
    ruleId: "security_config/tf-iam-wildcard-policy",
    title: "IAM policy allows every action on every resource",
    problem: 'This IAM policy has an Allow statement with Action "*" and Resource "*".',
    why: "Any compromise of the identity that holds this policy becomes a full account takeover.",
    fix: [
      "List only the actions the workload needs and scope Resource to specific ARNs.",
      "Use IAM Access Analyzer to generate a least-privilege policy from real usage.",
    ],
    prompt:
      'Replace the Action "*" / Resource "*" statement in this IAM policy with the specific actions and resource ARNs the workload needs.',
  },
  oidcSubject: {
    ruleId: "security_config/tf-oidc-wildcard-subject",
    title: "OIDC trust policy accepts too many callers",
    problem:
      "This role trust policy for a CI OIDC provider does not pin the subject to one repository and branch/environment (wildcard or missing :sub condition).",
    why: "Any repository or branch that matches can assume the role, including forks and pull-request code, and deploy with its permissions.",
    fix: [
      'Add a StringEquals/StringLike condition on the ":sub" claim naming one repo and ref, such as repo:<org>/<repo>:ref:refs/heads/main or :environment:<name>.',
      'Also check ":aud" and keep the role permissions minimal.',
    ],
    prompt:
      "Tighten this OIDC role trust policy: require the :sub claim to equal one repository and a specific branch or environment, and keep the :aud condition.",
  },
  storageUnencrypted: {
    ruleId: "security_config/tf-storage-unencrypted",
    title: "Storage encryption at rest is turned off",
    problem: "This resource explicitly disables encryption at rest (false or an empty KMS key).",
    why: "Snapshots, backups and detached volumes can be read in clear text if they are shared or leaked.",
    fix: [
      "Set the encryption flag to true and provide a KMS key.",
      "Encrypt existing data by restoring from an encrypted snapshot copy.",
    ],
    prompt:
      "Enable encryption at rest on this resource (storage_encrypted / encrypted = true with a KMS key) and describe how to migrate existing data.",
  },
  allowsHttp: {
    ruleId: "security_config/tf-cloudfront-allows-http",
    title: "Traffic is served over plain HTTP",
    problem:
      "This CloudFront behavior allows plain HTTP viewers, or this load balancer listener serves HTTP without redirecting to HTTPS.",
    why: "Sessions, tokens and documents sent over HTTP can be read and modified by anyone on the network path.",
    fix: [
      'Use viewer_protocol_policy = "redirect-to-https" (or "https-only").',
      "Make the HTTP listener only redirect to HTTPS.",
    ],
    prompt:
      'Change this resource so plain HTTP is never served: use viewer_protocol_policy "redirect-to-https" for CloudFront, or a redirect default action on the HTTP listener.',
  },
  mutableTags: {
    ruleId: "security_config/tf-mutable-image-tags",
    title: "Container registry allows mutable image tags",
    problem: 'This ECR repository sets image_tag_mutability = "MUTABLE".',
    why: "A tag such as latest can be overwritten, so what runs in production can change without a deploy and a compromised push replaces a trusted image.",
    fix: ['Set image_tag_mutability = "IMMUTABLE" and deploy by unique tag or digest.'],
    prompt:
      'Set image_tag_mutability = "IMMUTABLE" on this ECR repository and update the deploy pipeline to push unique tags.',
  },
} satisfies Record<string, RuleText>;

type RuleKey = keyof typeof RULES;
type Emit = (
  rule: RuleKey,
  line: number,
  severity: Severity,
  confidence: Confidence,
  extra?: { endLine?: number; discriminator?: string },
) => void;

const S3_ACL_TYPES = new Set([
  "aws_s3_bucket",
  "aws_s3_bucket_acl",
  "aws_s3_object",
  "aws_s3_bucket_object",
]);
const PUBLIC_ACLS = new Set(["public-read", "public-read-write", "authenticated-read"]);
const DB_PUBLIC_TYPES = new Set([
  "aws_db_instance",
  "aws_rds_cluster_instance",
  "aws_redshift_cluster",
]);
const IAM_POLICY_TYPES = new Set([
  "aws_iam_policy",
  "aws_iam_role_policy",
  "aws_iam_user_policy",
  "aws_iam_group_policy",
]);
const SENSITIVE_PORTS = [
  22, 3389, 5432, 3306, 1433, 1521, 27017, 6379, 9200, 5984, 11211, 2375, 2376, 9042,
];
const OIDC_ISSUER_RE = /(?:token\.actions\.githubusercontent\.com|gitlab\.com|app\.terraform\.io):/;
const OIDC_SUB_RE =
  /(?:token\.actions\.githubusercontent\.com|gitlab\.com|app\.terraform\.io):sub$/;
const FLAG_NAMES = [
  "block_public_acls",
  "block_public_policy",
  "ignore_public_acls",
  "restrict_public_buckets",
];

function flowOf(text: string, line: number): string {
  return text.split(/\r?\n/)[line - 1] ?? "";
}

/**
 * Terraform (`*.tf`) rules: public S3 buckets and policies, open security groups,
 * publicly accessible databases, wildcard IAM and OIDC trust policies, disabled
 * encryption, plain-HTTP delivery and mutable image tags. Reads literals only: values
 * that are variables, expressions or interpolations stay silent.
 */
export class TerraformDetector implements Detector {
  id = "terraform-detector";
  name = "Terraform Security";
  category = "security_config" as const;
  description =
    "Detects public S3 buckets, open security groups, public databases, wildcard IAM and OIDC trust, unencrypted storage, plain HTTP and mutable image tags in Terraform files.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (classifyPath(file) !== "terraform") continue;
      if (isTestOrFixturePath(file) && context.config.includeTests !== true) continue;
      try {
        const text = await context.readFile(file);
        if (text.trim() === "") continue;
        const blocks = parseHcl(text);
        const emit = (
          rule: RuleKey,
          line: number,
          severity: Severity,
          confidence: Confidence,
          extra?: { endLine?: number; discriminator?: string },
        ): void => {
          const r: RuleText = RULES[rule];
          findings.push(
            makeFinding({
              category: "security_config",
              ruleId: r.ruleId,
              title: r.title,
              severity,
              confidence,
              file,
              line,
              endLine: extra?.endLine,
              evidence: flowOf(text, line).trim(),
              discriminator: extra?.discriminator,
              plainEnglishProblem: r.problem,
              whyItMatters: r.why,
              fixSteps: r.fix,
              aiFixPrompt: r.prompt,
            }),
          );
        };
        const documents = new Map<string, HclBlock>();
        for (const b of blocks) {
          if (b.type === "data" && b.labels[0] === "aws_iam_policy_document" && b.labels[1]) {
            documents.set(b.labels[1], b);
          }
        }
        const oidcProviders = new Map<string, string>();
        for (const b of blocks) {
          if (
            b.type === "resource" &&
            b.labels[0] === "aws_iam_openid_connect_provider" &&
            b.labels[1]
          ) {
            oidcProviders.set(b.labels[1], hclString(attrOf(b, "url")?.value ?? "") ?? "");
          }
        }
        for (const b of blocks) {
          if (b.type === "resource") this.resource(b, emit, documents, oidcProviders);
          else if (b.type === "data" && b.labels[0] === "aws_iam_policy_document") {
            this.iamStatements(policyStatements(b), emit);
          }
        }
      } catch {
        // Never throw from a detector.
      }
    }
    return capFindingsPerRule(findings);
  }

  private resource(
    b: HclBlock,
    emit: Emit,
    documents: Map<string, HclBlock>,
    oidcProviders: Map<string, string>,
  ): void {
    const type = b.labels[0] ?? "";
    const val = (name: string): string | undefined => {
      const a = attrOf(b, name);
      return a ? hclString(a.value) : undefined;
    };
    const boolAttr = (name: string): HclAttr | undefined => attrOf(b, name);

    if (S3_ACL_TYPES.has(type)) {
      const acl = attrOf(b, "acl");
      const aclValue = acl ? hclString(acl.value) : undefined;
      if (acl && aclValue !== undefined && PUBLIC_ACLS.has(aclValue)) {
        emit("publicAcl", acl.line, aclValue === "public-read-write" ? "critical" : "high", "high");
      } else {
        for (const a of allAttrs(b)) {
          const uri = a.name === "uri" ? hclString(a.value) : undefined;
          if (uri !== undefined && /\/global\/(?:AllUsers|AuthenticatedUsers)$/.test(uri)) {
            emit("publicAcl", a.line, "high", "high");
            break;
          }
        }
      }
    }

    if (
      type === "aws_s3_bucket_public_access_block" ||
      type === "aws_s3_account_public_access_block"
    ) {
      for (const flag of FLAG_NAMES) {
        const a = boolAttr(flag);
        if (a && hclBool(a.value) === false) {
          emit("publicAccessBlock", a.line, "medium", "high");
          break;
        }
      }
    }

    if (type === "aws_s3_bucket_policy") {
      const policy = attrOf(b, "policy");
      if (policy) {
        let statements = policyStatements(policy);
        const ref = /^data\.aws_iam_policy_document\.([\w-]+)\.json$/.exec(policy.value.trim());
        const doc = ref?.[1] ? documents.get(ref[1]) : undefined;
        if (doc) statements = policyStatements(doc);
        for (const st of statements) {
          if (st.effect.toLowerCase() !== "allow" || st.conditions !== "") continue;
          if (st.principals.includes("*")) {
            emit("publicPolicy", st.principalLine, "high", "medium");
          }
        }
      }
    }

    if (DB_PUBLIC_TYPES.has(type)) {
      const a = boolAttr("publicly_accessible");
      if (a && hclBool(a.value) === true) emit("dbPublic", a.line, "high", "high");
    }

    if (type === "aws_security_group") {
      for (const ing of b.blocks.filter((x) => x.type === "ingress")) this.ingress(ing, emit);
    } else if (type === "aws_security_group_rule") {
      if (val("type") === "ingress") this.ingress(b, emit);
    } else if (type === "aws_vpc_security_group_ingress_rule") {
      this.ingress(b, emit);
    }

    if (IAM_POLICY_TYPES.has(type)) {
      const policy = attrOf(b, "policy");
      if (policy) this.iamStatements(policyStatements(policy), emit);
    } else if (type === "aws_iam_role") {
      for (const inline of b.blocks.filter((x) => x.type === "inline_policy")) {
        const policy = attrOf(inline, "policy");
        if (policy) this.iamStatements(policyStatements(policy), emit);
      }
    }

    if (type === "aws_iam_role") {
      const trust = attrOf(b, "assume_role_policy");
      if (trust) {
        let statements = policyStatements(trust);
        const ref = /^data\.aws_iam_policy_document\.([\w-]+)\.json$/.exec(trust.value.trim());
        const doc = ref?.[1] ? documents.get(ref[1]) : undefined;
        if (doc) statements = policyStatements(doc);
        this.oidcStatements(statements, emit, oidcProviders);
      }
    }

    if (DB_PUBLIC_TYPES.has(type) || type === "aws_rds_cluster") {
      const a = boolAttr("storage_encrypted");
      if (a && hclBool(a.value) === false) emit("storageUnencrypted", a.line, "medium", "high");
    }
    if (type === "aws_ebs_volume" || type === "aws_efs_file_system") {
      const a = boolAttr("encrypted");
      if (a && hclBool(a.value) === false) emit("storageUnencrypted", a.line, "medium", "high");
    }
    if (
      DB_PUBLIC_TYPES.has(type) ||
      type === "aws_rds_cluster" ||
      type === "aws_ebs_volume" ||
      type === "aws_efs_file_system"
    ) {
      const k = boolAttr("kms_key_id");
      if (k && hclString(k.value) === "") emit("storageUnencrypted", k.line, "medium", "high");
    }

    if (type === "aws_cloudfront_distribution") {
      for (const a of allAttrs(b)) {
        if (a.name === "viewer_protocol_policy" && hclString(a.value) === "allow-all") {
          emit("allowsHttp", a.line, "medium", "high");
        }
      }
    }
    if (type === "aws_lb_listener" || type === "aws_alb_listener") {
      const protocol = attrOf(b, "protocol");
      if (protocol && hclString(protocol.value)?.toUpperCase() === "HTTP") {
        const redirects = b.blocks.some(
          (d) =>
            d.type === "default_action" &&
            (hclString(attrOf(d, "type")?.value ?? "") === "redirect" ||
              d.blocks.some((x) => x.type === "redirect")),
        );
        if (!redirects) emit("allowsHttp", protocol.line, "medium", "high");
      }
    }

    if (type === "aws_ecr_repository") {
      const a = attrOf(b, "image_tag_mutability");
      if (a && hclString(a.value) === "MUTABLE") emit("mutableTags", a.line, "low", "high");
    }
  }

  private ingress(b: HclBlock, emit: Emit): void {
    let cidrLine: number | undefined;
    for (const name of ["cidr_blocks", "ipv6_cidr_blocks", "cidr_ipv4", "cidr_ipv6"]) {
      const a = attrOf(b, name);
      if (!a) continue;
      const list = hclStringList(a.value) ?? [];
      if (list.some((c) => c.trim() === "0.0.0.0/0" || c.trim() === "::/0")) {
        cidrLine = a.line;
        break;
      }
    }
    if (cidrLine === undefined) return;
    const proto = (
      hclString(attrOf(b, "protocol")?.value ?? attrOf(b, "ip_protocol")?.value ?? "") ?? ""
    ).toLowerCase();
    const allProtocols = proto === "-1" || proto === "all";
    if (allProtocols) {
      emit("openIngress", cidrLine, "high", "high");
      return;
    }
    if (proto !== "tcp" && proto !== "6") return;
    const from = Number(
      hclString(attrOf(b, "from_port")?.value ?? "") ?? attrOf(b, "from_port")?.value,
    );
    const to = Number(hclString(attrOf(b, "to_port")?.value ?? "") ?? attrOf(b, "to_port")?.value);
    if (!Number.isInteger(from) || !Number.isInteger(to)) return;
    if (SENSITIVE_PORTS.some((p) => p >= from && p <= to)) {
      emit("openIngress", cidrLine, "high", "high");
    }
  }

  private iamStatements(statements: PolicyStatement[], emit: Emit): void {
    for (const st of statements) {
      if (st.effect.toLowerCase() !== "allow") continue;
      if (!st.resources.includes("*")) continue;
      if (st.actions.includes("*") || st.notActions.length > 0) {
        emit("iamWildcard", st.actionLine, "high", "high");
      }
    }
  }

  private oidcStatements(
    statements: PolicyStatement[],
    emit: Emit,
    oidcProviders: Map<string, string>,
  ): void {
    for (const st of statements) {
      if (st.effect.toLowerCase() !== "allow") continue;
      if (!st.actions.some((a) => /AssumeRoleWithWebIdentity$/i.test(a))) continue;
      const subs = st.conditionEntries.filter((c) => OIDC_SUB_RE.test(c.key));
      if (subs.length > 0) {
        for (const c of subs) {
          if (!/like/i.test(c.operator)) continue;
          for (const raw of c.values) {
            const v = shape(raw);
            if (v === "*" || /^repo:\*(?::.*)?$/.test(v) || /^repo:[^:/*]*\/\*(?::.*)?$/.test(v)) {
              emit("oidcSubject", c.line, "high", "high");
              break;
            }
            if (/^repo:[^:/*]+\/[^:*]+:\*$/.test(v)) {
              emit("oidcSubject", c.line, "medium", "medium");
              break;
            }
          }
        }
        continue;
      }
      // No :sub condition at all: only when the federated principal is a CI OIDC provider.
      const ci =
        st.conditionEntries.some((c) => OIDC_ISSUER_RE.test(c.key)) ||
        st.federated.some((f) => isCiProvider(f, oidcProviders));
      if (ci) emit("oidcSubject", st.principalLine, "high", "high");
    }
  }
}

function shape(raw: string): string {
  return raw.replace(/\$\{[^}]*\}/g, "ORG");
}

function isCiProvider(federated: string, providers: Map<string, string>): boolean {
  if (/token\.actions\.githubusercontent\.com|gitlab\.com|app\.terraform\.io/.test(federated)) {
    return true;
  }
  const ref = /aws_iam_openid_connect_provider\.([\w-]+)/.exec(federated);
  if (!ref?.[1]) return false;
  const url = providers.get(ref[1]);
  if (url === undefined || url === "") return /github|gitlab/i.test(ref[1]);
  return /token\.actions\.githubusercontent\.com|gitlab\.com|app\.terraform\.io/.test(url);
}
