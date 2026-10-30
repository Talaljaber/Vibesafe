import type {
  Confidence,
  Detector,
  Finding,
  ScanContext,
  Severity,
} from "@talaljaber/vibesafe-shared";
import { classifyPath, isTestOrFixturePath } from "./utils/file-kind.js";
import { makeFinding } from "./utils/finding.js";
import {
  capFindingsPerRule,
  credentialNameKind,
  findUrlCredential,
  hasSpecificSecret,
  isPlaceholderValue,
  looksLikeSecretValue,
} from "./utils/infra-common.js";
import {
  allAttrs,
  attrOf,
  hclString,
  parseHcl,
  topLevelAttrs,
  type HclBlock,
} from "./utils/hcl.js";
import { isK8sResource, parseK8sDocuments, type K8sDoc } from "./utils/k8s-manifest.js";
import { unquoteYaml, type YamlEntry } from "./utils/yaml-lines.js";

interface RuleText {
  ruleId: string;
  title: string;
  problem: string;
  why: string;
  fix: string[];
  prompt: string;
}

const RULES = {
  secretManifest: {
    ruleId: "secret/k8s-secret-manifest",
    title: "Kubernetes Secret with a real value is committed",
    problem:
      "This Secret manifest carries credential values in the repository. base64 in `data` is an encoding, not encryption: anyone who can read the repo can decode it.",
    why: "Committed credentials stay in git history and are usable by anyone with repository access until they are rotated.",
    fix: [
      "Rotate the exposed values now, then remove them from the manifest and from git history.",
      "Create the Secret out of band, or use Sealed Secrets, SOPS or the External Secrets Operator so only encrypted or referenced values are committed.",
    ],
    prompt:
      "This Kubernetes Secret manifest contains real credentials. Remove the values, switch to SealedSecret, SOPS or ExternalSecret, and list the credentials that must be rotated.",
  },
  configMapCredential: {
    ruleId: "secret/k8s-configmap-credential",
    title: "Credential stored in a Kubernetes ConfigMap",
    problem:
      "A credential-looking key in this ConfigMap holds a literal value. ConfigMaps are not access-controlled or encrypted like Secrets.",
    why: "Anyone who can read ConfigMaps in the namespace, and everyone with repository access, can read the credential.",
    fix: [
      "Move the value into a Secret (or an external secret store) and reference it with secretKeyRef.",
      "Rotate the credential because it has been committed.",
    ],
    prompt:
      "Move the credential out of this ConfigMap into a Secret referenced via secretKeyRef (or an external secrets manager), and rotate the exposed value.",
  },
  terraformCredential: {
    ruleId: "secret/terraform-literal-credential",
    title: "Credential hard-coded in Terraform",
    problem:
      "A credential-named Terraform variable, tfvars entry or resource attribute holds a literal value that is committed to the repository.",
    why: "Terraform files and state end up in git and CI logs; a literal password or key is exposed to everyone with access and stays in history.",
    fix: [
      "Rotate the credential, then remove the literal.",
      "Pass it through an environment variable (TF_VAR_...), a secrets manager data source or `manage_master_user_password`, and mark the variable sensitive = true.",
    ],
    prompt:
      "Remove the hard-coded credential from this Terraform file. Read it from a secrets manager or a TF_VAR_ environment variable, mark the variable sensitive, and rotate the exposed value.",
  },
} satisfies Record<string, RuleText>;

type RuleKey = keyof typeof RULES;
type Emit = (
  rule: RuleKey,
  line: number,
  severity: Severity,
  confidence: Confidence,
  evidence: string,
) => void;

const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const PUBLIC_CERT_KEY_RE = /(?:^|[./_-])(?:crt|cert|cer|certificate|ca)(?:$|[./_-])|\.pem$/i;

function printable(s: string): boolean {
  return !/[\u0000-\u0008\u000b\u000c\u000e-\u001f�]/.test(s);
}

/** Decodes standard base64 to printable UTF-8, or undefined. */
function decodeBase64(value: string): string | undefined {
  const v = value.replace(/\s+/g, "");
  if (v.length < 8 || v.length > 20000 || v.length % 4 === 1 || !BASE64_RE.test(v))
    return undefined;
  const decoded = Buffer.from(v, "base64").toString("utf8");
  return printable(decoded) ? decoded : undefined;
}

/** Inline value of a key entry, or the joined block-scalar lines. */
function valueOfKey(entries: YamlEntry[], index: number): string {
  const e = entries[index];
  if (!e) return "";
  if (!/^[|>]/.test(e.value)) return unquoteYaml(e.value);
  const lines: string[] = [];
  for (let j = index + 1; j < entries.length; j++) {
    const n = entries[j];
    if (n && n.kind === "block" && n.path.length === e.path.length) lines.push(n.value);
    else break;
  }
  return lines.join("\n");
}

/**
 * Secrets stored in infrastructure files that the generic secret detector does not
 * understand: Kubernetes Secret manifests (base64 is not protection), credentials in
 * ConfigMaps, and literal credentials in Terraform and tfvars. Lines that a specific
 * token pattern matches are skipped here because the secret detector reports them.
 */
export class IacSecretDetector implements Detector {
  id = "iac-secret-detector";
  name = "IaC Secret Detection";
  category = "secret" as const;
  description =
    "Detects real credentials in Kubernetes Secret and ConfigMap manifests and literal credentials in Terraform and tfvars files.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of context.files) {
      const kind = classifyPath(file);
      if (kind !== "k8s-manifest" && kind !== "terraform" && kind !== "tfvars") continue;
      if (isTestOrFixturePath(file) && context.config.includeTests !== true) continue;
      try {
        const text = await context.readFile(file);
        if (text.trim() === "") continue;
        const lines = text.split(/\r?\n/);
        const emit: Emit = (rule, line, severity, confidence, evidence) => {
          const r: RuleText = RULES[rule];
          findings.push(
            makeFinding({
              category: "secret",
              ruleId: r.ruleId,
              title: r.title,
              severity,
              confidence,
              file,
              line,
              evidence,
              plainEnglishProblem: r.problem,
              whyItMatters: r.why,
              fixSteps: r.fix,
              aiFixPrompt: r.prompt,
            }),
          );
        };
        const known = (line: number): boolean => hasSpecificSecret(lines[line - 1] ?? "");
        if (kind === "k8s-manifest") {
          if (!text.includes("apiVersion")) continue;
          for (const doc of parseK8sDocuments(text)) {
            if (!isK8sResource(doc)) continue;
            if (doc.kind === "Secret") this.secretDoc(doc, emit, known);
            else if (doc.kind === "ConfigMap") this.configMapDoc(doc, emit, known);
          }
        } else {
          this.terraform(parseHcl(text), emit, known, kind === "tfvars");
        }
      } catch {
        // Never throw from a detector.
      }
    }
    return capFindingsPerRule(findings);
  }

  private secretDoc(doc: K8sDoc, emit: Emit, known: (line: number) => boolean): void {
    const entries = doc.entries;
    for (let i = 0; i < entries.length; i++) {
      const e = entries[i];
      if (!e || e.kind !== "key" || e.path.length !== 2 || !e.key) continue;
      const section = e.path[0];
      if (section !== "data" && section !== "stringData") continue;
      if (known(e.line)) continue;
      const raw = valueOfKey(entries, i);
      if (raw.trim() === "" || raw.includes("{{")) continue;
      if (PUBLIC_CERT_KEY_RE.test(e.key)) continue;
      const value = section === "data" ? decodeBase64(raw) : raw;
      if (value === undefined) continue;
      const trimmed = value.trim();
      if (trimmed.length < 8 || isPlaceholderValue(trimmed) || trimmed.includes("${")) continue;
      const strong = hasSpecificSecret(trimmed) || findUrlCredential(trimmed) !== undefined;
      emit("secretManifest", e.line, strong ? "critical" : "high", "high", `${e.key}: <redacted>`);
    }
  }

  private configMapDoc(doc: K8sDoc, emit: Emit, known: (line: number) => boolean): void {
    const entries = doc.entries;
    for (let i = 0; i < entries.length; i++) {
      const e = entries[i];
      if (!e || e.kind !== "key" || e.path.length !== 2 || e.path[0] !== "data" || !e.key) continue;
      const nameKind = credentialNameKind(e.key);
      if (nameKind === undefined || /^[|>]/.test(e.value)) continue;
      if (known(e.line)) continue;
      const value = unquoteYaml(e.value);
      if (value.includes("{{") || !looksLikeSecretValue(value)) continue;
      if (nameKind === "connection" && findUrlCredential(value) === undefined) continue;
      emit("configMapCredential", e.line, "high", "medium", `${e.key}: <redacted>`);
    }
  }

  private terraform(
    blocks: HclBlock[],
    emit: Emit,
    known: (line: number) => boolean,
    isTfvars: boolean,
  ): void {
    const check = (name: string, valueRaw: string, line: number): void => {
      const nameKind = credentialNameKind(name);
      if (nameKind === undefined) return;
      const value = hclString(valueRaw);
      if (value === undefined || known(line)) return;
      if (!looksLikeSecretValue(value) || isPlaceholderValue(value)) return;
      if (nameKind === "connection" && findUrlCredential(value) === undefined) return;
      emit("terraformCredential", line, "high", "high", `${name} = <redacted>`);
    };
    for (const a of topLevelAttrs(blocks)) check(a.name, a.value, a.line);
    if (isTfvars) return;
    for (const b of blocks) {
      if (b.type === "variable") {
        const def = attrOf(b, "default");
        const name = b.labels[0];
        if (def && name) check(name, def.value, def.line);
        continue;
      }
      if (b.type === "terraform" || b.type === "") continue;
      for (const a of allAttrs(b)) check(a.name, a.value, a.line);
    }
  }
}
