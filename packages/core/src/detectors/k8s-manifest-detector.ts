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
  containerField,
  containers,
  envOf,
  isK8sResource,
  listValues,
  parseK8sDocuments,
  podSpecEntries,
  type K8sDoc,
} from "./utils/k8s-manifest.js";
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
  privileged: {
    ruleId: "security_config/k8s-privileged-container",
    title: "Container runs in privileged mode",
    problem:
      "This container sets securityContext.privileged: true, giving it nearly all host capabilities.",
    why: "A privileged container can escape to the node: mount host disks, load kernel modules and take over every other workload on that node.",
    fix: [
      "Remove privileged: true and add only the specific capabilities the workload needs.",
      "Set allowPrivilegeEscalation: false and drop ALL capabilities by default.",
    ],
    prompt:
      "Remove privileged: true from this container's securityContext. Drop all capabilities and add back only the ones the workload really needs.",
  },
  hostNamespace: {
    ruleId: "security_config/k8s-host-namespace",
    title: "Pod shares a host namespace",
    problem:
      "This pod sets hostNetwork, hostPID or hostIPC to true, so it shares that namespace with the node.",
    why: "A pod in the host network or process namespace can sniff node traffic, see every process and reach node-local services such as the kubelet or metadata endpoint.",
    fix: [
      "Remove hostNetwork, hostPID and hostIPC unless this is a node-level agent that truly needs them.",
      "Expose the pod through a Service or hostPort instead.",
    ],
    prompt:
      "Remove hostNetwork/hostPID/hostIPC: true from this pod spec, or document why this node agent needs it and isolate it in its own namespace.",
  },
  hostPath: {
    ruleId: "security_config/k8s-host-path-mount",
    title: "Pod mounts a path from the host",
    problem: "This volume mounts a directory (or socket) of the node's filesystem into the pod.",
    why: "Mounting the host root, /etc, the container runtime socket or kubelet data lets a compromised pod read secrets, tamper with the node and escape the container.",
    fix: [
      "Use emptyDir, a PersistentVolumeClaim or a ConfigMap/Secret volume instead of hostPath.",
      "When hostPath is unavoidable, mount a narrow subdirectory read-only.",
    ],
    prompt:
      "Replace this hostPath volume with an emptyDir, PersistentVolumeClaim or ConfigMap/Secret volume. If a host path is required, mount only a narrow directory with readOnly: true.",
  },
  runsAsRoot: {
    ruleId: "security_config/k8s-runs-as-root",
    title: "Container is allowed to run as root or escalate privileges",
    problem:
      "This securityContext explicitly sets runAsUser 0, runAsNonRoot false or allowPrivilegeEscalation true.",
    why: "Root inside a container (and setuid escalation) makes any application bug or container escape far more damaging.",
    fix: [
      "Set runAsNonRoot: true with a numeric runAsUser such as 10001.",
      "Set allowPrivilegeEscalation: false and readOnlyRootFilesystem: true.",
    ],
    prompt:
      "Harden this securityContext: runAsNonRoot: true, a non-zero runAsUser, allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, and drop ALL capabilities.",
  },
  clusterAdmin: {
    ruleId: "security_config/k8s-cluster-admin-binding",
    title: "Workload identity is bound to cluster-admin",
    problem:
      "This binding gives a service account (or every authenticated/anonymous user) the cluster-admin role.",
    why: "Any compromise of that pod or user becomes full control of the cluster, including every secret in every namespace.",
    fix: [
      "Create a Role with only the verbs and resources the workload needs and bind that instead.",
      "Never bind system:authenticated or system:unauthenticated to powerful roles.",
    ],
    prompt:
      "Replace this cluster-admin binding with a least-privilege Role or ClusterRole limited to the resources the workload needs.",
  },
  wildcardRbac: {
    ruleId: "security_config/k8s-wildcard-rbac",
    title: "RBAC role allows every verb on every resource",
    problem: 'This role rule uses "*" for both verbs and resources.',
    why: "It is equivalent to cluster-admin within its scope, so any holder of the role can read secrets and change workloads.",
    fix: [
      "List explicit verbs and resources (and resourceNames when possible).",
      "Review who is bound to this role.",
    ],
    prompt:
      "Rewrite this RBAC rule so verbs and resources are explicit lists instead of '*', limited to what the subject needs.",
  },
  debug: {
    ruleId: "security_config/k8s-debug-enabled",
    title: "Debug mode or wildcard allowed hosts in a deployment",
    problem: "This container environment turns debug mode on or sets ALLOWED_HOSTS to '*'.",
    why: "Debug pages leak settings, secrets and stack traces; a wildcard host list disables Host header validation.",
    fix: [
      "Set DEBUG to false (or remove it) in the deployed manifest.",
      "List the real host names in ALLOWED_HOSTS.",
    ],
    prompt:
      "Set DEBUG to a false value and replace the ALLOWED_HOSTS wildcard with the real hostnames in this Kubernetes manifest.",
  },
  ingressHttp: {
    ruleId: "security_config/k8s-ingress-plain-http",
    title: "Ingress serves traffic over plain HTTP",
    problem:
      "This Ingress disables the HTTPS redirect, or exposes hosts without any TLS configuration.",
    why: "Credentials and session cookies cross the network in clear text and can be read or modified in transit.",
    fix: [
      "Add a spec.tls section with a certificate (cert-manager works well).",
      'Remove ssl-redirect: "false" so HTTP redirects to HTTPS.',
    ],
    prompt:
      'Add spec.tls for the hosts of this Ingress and make sure HTTP redirects to HTTPS (remove ssl-redirect: "false").',
  },
  mutableImage: {
    ruleId: "security_config/k8s-mutable-image-tag",
    title: "Container image uses a mutable tag",
    problem: "This container image has no tag, or uses :latest, and no digest.",
    why: "The image behind a mutable tag can change between restarts, so deploys are not reproducible and a poisoned push goes live silently.",
    fix: ["Pin the image to a version tag or, better, an @sha256 digest."],
    prompt:
      "Pin this container image to an immutable version tag or sha256 digest instead of :latest or no tag.",
  },
} satisfies Record<string, RuleText>;

type RuleKey = keyof typeof RULES;

const RISKY_HOST_PATHS = new Set([
  "/",
  "/etc",
  "/root",
  "/proc",
  "/sys",
  "/var/run/docker.sock",
  "/run/docker.sock",
  "/run/containerd/containerd.sock",
  "/var/run/containerd/containerd.sock",
  "/var/lib/kubelet",
  "/home",
]);
const DEBUG_ENV_RE = /^(?:DJANGO_|FLASK_|APP_|RAILS_)?DEBUG$/;

const isTemplated = (v: string): boolean => v.includes("{{");
const isTrue = (v: string): boolean => /^(?:true|yes)$/i.test(unquoteYaml(v));
const isFalse = (v: string): boolean => /^(?:false|no)$/i.test(unquoteYaml(v));

/**
 * Kubernetes manifest rules for workloads, RBAC and Ingress. Only documents with a
 * top-level apiVersion and kind are read; values with Helm template syntax are skipped.
 */
export class K8sManifestDetector implements Detector {
  id = "k8s-manifest-detector";
  name = "Kubernetes Manifest Security";
  category = "security_config" as const;
  description =
    "Detects privileged containers, host mounts, root users, cluster-admin bindings, wildcard RBAC, debug mode, plain-HTTP Ingress and mutable image tags in Kubernetes manifests.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (classifyPath(file) !== "k8s-manifest") continue;
      if (isTestOrFixturePath(file) && context.config.includeTests !== true) continue;
      try {
        const text = await context.readFile(file);
        if (text.trim() === "" || !text.includes("apiVersion")) continue;
        const lines = text.split(/\r?\n/);
        const emit = (
          rule: RuleKey,
          line: number,
          severity: Severity,
          confidence: Confidence,
          discriminator?: string,
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
              evidence: (lines[line - 1] ?? "").trim(),
              discriminator,
              plainEnglishProblem: r.problem,
              whyItMatters: r.why,
              fixSteps: r.fix,
              aiFixPrompt: r.prompt,
            }),
          );
        };
        for (const doc of parseK8sDocuments(text)) {
          if (!isK8sResource(doc)) continue;
          this.workload(doc, emit);
          this.rbac(doc, emit);
          this.ingress(doc, emit);
        }
      } catch {
        // Never throw from a detector.
      }
    }
    return capFindingsPerRule(findings);
  }

  private workload(
    doc: K8sDoc,
    emit: (r: RuleKey, line: number, s: Severity, c: Confidence, d?: string) => void,
  ): void {
    for (const spec of podSpecEntries(doc)) {
      const at = (...rel: string[]): YamlEntry | undefined =>
        spec.entries.find(
          (e) =>
            e.kind === "key" &&
            e.path.length === spec.prefix.length + rel.length &&
            [...spec.prefix, ...rel].every((seg, i) => e.path[i] === seg),
        );
      for (const key of ["hostNetwork", "hostPID", "hostIPC"]) {
        const e = at(key);
        if (e && isTrue(e.value) && !isTemplated(e.value))
          emit("hostNamespace", e.line, "medium", "high", key);
      }
      for (const e of spec.entries) {
        const p = e.path;
        const n = spec.prefix.length;
        if (
          e.kind === "key" &&
          e.key === "path" &&
          p.length === n + 4 &&
          p[n] === "volumes" &&
          p[n + 2] === "hostPath"
        ) {
          const v = unquoteYaml(e.value).replace(/(.)\/+$/, "$1");
          if (v === "" || isTemplated(v)) continue;
          if (RISKY_HOST_PATHS.has(v)) emit("hostPath", e.line, "high", "high");
          else emit("hostPath", e.line, "medium", "medium");
        }
      }
      // Pod-level securityContext.
      const podCtx = spec.entries.filter(
        (e) =>
          e.kind === "key" &&
          e.path.length === spec.prefix.length + 2 &&
          e.path[spec.prefix.length] === "securityContext",
      );
      this.rootRule(podCtx, emit);
    }
    for (const c of containers(doc)) {
      const priv = containerField(c, "securityContext", "privileged");
      if (priv && isTrue(priv.value) && !isTemplated(priv.value)) {
        emit("privileged", priv.line, "high", "high");
      }
      const ctx = c.entries.filter(
        (e) =>
          e.kind === "key" &&
          e.path.length === c.path.length + 2 &&
          e.path[c.path.length] === "securityContext",
      );
      this.rootRule(ctx, emit);

      const image = containerField(c, "image");
      if (image) this.image(image, emit);

      for (const env of envOf(c)) {
        if (env.valueFrom || env.value === undefined || env.valueLine === undefined) continue;
        if (isTemplated(env.value)) continue;
        const v = env.value.trim();
        if (DEBUG_ENV_RE.test(env.name) && /^(?:true|1|yes)$/i.test(v)) {
          emit("debug", env.valueLine, "medium", "high");
        } else if (env.name === "ALLOWED_HOSTS" && v === "*") {
          emit("debug", env.valueLine, "medium", "high");
        }
      }
    }
  }

  private rootRule(
    ctx: YamlEntry[],
    emit: (r: RuleKey, line: number, s: Severity, c: Confidence, d?: string) => void,
  ): void {
    for (const e of ctx) {
      const v = e.value;
      if (isTemplated(v)) continue;
      const bad =
        (e.key === "runAsUser" && unquoteYaml(v) === "0") ||
        (e.key === "runAsNonRoot" && isFalse(v)) ||
        (e.key === "allowPrivilegeEscalation" && isTrue(v));
      if (bad) {
        emit("runsAsRoot", e.line, "medium", "high");
        return;
      }
    }
  }

  private image(
    entry: YamlEntry,
    emit: (r: RuleKey, line: number, s: Severity, c: Confidence, d?: string) => void,
  ): void {
    const v = unquoteYaml(entry.value);
    if (v === "" || isTemplated(v) || v.includes("$") || v.includes("@sha256:")) return;
    const last = v.slice(v.lastIndexOf("/") + 1);
    const colon = last.indexOf(":");
    const tag = colon === -1 ? "" : last.slice(colon + 1);
    if (tag === "" || tag === "latest") emit("mutableImage", entry.line, "low", "high");
  }

  private rbac(
    doc: K8sDoc,
    emit: (r: RuleKey, line: number, s: Severity, c: Confidence, d?: string) => void,
  ): void {
    if (doc.kind === "ClusterRoleBinding" || doc.kind === "RoleBinding") {
      const roleName = doc.entries.find(
        (e) =>
          e.kind === "key" && e.path.length === 2 && e.path[0] === "roleRef" && e.key === "name",
      );
      if (!roleName) return;
      const role = unquoteYaml(roleName.value);
      if (isTemplated(role)) return;
      if (role !== "cluster-admin" && !(role === "admin" && doc.kind === "ClusterRoleBinding"))
        return;
      const subjects = new Map<string, Record<string, string>>();
      for (const e of doc.entries) {
        if (e.kind === "key" && e.path.length === 3 && e.path[0] === "subjects" && e.key) {
          const idx = e.path[1] ?? "";
          const rec = subjects.get(idx) ?? {};
          rec[e.key] = unquoteYaml(e.value);
          subjects.set(idx, rec);
        }
      }
      for (const s of subjects.values()) {
        const kind = s.kind ?? "";
        const name = s.name ?? "";
        const ns = s.namespace ?? doc.namespace ?? "";
        const sa = kind === "ServiceAccount" && ns !== "kube-system" && !isTemplated(name);
        const everyone =
          (kind === "Group" &&
            (name === "system:authenticated" || name === "system:unauthenticated")) ||
          (kind === "User" && name === "system:anonymous");
        if (sa || everyone) {
          emit("clusterAdmin", roleName.line, "high", "high");
          return;
        }
      }
      return;
    }
    if (doc.kind === "ClusterRole" || doc.kind === "Role") {
      const rules = new Set<string>();
      for (const e of doc.entries) {
        if (e.path[0] === "rules" && e.path.length >= 2) rules.add(e.path[1] ?? "");
      }
      for (const idx of rules) {
        const verbs = listValues(doc, ["rules", idx, "verbs"]);
        const resources = listValues(doc, ["rules", idx, "resources"]);
        if (verbs.some((v) => v.value === "*") && resources.some((r) => r.value === "*")) {
          emit(
            "wildcardRbac",
            verbs.find((v) => v.value === "*")?.line ?? doc.startLine,
            "high",
            "medium",
          );
        }
      }
    }
  }

  private ingress(
    doc: K8sDoc,
    emit: (r: RuleKey, line: number, s: Severity, c: Confidence, d?: string) => void,
  ): void {
    if (doc.kind !== "Ingress") return;
    const annotations = doc.entries.filter(
      (e) =>
        e.kind === "key" &&
        e.path.length === 3 &&
        e.path[0] === "metadata" &&
        e.path[1] === "annotations",
    );
    let reported = false;
    for (const a of annotations) {
      const key = a.key ?? "";
      const v = unquoteYaml(a.value);
      if (isTemplated(v)) continue;
      if (/(?:^|\/)(?:force-)?ssl-redirect$/.test(key) && /nginx/.test(key) && /^false$/i.test(v)) {
        emit("ingressHttp", a.line, "medium", "high");
        reported = true;
      } else if (
        /traefik\.ingress\.kubernetes\.io\/router\.entrypoints$/.test(key) &&
        v === "web"
      ) {
        emit("ingressHttp", a.line, "medium", "high");
        reported = true;
      }
    }
    if (reported) return;
    const terminatesTls = annotations.some((a) =>
      /certificate|managed-certificates|ssl-cert|cert-manager|tls/i.test(a.key ?? ""),
    );
    const hasTls = doc.entries.some((e) => e.path[0] === "spec" && e.path[1] === "tls");
    const hosts = doc.entries.some(
      (e) =>
        e.kind === "key" &&
        e.key === "host" &&
        e.path.length === 4 &&
        e.path[0] === "spec" &&
        e.path[1] === "rules" &&
        unquoteYaml(e.value) !== "" &&
        !isTemplated(e.value),
    );
    if (hosts && !hasTls && !terminatesTls) {
      const kindLine =
        doc.entries.find((e) => e.kind === "key" && e.path.length === 1 && e.key === "kind")
          ?.line ?? doc.startLine;
      emit("ingressHttp", kindLine, "medium", "medium");
    }
  }
}
