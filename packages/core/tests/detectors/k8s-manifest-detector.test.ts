import { describe, it, expect } from "vitest";
import type { Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { K8sManifestDetector } from "../../src/detectors/k8s-manifest-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const createContext = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake",
  projectContext: {} as ScanContext["projectContext"],
  files: Object.keys(files),
  config: { rootPath: "/fake" },
  readFile: async (f) => files[f] ?? "",
});

const run = async (yaml: string, file = "k8s/app.yaml"): Promise<Finding[]> => {
  const files = { [file]: yaml };
  const findings = await new K8sManifestDetector().detect(createContext(files));
  expectRubric(findings);
  const again = await new K8sManifestDetector().detect(createContext(files));
  expect(again.map((f) => f.id)).toEqual(findings.map((f) => f.id));
  return findings;
};

const rule = (findings: Finding[], slug: string): Finding[] =>
  findings.filter((f) => f.ruleId === `security_config/${slug}`);

const y = (...lines: string[]): string => lines.join("\n") + "\n";

/** A Deployment whose container body (indented 10 spaces) and pod spec extras are supplied. */
const deployment = (
  container: string[],
  podExtra: string[] = [],
  image = "acme/app:1.4.2",
): string =>
  y(
    "apiVersion: apps/v1",
    "kind: Deployment",
    "metadata:",
    "  name: app",
    "spec:",
    "  template:",
    "    spec:",
    ...podExtra.map((l) => `      ${l}`),
    "      containers:",
    "        - name: app",
    `          image: ${image}`,
    ...container.map((l) => `          ${l}`),
  );

describe("K8sManifestDetector: privileged and root", () => {
  it("flags privileged: true on the privileged line", async () => {
    const f = rule(
      await run(deployment(["securityContext:", "  privileged: true"])),
      "k8s-privileged-container",
    );
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ line: 12, severity: "high", confidence: "high" });
  });

  it("flags privileged containers in a CronJob and in init containers", async () => {
    const cron = y(
      "apiVersion: batch/v1",
      "kind: CronJob",
      "metadata:",
      "  name: job",
      "spec:",
      "  jobTemplate:",
      "    spec:",
      "      template:",
      "        spec:",
      "          initContainers:",
      "            - name: init",
      "              image: acme/init:1.0.0",
      "              securityContext:",
      "                privileged: true",
      "          containers:",
      "            - name: main",
      "              image: acme/main:1.0.0",
      "              securityContext:",
      "                privileged: true",
    );
    expect(
      rule(await run(cron), "k8s-privileged-container")
        .map((x) => x.line)
        .sort((a, b) => (a ?? 0) - (b ?? 0)),
    ).toEqual([14, 19]);
  });

  it.each([
    ["privileged false", ["securityContext:", "  privileged: false"]],
    ["no securityContext", []],
    ["helm template value", ["securityContext:", "  privileged: {{ .Values.privileged }}"]],
  ])("is silent for %s", async (_n, container) => {
    expect(rule(await run(deployment(container)), "k8s-privileged-container")).toEqual([]);
  });

  it("flags runAsUser 0, runAsNonRoot false and allowPrivilegeEscalation true", async () => {
    for (const line of ["runAsUser: 0", "runAsNonRoot: false", "allowPrivilegeEscalation: true"]) {
      const f = rule(await run(deployment(["securityContext:", `  ${line}`])), "k8s-runs-as-root");
      expect(f, line).toHaveLength(1);
      expect(f[0]).toMatchObject({ severity: "medium", confidence: "high", line: 12 });
    }
  });

  it("flags pod-level securityContext", async () => {
    const f = rule(
      await run(deployment([], ["securityContext:", "  runAsUser: 0"])),
      "k8s-runs-as-root",
    );
    expect(f).toHaveLength(1);
  });

  it.each([
    ["non-root user", ["securityContext:", "  runAsUser: 1000", "  runAsNonRoot: true"]],
    ["escalation off", ["securityContext:", "  allowPrivilegeEscalation: false"]],
    ["missing securityContext", []],
  ])("is silent for %s", async (_n, container) => {
    expect(rule(await run(deployment(container)), "k8s-runs-as-root")).toEqual([]);
  });
});

describe("K8sManifestDetector: host namespaces and hostPath", () => {
  it("flags hostNetwork, hostPID and hostIPC", async () => {
    const f = rule(
      await run(deployment([], ["hostNetwork: true", "hostPID: true", "hostIPC: true"])),
      "k8s-host-namespace",
    );
    expect(f).toHaveLength(3);
    expect(f[0]).toMatchObject({ severity: "medium", confidence: "high" });
  });

  it("is silent for false, missing and other kinds", async () => {
    expect(rule(await run(deployment([], ["hostNetwork: false"])), "k8s-host-namespace")).toEqual(
      [],
    );
    const svc = y("apiVersion: v1", "kind: Service", "spec:", "  hostNetwork: true");
    expect(rule(await run(svc), "k8s-host-namespace")).toEqual([]);
    expect(rule(await run(deployment([])), "k8s-host-namespace")).toEqual([]);
  });

  const vol = (path: string): string[] => [
    "volumes:",
    "  - name: host",
    "    hostPath:",
    `      path: ${path}`,
  ];

  it.each([
    "/",
    "/etc",
    "/var/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/var/lib/kubelet",
    "/home",
    "/root",
    "/proc",
    "/sys",
  ])("flags hostPath %s as high", async (p) => {
    const f = rule(await run(deployment([], vol(p))), "k8s-host-path-mount");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "high", confidence: "high", line: 11 });
  });

  it("flags other host paths as medium/medium on the path line", async () => {
    const f = rule(await run(deployment([], vol("/var/log"))), "k8s-host-path-mount");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "medium", confidence: "medium", line: 11 });
  });

  it("is silent for emptyDir, PVC volumes and templated paths", async () => {
    const tmpl = deployment([], vol("{{ .Values.hostPath }}"));
    expect(rule(await run(tmpl), "k8s-host-path-mount")).toEqual([]);
    const empty = deployment([], ["volumes:", "  - name: scratch", "    emptyDir: {}"]);
    expect(rule(await run(empty), "k8s-host-path-mount")).toEqual([]);
    const pvc = deployment(
      [],
      ["volumes:", "  - name: data", "    persistentVolumeClaim:", "      claimName: data"],
    );
    expect(rule(await run(pvc), "k8s-host-path-mount")).toEqual([]);
  });
});

describe("K8sManifestDetector: RBAC", () => {
  const binding = (
    subject: string[],
    role = "cluster-admin",
    kind = "ClusterRoleBinding",
  ): string =>
    y(
      "apiVersion: rbac.authorization.k8s.io/v1",
      `kind: ${kind}`,
      "metadata:",
      "  name: b",
      "subjects:",
      ...subject,
      "roleRef:",
      "  kind: ClusterRole",
      `  name: ${role}`,
      "  apiGroup: rbac.authorization.k8s.io",
    );

  it("flags a ServiceAccount outside kube-system on the roleRef name line", async () => {
    const f = rule(
      await run(binding(["  - kind: ServiceAccount", "    name: web", "    namespace: shop"])),
      "k8s-cluster-admin-binding",
    );
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ line: 11, severity: "high", confidence: "high" });
  });

  it("flags system:authenticated and unauthenticated groups, and admin in a ClusterRoleBinding", async () => {
    for (const name of ["system:authenticated", "system:unauthenticated"]) {
      const f = rule(
        await run(binding(["  - kind: Group", `    name: ${name}`])),
        "k8s-cluster-admin-binding",
      );
      expect(f, name).toHaveLength(1);
    }
    const admin = binding(
      ["  - kind: ServiceAccount", "    name: w", "    namespace: shop"],
      "admin",
    );
    expect(rule(await run(admin), "k8s-cluster-admin-binding")).toHaveLength(1);
  });

  it.each([
    ["system:masters", ["  - kind: Group", "    name: system:masters"], "cluster-admin"],
    [
      "kube-system service account",
      ["  - kind: ServiceAccount", "    name: x", "    namespace: kube-system"],
      "cluster-admin",
    ],
    ["view role", ["  - kind: ServiceAccount", "    name: x", "    namespace: shop"], "view"],
    ["a user", ["  - kind: User", "    name: alice"], "cluster-admin"],
  ])("is silent for %s", async (_n, subject, role) => {
    expect(rule(await run(binding(subject, role)), "k8s-cluster-admin-binding")).toEqual([]);
  });

  it("flags wildcard verbs and resources", async () => {
    const role = y(
      "apiVersion: rbac.authorization.k8s.io/v1",
      "kind: ClusterRole",
      "metadata:",
      "  name: all",
      "rules:",
      "  - apiGroups: ['*']",
      "    resources: ['*']",
      "    verbs: ['*']",
      "  - apiGroups: ['']",
      "    resources:",
      '      - "*"',
      "    verbs:",
      "      - '*'",
    );
    const f = rule(await run(role), "k8s-wildcard-rbac");
    expect(f).toHaveLength(2);
    expect(f[0]).toMatchObject({ severity: "high", confidence: "medium" });
  });

  it("is silent for explicit rules and a wildcard on only one side", async () => {
    const role = y(
      "apiVersion: rbac.authorization.k8s.io/v1",
      "kind: Role",
      "metadata:",
      "  name: reader",
      "rules:",
      "  - apiGroups: ['']",
      "    resources: ['pods', 'services']",
      "    verbs: ['get', 'list']",
      "  - apiGroups: ['*']",
      "    resources: ['configmaps']",
      "    verbs: ['get']",
      "  - apiGroups: ['']",
      "    resources: ['*']",
      "    verbs: ['get']",
    );
    expect(rule(await run(role), "k8s-wildcard-rbac")).toEqual([]);
  });
});

describe("K8sManifestDetector: debug", () => {
  const env = (name: string, value: string): string[] => [
    "env:",
    `  - name: ${name}`,
    `    value: ${value}`,
  ];

  it.each([
    ["DEBUG", '"True"'],
    ["DJANGO_DEBUG", "true"],
    ["FLASK_DEBUG", '"1"'],
    ["ALLOWED_HOSTS", '"*"'],
  ])("flags %s=%s on the value line", async (name, value) => {
    const f = rule(await run(deployment(env(name, value))), "k8s-debug-enabled");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ line: 13, severity: "medium", confidence: "high" });
  });

  it.each([
    ["DEBUG", '"False"'],
    ["DEBUG", "false"],
    ["LOG_DEBUG_LEVEL", "true"],
    ["ALLOWED_HOSTS", "app.example.com"],
    ["DEBUG", "{{ .Values.debug }}"],
  ])("is silent for %s=%s", async (name, value) => {
    expect(rule(await run(deployment(env(name, value))), "k8s-debug-enabled")).toEqual([]);
  });

  it("is silent for values read from a secret or configmap", async () => {
    const c = [
      "env:",
      "  - name: DEBUG",
      "    valueFrom:",
      "      configMapKeyRef:",
      "        name: cfg",
      "        key: debug",
    ];
    expect(rule(await run(deployment(c)), "k8s-debug-enabled")).toEqual([]);
  });
});

describe("K8sManifestDetector: ingress", () => {
  const ingress = (annotations: string[], tls: string[] = [], host = "app.example.com"): string =>
    y(
      "apiVersion: networking.k8s.io/v1",
      "kind: Ingress",
      "metadata:",
      "  name: web",
      ...(annotations.length > 0 ? ["  annotations:", ...annotations.map((a) => `    ${a}`)] : []),
      "spec:",
      ...tls.map((l) => `  ${l}`),
      "  rules:",
      `    - host: ${host}`,
      "      http:",
      "        paths:",
      "          - path: /",
    );

  it("flags ssl-redirect false at medium/high on the annotation line", async () => {
    for (const key of ["ssl-redirect", "force-ssl-redirect"]) {
      const f = rule(
        await run(
          ingress(
            [`nginx.ingress.kubernetes.io/${key}: "false"`],
            ["tls:", "  - hosts: [app.example.com]"],
          ),
        ),
        "k8s-ingress-plain-http",
      );
      expect(f, key).toHaveLength(1);
      expect(f[0]).toMatchObject({ line: 6, severity: "medium", confidence: "high" });
    }
  });

  it("flags an ingress with hosts and no tls at medium/medium on the kind line", async () => {
    const f = rule(await run(ingress([])), "k8s-ingress-plain-http");
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ line: 2, severity: "medium", confidence: "medium" });
  });

  it("flags a Traefik web-only entrypoint", async () => {
    const f = rule(
      await run(ingress(["traefik.ingress.kubernetes.io/router.entrypoints: web"])),
      "k8s-ingress-plain-http",
    );
    expect(f).toHaveLength(1);
    expect(f[0]!.confidence).toBe("high");
  });

  it("is silent with tls, an https redirect, a TLS-terminating load balancer or no hosts", async () => {
    const tls = ["tls:", "  - hosts: [app.example.com]", "    secretName: web-tls"];
    expect(rule(await run(ingress([], tls)), "k8s-ingress-plain-http")).toEqual([]);
    expect(
      rule(
        await run(ingress(['nginx.ingress.kubernetes.io/ssl-redirect: "true"'], tls)),
        "k8s-ingress-plain-http",
      ),
    ).toEqual([]);
    expect(
      rule(
        await run(ingress(["alb.ingress.kubernetes.io/certificate-arn: arn:aws:acm:x"])),
        "k8s-ingress-plain-http",
      ),
    ).toEqual([]);
    expect(
      rule(await run(ingress([], [], "{{ .Values.host }}")), "k8s-ingress-plain-http"),
    ).toEqual([]);
  });
});

describe("K8sManifestDetector: mutable image tags", () => {
  it.each(["acme/app:latest", "acme/app", "registry.example.com:5000/acme/app"])(
    "flags %s as low",
    async (image) => {
      const f = rule(await run(deployment([], [], image)), "k8s-mutable-image-tag");
      expect(f).toHaveLength(1);
      expect(f[0]).toMatchObject({ severity: "low", confidence: "high", line: 10 });
    },
  );

  it.each([
    "acme/app:1.4.2",
    "acme/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "registry.example.com:5000/acme/app:v2",
    "{{ .Values.image }}",
    "${IMAGE}",
  ])("is silent for %s", async (image) => {
    expect(rule(await run(deployment([], [], image)), "k8s-mutable-image-tag")).toEqual([]);
  });
});

describe("K8sManifestDetector: file kinds and documents", () => {
  const bad = deployment(["securityContext:", "  privileged: true"]);

  it("only reads k8s-manifest files and documents with apiVersion and kind", async () => {
    expect(await run(bad, "src/privileged.ts")).toEqual([]);
    expect(await run(bad, "config.yml")).toEqual([]);
    expect(await run(bad, "main.tf")).toEqual([]);
    const helmValues = y("securityContext:", "  privileged: true", "image:", "  tag: latest");
    expect(await run(helmValues, "helm/values.yaml")).toEqual([]);
    const noKind = y(
      "apiVersion: apps/v1",
      "spec:",
      "  template:",
      "    spec:",
      "      hostNetwork: true",
    );
    expect(await run(noKind)).toEqual([]);
  });

  it("reads every document of a multi-document file with file-relative lines", async () => {
    const text = y("apiVersion: v1", "kind: Service", "---") + bad;
    const f = rule(await run(text), "k8s-privileged-container");
    expect(f).toHaveLength(1);
    expect(f[0]!.line).toBe(15);
  });

  it("never throws on malformed yaml", async () => {
    for (const text of [
      "apiVersion: [",
      "kind: Deployment\napiVersion: x\n  - : :\n\t\t:",
      "---\n---\n---",
      "{{ }}\napiVersion: v1\nkind: Pod",
    ]) {
      await expect(run(text)).resolves.toBeDefined();
    }
  });
});
