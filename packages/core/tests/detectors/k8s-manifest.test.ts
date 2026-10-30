import { describe, it, expect } from "vitest";
import {
  containerField,
  containers,
  envOf,
  isK8sResource,
  listValues,
  parseK8sDocuments,
  podSpecEntries,
} from "../../src/detectors/utils/k8s-manifest.js";

const y = (...lines: string[]): string => lines.join("\n") + "\n";

describe("parseK8sDocuments", () => {
  it("splits on --- and shifts entry lines back to the file", () => {
    const docs = parseK8sDocuments(
      y(
        "apiVersion: v1",
        "kind: Service",
        "metadata:",
        "  name: web",
        "  namespace: shop",
        "---",
        "apiVersion: apps/v1",
        "kind: Deployment",
        "metadata:",
        "  name: app",
      ),
    );
    expect(docs.map((d) => [d.kind, d.name, d.namespace, d.startLine, d.endLine])).toEqual([
      ["Service", "web", "shop", 1, 5],
      ["Deployment", "app", undefined, 7, 10],
    ]);
    const kind = docs[1]!.entries.find((e) => e.key === "kind")!;
    expect(kind.line).toBe(8);
  });

  it("tolerates a leading separator, empty documents and comments", () => {
    const docs = parseK8sDocuments(
      y("---", "# only a comment", "---", "apiVersion: v1", "kind: Pod"),
    );
    expect(docs).toHaveLength(1);
    expect(docs[0]!.startLine).toBe(4);
    expect(isK8sResource(docs[0]!)).toBe(true);
  });

  it("marks documents without apiVersion and kind as non-resources", () => {
    const [doc] = parseK8sDocuments(y("image:", "  tag: latest"));
    expect(isK8sResource(doc!)).toBe(false);
  });

  it("never throws", () => {
    for (const t of ["", "---", "a: [", "\t\t:", "{{ x }}", "- - -"]) {
      expect(() => parseK8sDocuments(t)).not.toThrow();
    }
  });
});

describe("containers, env and pod specs", () => {
  const deployment = y(
    "apiVersion: apps/v1",
    "kind: Deployment",
    "metadata:",
    "  name: app",
    "spec:",
    "  template:",
    "    spec:",
    "      hostNetwork: true",
    "      initContainers:",
    "        - name: init",
    "          image: acme/init:1",
    "      containers:",
    "        - name: app",
    "          image: acme/app:1",
    "          securityContext:",
    "            privileged: true",
    "          env:",
    "            - name: DEBUG",
    '              value: "true"',
    "            - name: TOKEN",
    "              valueFrom:",
    "                secretKeyRef:",
    "                  name: s",
    "                  key: t",
    "        - name: sidecar",
    "          image: acme/side:2",
  );

  it("finds the pod spec and every container with its entries", () => {
    const [doc] = parseK8sDocuments(deployment);
    expect(podSpecEntries(doc!)).toHaveLength(1);
    expect(podSpecEntries(doc!)[0]!.prefix).toEqual(["spec", "template", "spec"]);
    const cs = containers(doc!);
    expect(cs.map((c) => [c.name, c.init])).toEqual([
      ["app", false],
      ["sidecar", false],
      ["init", true],
    ]);
    expect(containerField(cs[0]!, "securityContext", "privileged")).toMatchObject({
      line: 16,
      value: "true",
    });
    expect(containerField(cs[1]!, "securityContext", "privileged")).toBeUndefined();
  });

  it("reads env literals and references", () => {
    const [doc] = parseK8sDocuments(deployment);
    const env = envOf(containers(doc!)[0]!);
    expect(env).toEqual([
      { name: "DEBUG", value: "true", valueFrom: false, nameLine: 18, valueLine: 19 },
      { name: "TOKEN", value: undefined, valueFrom: true, nameLine: 20, valueLine: undefined },
    ]);
  });

  it("covers Pod and CronJob pod spec locations and ignores other kinds", () => {
    const [pod] = parseK8sDocuments(
      y(
        "apiVersion: v1",
        "kind: Pod",
        "spec:",
        "  containers:",
        "    - name: a",
        "      image: x:1",
      ),
    );
    expect(containers(pod!)).toHaveLength(1);
    const [cron] = parseK8sDocuments(
      y(
        "apiVersion: batch/v1",
        "kind: CronJob",
        "spec:",
        "  jobTemplate:",
        "    spec:",
        "      template:",
        "        spec:",
        "          containers:",
        "            - name: a",
        "              image: x:1",
      ),
    );
    expect(containers(cron!)).toHaveLength(1);
    const [svc] = parseK8sDocuments(
      y("apiVersion: v1", "kind: Service", "spec:", "  containers:", "    - name: a"),
    );
    expect(containers(svc!)).toEqual([]);
  });
});

describe("listValues", () => {
  it("reads flow lists and block items with lines", () => {
    const [doc] = parseK8sDocuments(
      y(
        "apiVersion: rbac.authorization.k8s.io/v1",
        "kind: Role",
        "rules:",
        "  - verbs: ['get', 'list']",
        "    resources:",
        "      - pods",
        "      - '*'",
      ),
    );
    expect(listValues(doc!, ["rules", "[0]", "verbs"])).toEqual([
      { value: "get", line: 4 },
      { value: "list", line: 4 },
    ]);
    expect(listValues(doc!, ["rules", "[0]", "resources"])).toEqual([
      { value: "pods", line: 6 },
      { value: "*", line: 7 },
    ]);
  });
});
