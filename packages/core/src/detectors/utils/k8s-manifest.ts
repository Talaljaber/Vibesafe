import { scanYamlLines, unquoteYaml, parseFlowList, type YamlEntry } from "./yaml-lines.js";

/**
 * Reading Kubernetes manifests on top of the line-oriented YAML scanner: documents are
 * split on `---`, each is scanned on its own and its line numbers are shifted back to the
 * file. Pod specs, containers and env entries are found by key path. Nothing here throws.
 */

export interface K8sDoc {
  apiVersion: string | undefined;
  kind: string | undefined;
  name: string | undefined;
  namespace: string | undefined;
  /** 1-based line of the document's first line. */
  startLine: number;
  endLine: number;
  /** Entries with file-relative line numbers. */
  entries: YamlEntry[];
}

const MAX_DOCS = 400;

/** Splits on `---` lines and scans every document. Documents without entries are dropped. */
export function parseK8sDocuments(text: string): K8sDoc[] {
  try {
    const rawLines = text.split(/\r?\n/);
    const docs: K8sDoc[] = [];
    let start = 0;
    const flush = (endExclusive: number): void => {
      let end = endExclusive;
      while (end > start && (rawLines[end - 1] ?? "").trim() === "") end--;
      if (end <= start || docs.length >= MAX_DOCS) return;
      const body = rawLines.slice(start, end).join("\n");
      if (body.trim() === "") return;
      const offset = start;
      const entries = scanYamlLines(body).map((e) => ({ ...e, line: e.line + offset }));
      if (entries.length === 0) return;
      const top = (key: string): string | undefined => {
        const e = entries.find((x) => x.kind === "key" && x.path.length === 1 && x.path[0] === key);
        return e ? unquoteYaml(e.value) : undefined;
      };
      const meta = (key: string): string | undefined => {
        const e = entries.find(
          (x) =>
            x.kind === "key" &&
            x.path.length === 2 &&
            x.path[0] === "metadata" &&
            x.path[1] === key,
        );
        return e ? unquoteYaml(e.value) : undefined;
      };
      docs.push({
        apiVersion: top("apiVersion"),
        kind: top("kind"),
        name: meta("name"),
        namespace: meta("namespace"),
        startLine: start + 1,
        endLine: end,
        entries,
      });
    };
    for (let i = 0; i < rawLines.length; i++) {
      if (/^---(?:\s|$)/.test(rawLines[i] ?? "")) {
        flush(i);
        start = i + 1;
      }
    }
    flush(rawLines.length);
    return docs;
  } catch {
    return [];
  }
}

/** True for a document with both a top-level `apiVersion` and `kind` (a Kubernetes object). */
export function isK8sResource(doc: K8sDoc): boolean {
  return doc.apiVersion !== undefined && doc.apiVersion !== "" && !!doc.kind;
}

/** Workload kinds whose pod spec the container rules read. */
export const WORKLOAD_KINDS: ReadonlySet<string> = new Set([
  "Pod",
  "Deployment",
  "StatefulSet",
  "DaemonSet",
  "ReplicaSet",
  "ReplicationController",
  "Job",
  "CronJob",
]);

const POD_SPEC_PREFIXES: readonly (readonly string[])[] = [
  ["spec"],
  ["spec", "template", "spec"],
  ["spec", "jobTemplate", "spec", "template", "spec"],
];

function startsWith(path: readonly string[], prefix: readonly string[]): boolean {
  if (path.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) if (path[i] !== prefix[i]) return false;
  return true;
}

export interface PodSpecEntries {
  prefix: readonly string[];
  entries: YamlEntry[];
}

/** The entries of every pod spec in the document (workload kinds only). */
export function podSpecEntries(doc: K8sDoc): PodSpecEntries[] {
  if (!doc.kind || !WORKLOAD_KINDS.has(doc.kind)) return [];
  const out: PodSpecEntries[] = [];
  for (const prefix of POD_SPEC_PREFIXES) {
    const entries = doc.entries.filter((e) => startsWith(e.path, prefix));
    const hasContainers = entries.some(
      (e) =>
        e.path.length > prefix.length &&
        (e.path[prefix.length] === "containers" || e.path[prefix.length] === "initContainers"),
    );
    if (hasContainers) out.push({ prefix, entries });
  }
  return out;
}

export interface K8sContainer {
  name: string | undefined;
  init: boolean;
  /** Key path of the container item, e.g. `spec.template.spec.containers.[0]`. */
  path: readonly string[];
  /** Line of the container's first key. */
  line: number;
  entries: YamlEntry[];
}

/** Containers and init containers of every pod spec in the document. */
export function containers(doc: K8sDoc): K8sContainer[] {
  const out: K8sContainer[] = [];
  for (const spec of podSpecEntries(doc)) {
    for (const listName of ["containers", "initContainers"] as const) {
      const base = [...spec.prefix, listName];
      const groups = new Map<string, YamlEntry[]>();
      for (const e of spec.entries) {
        if (e.path.length > base.length && startsWith(e.path, base)) {
          const idx = e.path[base.length] ?? "";
          const g = groups.get(idx);
          if (g) g.push(e);
          else groups.set(idx, [e]);
        }
      }
      for (const [idx, entries] of groups) {
        const path = [...base, idx];
        const nameEntry = entries.find(
          (e) => e.kind === "key" && e.path.length === path.length + 1 && e.key === "name",
        );
        out.push({
          name: nameEntry ? unquoteYaml(nameEntry.value) : undefined,
          init: listName === "initContainers",
          path,
          line: entries[0]?.line ?? doc.startLine,
          entries,
        });
      }
    }
  }
  return out;
}

/** The key entry at `container.path + rel`, if any. */
export function containerField(container: K8sContainer, ...rel: string[]): YamlEntry | undefined {
  const want = [...container.path, ...rel];
  return container.entries.find(
    (e) =>
      e.kind === "key" &&
      e.path.length === want.length &&
      want.every((seg, i) => e.path[i] === seg),
  );
}

export interface K8sEnvVar {
  name: string;
  value: string | undefined;
  valueFrom: boolean;
  nameLine: number;
  valueLine: number | undefined;
}

/** Literal and referenced env entries of a container. */
export function envOf(container: K8sContainer): K8sEnvVar[] {
  const base = [...container.path, "env"];
  const groups = new Map<string, YamlEntry[]>();
  for (const e of container.entries) {
    if (e.path.length > base.length && startsWith(e.path, base)) {
      const idx = e.path[base.length] ?? "";
      const g = groups.get(idx);
      if (g) g.push(e);
      else groups.set(idx, [e]);
    }
  }
  const out: K8sEnvVar[] = [];
  for (const entries of groups.values()) {
    const depth = base.length + 2;
    const nameEntry = entries.find(
      (e) => e.kind === "key" && e.path.length === depth && e.key === "name",
    );
    if (!nameEntry) continue;
    const valueEntry = entries.find(
      (e) => e.kind === "key" && e.path.length === depth && e.key === "value",
    );
    out.push({
      name: unquoteYaml(nameEntry.value),
      value: valueEntry ? unquoteYaml(valueEntry.value) : undefined,
      valueFrom: entries.some(
        (e) => e.kind === "key" && e.path.length >= depth && e.path[depth - 1] === "valueFrom",
      ),
      nameLine: nameEntry.line,
      valueLine: valueEntry?.line,
    });
  }
  return out;
}

/** Scalar items of a key: inline flow list or `- item` entries, with their lines. */
export function listValues(
  doc: K8sDoc,
  listPath: readonly string[],
): { value: string; line: number }[] {
  const out: { value: string; line: number }[] = [];
  for (const e of doc.entries) {
    if (e.kind === "key" && e.path.length === listPath.length && startsWith(e.path, listPath)) {
      const flow = parseFlowList(e.value);
      if (flow) for (const v of flow) out.push({ value: v, line: e.line });
    } else if (
      e.kind === "item" &&
      e.path.length === listPath.length + 1 &&
      startsWith(e.path, listPath)
    ) {
      out.push({ value: unquoteYaml(e.value), line: e.line });
    }
  }
  return out;
}
