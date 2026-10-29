/**
 * Line-oriented YAML reading for workflow and compose files. This is not a YAML
 * parser: it tracks the key path of every line with an indentation stack, which is
 * enough for the shapes CI and compose files use (block mappings and sequences,
 * `|`/`>` block scalars, flow lists of scalars, quoted keys such as `'on':`, CRLF
 * line endings and tab indentation). Anchors, aliases, flow mappings and multi-line
 * flow collections are not resolved. Nothing here throws.
 */

/** One meaningful YAML line (blank and comment-only lines are skipped). */
export interface YamlEntry {
  /** 1-based line number. */
  line: number;
  /** Column of the key, list-item content or block-scalar text. */
  indent: number;
  /**
   * Key path of this line. Mapping keys appear as-is (quotes removed); sequence items
   * appear as `[n]`. For `block` and `text` entries it is the path of the owning key.
   */
  path: readonly string[];
  /**
   * - `key`: `key: value` (also `- key: value`, whose path contains the item index);
   * - `item`: a scalar sequence item, `- value`;
   * - `block`: a line of a `|`/`>` block scalar;
   * - `text`: a continuation line of a multi-line plain or quoted scalar.
   */
  kind: "key" | "item" | "block" | "text";
  /** Mapping key for `key` entries. */
  key: string | undefined;
  /**
   * Inline value: for `key`/`item` the scalar after the colon or dash with the trailing
   * comment removed (quotes kept; `""` when the value is a nested block); for
   * `block`/`text` the trimmed line.
   */
  value: string;
  /** The original line (CR removed). */
  raw: string;
}

const BLOCK_SCALAR_RE = /^[|>](?:[1-9][+-]?|[+-][1-9]?)?$/;
const KEY_RE =
  /^("(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^\s#'"{[\]},&*!|>%@`-][^#]*?|-[^\s#][^#]*?)\s*:(?=\s|$)(.*)$/;

interface Frame {
  /** Column the frame's content starts at. */
  indent: number;
  segment: string;
  item: boolean;
  /** Next sequence index for items directly under this frame. */
  nextIndex: number;
}

function leadingWidth(raw: string): number {
  let i = 0;
  while (i < raw.length && (raw[i] === " " || raw[i] === "\t")) i++;
  return i;
}

/** Removes a trailing ` # comment` that is not inside quotes. */
export function stripYamlComment(value: string): string {
  let quote: string | null = null;
  for (let i = 0; i < value.length; i++) {
    const ch = value[i];
    if (quote) {
      if (ch === quote) {
        if (quote === "'" && value[i + 1] === "'") i++;
        else quote = null;
      } else if (ch === "\\" && quote === '"') i++;
    } else if (ch === '"' || ch === "'") {
      // Quotes only open a quoted scalar at the start of a token.
      if (i === 0 || /[\s,[{:]/.test(value[i - 1] ?? "")) quote = ch;
    } else if (ch === "#" && (i === 0 || /\s/.test(value[i - 1] ?? ""))) {
      return value.slice(0, i).trimEnd();
    }
  }
  return value.trimEnd();
}

/** Removes one pair of matching surrounding quotes. */
export function unquoteYaml(value: string): string {
  const v = value.trim();
  if (v.length >= 2) {
    const q = v[0];
    if ((q === '"' || q === "'") && v[v.length - 1] === q) {
      const inner = v.slice(1, -1);
      return q === "'" ? inner.replace(/''/g, "'") : inner.replace(/\\(["\\])/g, "$1");
    }
  }
  return v;
}

/**
 * Splits a single-line flow sequence (`[a, "b", 'c']`) into unquoted scalars, or
 * returns null when the value is not a flow sequence.
 */
export function parseFlowList(value: string): string[] | null {
  const v = value.trim();
  if (!v.startsWith("[") || !v.endsWith("]")) return null;
  const inner = v.slice(1, -1);
  const out: string[] = [];
  let cur = "";
  let quote: string | null = null;
  let depth = 0;
  for (let i = 0; i < inner.length; i++) {
    const ch = inner[i] as string;
    if (quote) {
      cur += ch;
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") quote = ch;
    else if (ch === "[" || ch === "{") depth++;
    else if (ch === "]" || ch === "}") depth--;
    else if (ch === "," && depth === 0) {
      if (cur.trim() !== "") out.push(unquoteYaml(cur));
      cur = "";
      continue;
    }
    cur += ch;
  }
  if (cur.trim() !== "") out.push(unquoteYaml(cur));
  return out;
}

/**
 * Walks a YAML document line by line and returns every meaningful line with its key
 * path (see {@link YamlEntry}). Multi-document files (`---`) are read as one document.
 */
export function scanYamlLines(text: string): YamlEntry[] {
  const entries: YamlEntry[] = [];
  const lines = text.split(/\r?\n/);
  const stack: Frame[] = [{ indent: -1, segment: "", item: false, nextIndex: 0 }];
  /** Open block scalar: lines indented deeper than `minIndent` belong to it. */
  let block: { path: string[]; minIndent: number } | null = null;
  /** Last key whose value may continue on following, deeper lines. */
  let lastKey: { path: string[]; indent: number } | null = null;

  const pathOf = (): string[] => stack.slice(1).map((f) => f.segment);

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] ?? "";
    const lineNo = i + 1;
    const indent = leadingWidth(raw);
    const content = raw.slice(indent);

    if (block) {
      if (content === "" || indent > block.minIndent) {
        if (content !== "") {
          entries.push({
            line: lineNo,
            indent,
            path: block.path,
            kind: "block",
            key: undefined,
            value: content.trimEnd(),
            raw,
          });
        }
        continue;
      }
      block = null;
    }

    if (content === "" || content.startsWith("#")) continue;
    if (indent === 0 && /^(?:---|\.\.\.)(?:\s|$)/.test(content)) {
      stack.length = 1;
      stack[0]!.nextIndex = 0;
      lastKey = null;
      continue;
    }

    let col = indent;
    let rest = content;
    let isItem = false;

    if (rest === "-" || rest.startsWith("- ") || rest.startsWith("-\t")) {
      isItem = true;
      // Items close deeper frames and sibling items, but stay under a key at the same
      // column (`steps:` followed by `- run: x` at the same indentation).
      while (stack.length > 1) {
        const top = stack[stack.length - 1]!;
        if (top.indent > col || (top.indent === col && top.item)) stack.pop();
        else break;
      }
      const parent = stack[stack.length - 1]!;
      stack.push({ indent: col, segment: `[${parent.nextIndex++}]`, item: true, nextIndex: 0 });
      const after = rest.slice(1);
      const pad = leadingWidth(after);
      col = col + 1 + pad;
      rest = after.slice(pad);
      lastKey = null;
      if (rest === "" || rest.startsWith("#")) continue;
    } else if (lastKey && col > lastKey.indent && !KEY_RE.test(rest)) {
      // Continuation of a multi-line scalar.
      entries.push({
        line: lineNo,
        indent: col,
        path: lastKey.path,
        kind: "text",
        key: undefined,
        value: stripYamlComment(rest).trim(),
        raw,
      });
      continue;
    }

    const km = KEY_RE.exec(rest);
    if (km) {
      const key = unquoteYaml(km[1] ?? "");
      const value = stripYamlComment((km[2] ?? "").trim());
      while (stack.length > 1) {
        const top = stack[stack.length - 1]!;
        if (top.indent > col || (top.indent === col && !(isItem && top.item))) stack.pop();
        else break;
      }
      // `- key: v` keeps the item frame; a sibling `key:` at the item content column
      // pops only previous keys of the same mapping.
      stack.push({ indent: col, segment: key, item: false, nextIndex: 0 });
      const path = pathOf();
      entries.push({ line: lineNo, indent: col, path, kind: "key", key, value, raw });
      if (BLOCK_SCALAR_RE.test(value)) {
        block = { path, minIndent: col };
        lastKey = null;
      } else {
        lastKey = value === "" ? null : { path, indent: col };
      }
      continue;
    }

    if (isItem) {
      entries.push({
        line: lineNo,
        indent: col,
        path: pathOf(),
        kind: "item",
        key: undefined,
        value: stripYamlComment(rest).trim(),
        raw,
      });
      continue;
    }

    // Unparseable line (flow mapping continuation, odd syntax): attach to the open path.
    entries.push({
      line: lineNo,
      indent: col,
      path: pathOf(),
      kind: "text",
      key: undefined,
      value: stripYamlComment(rest).trim(),
      raw,
    });
  }
  return entries;
}

// ─── GitHub expressions ──────────────────────────────────────────────────────

/** One `${{ ... }}` expression. */
export interface GhExpression {
  /** The expression between the braces, trimmed. */
  expr: string;
  /** Offset of `${{` in the scanned text. */
  start: number;
  /** Offset just past `}}`. */
  end: number;
}

/** Finds every `${{ ... }}` expression in a line of text. */
export function findGhExpressions(text: string): GhExpression[] {
  const out: GhExpression[] = [];
  let from = 0;
  for (;;) {
    const start = text.indexOf("${{", from);
    if (start === -1) break;
    const close = text.indexOf("}}", start + 3);
    if (close === -1) break;
    out.push({ expr: text.slice(start + 3, close).trim(), start, end: close + 2 });
    from = close + 2;
  }
  return out;
}

// ─── Workflows ───────────────────────────────────────────────────────────────

/** A scalar value and the line it is on. */
export interface YamlValue {
  value: string;
  line: number;
}

/** A multi-line text value (inline or block scalar), one entry per source line. */
export interface YamlText {
  /** Lines joined with `\n`. */
  text: string;
  lines: YamlValue[];
  /** Line of the key. */
  line: number;
}

/** How an action reference is pinned. */
export type ActionRefKind = "sha" | "tag" | "branch" | "none" | "local" | "docker" | "other";

export interface ActionRef {
  /** The raw `uses:` value, unquoted. */
  raw: string;
  owner: string;
  repo: string;
  /** Sub-path inside the repo (reusable workflow or nested action), if any. */
  path: string | undefined;
  ref: string | undefined;
  refKind: ActionRefKind;
  line: number;
}

export interface WorkflowStep {
  index: number;
  /** Line of the step's first key. */
  line: number;
  name: YamlValue | undefined;
  uses: ActionRef | undefined;
  run: YamlText | undefined;
  with: Record<string, YamlText>;
  env: Record<string, YamlValue>;
  if: YamlValue | undefined;
}

/** `permissions:` as a scalar (`write-all`) and/or per-scope values. */
export interface WorkflowPermissions {
  line: number;
  value: string | undefined;
  scopes: Record<string, YamlValue>;
}

export interface WorkflowJob {
  id: string;
  line: number;
  permissions: WorkflowPermissions | undefined;
  if: YamlValue | undefined;
  /** `uses:` of a job that calls a reusable workflow. */
  uses: ActionRef | undefined;
  steps: WorkflowStep[];
  env: Record<string, YamlValue>;
  /** Highest line that belongs to the job. */
  endLine: number;
}

export interface Workflow {
  triggers: YamlValue[];
  permissions: WorkflowPermissions | undefined;
  env: Record<string, YamlValue>;
  jobs: WorkflowJob[];
}

const SHA_RE = /^[0-9a-f]{40}$/i;
const TAG_RE = /^v?\d+(?:\.\d+){0,3}(?:[-+][\w.-]+)?$/i;
const BRANCH_REFS = new Set([
  "main",
  "master",
  "dev",
  "develop",
  "development",
  "trunk",
  "head",
  "latest",
  "edge",
  "nightly",
  "canary",
  "next",
  "stable",
  "release",
]);

/** Parses a `uses:` value (`owner/repo[/path]@ref`, `./local`, `docker://image`). */
export function parseActionRef(value: string, line: number): ActionRef {
  const raw = unquoteYaml(value);
  const base = { raw, owner: "", repo: "", path: undefined, ref: undefined, line };
  if (raw.startsWith("./") || raw.startsWith("../")) return { ...base, refKind: "local" };
  if (raw.startsWith("docker://")) return { ...base, refKind: "docker" };
  const at = raw.lastIndexOf("@");
  const spec = at === -1 ? raw : raw.slice(0, at);
  const ref = at === -1 ? undefined : raw.slice(at + 1);
  const parts = spec.split("/");
  const owner = parts[0] ?? "";
  const repo = parts[1] ?? "";
  const sub = parts.length > 2 ? parts.slice(2).join("/") : undefined;
  let refKind: ActionRefKind;
  if (ref === undefined || ref === "") refKind = "none";
  else if (ref.includes("${{")) refKind = "other";
  else if (SHA_RE.test(ref)) refKind = "sha";
  else if (TAG_RE.test(ref)) refKind = "tag";
  else if (BRANCH_REFS.has(ref.toLowerCase())) refKind = "branch";
  else refKind = "other";
  return { raw, owner, repo, path: sub, ref, refKind, line };
}

function startsWithPath(path: readonly string[], prefix: readonly string[]): boolean {
  if (path.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) if (path[i] !== prefix[i]) return false;
  return true;
}

/** Collects the text of a key's value: inline, block-scalar or continuation lines. */
function collectText(entries: YamlEntry[], start: number, path: readonly string[]): YamlText {
  const head = entries[start]!;
  const lines: YamlValue[] = [];
  const inline = head.value;
  if (inline !== "" && !BLOCK_SCALAR_RE.test(inline)) {
    lines.push({ value: unquoteYaml(inline), line: head.line });
  }
  for (let j = start + 1; j < entries.length; j++) {
    const e = entries[j]!;
    if (
      (e.kind === "block" || e.kind === "text") &&
      e.path.length === path.length &&
      startsWithPath(e.path, path)
    ) {
      lines.push({ value: e.value, line: e.line });
    } else break;
  }
  return { text: lines.map((l) => l.value).join("\n"), lines, line: head.line };
}

function readPermissions(
  entries: YamlEntry[],
  index: number,
  path: readonly string[],
): WorkflowPermissions {
  const head = entries[index]!;
  const scopes: Record<string, YamlValue> = {};
  for (let j = index + 1; j < entries.length; j++) {
    const e = entries[j]!;
    if (!startsWithPath(e.path, path) || e.path.length === path.length) break;
    if (e.kind === "key" && e.path.length === path.length + 1 && e.key) {
      scopes[e.key] = { value: unquoteYaml(e.value), line: e.line };
    }
  }
  const flow = head.value.startsWith("{") ? head.value : "";
  if (flow) {
    for (const m of flow.matchAll(/([\w-]+)\s*:\s*([\w-]+)/g)) {
      scopes[m[1]!] = { value: m[2]!, line: head.line };
    }
  }
  const value = head.value !== "" && !flow ? unquoteYaml(head.value) : undefined;
  return { line: head.line, value, scopes };
}

/**
 * Reads the parts of a GitHub Actions workflow (or composite `action.yml`, whose
 * `runs.steps` are returned as one job with id `runs`) that the security rules need.
 */
export function parseWorkflow(text: string): Workflow {
  const entries = scanYamlLines(text);
  const wf: Workflow = { triggers: [], permissions: undefined, env: {}, jobs: [] };
  const jobs = new Map<string, WorkflowJob>();
  const steps = new Map<string, WorkflowStep>();

  const jobOf = (id: string, line: number): WorkflowJob => {
    let job = jobs.get(id);
    if (!job) {
      job = {
        id,
        line,
        permissions: undefined,
        if: undefined,
        uses: undefined,
        steps: [],
        env: {},
        endLine: line,
      };
      jobs.set(id, job);
      wf.jobs.push(job);
    }
    return job;
  };

  for (let i = 0; i < entries.length; i++) {
    const e = entries[i]!;
    const p = e.path;
    const top = p[0];

    if (top === "on") {
      if (p.length === 1 && e.kind === "key") {
        const v = unquoteYaml(e.value);
        const list = parseFlowList(e.value);
        if (list) for (const t of list) wf.triggers.push({ value: t, line: e.line });
        else if (v !== "" && !v.startsWith("{")) wf.triggers.push({ value: v, line: e.line });
        else if (v.startsWith("{")) {
          for (const m of v.matchAll(/([\w-]+)\s*:/g))
            wf.triggers.push({ value: m[1]!, line: e.line });
        }
      } else if (p.length === 2 && e.kind === "key" && e.key) {
        wf.triggers.push({ value: e.key, line: e.line });
      } else if (p.length === 2 && e.kind === "item") {
        wf.triggers.push({ value: unquoteYaml(e.value), line: e.line });
      }
      continue;
    }

    if (top === "permissions" && p.length === 1 && e.kind === "key") {
      wf.permissions = readPermissions(entries, i, p);
      continue;
    }
    if (top === "env" && p.length === 2 && e.kind === "key" && e.key) {
      wf.env[e.key] = { value: unquoteYaml(e.value), line: e.line };
      continue;
    }

    // Jobs: jobs.<id>.*; composite actions: runs.steps.*
    let jobId: string | undefined;
    let rel: readonly string[] = [];
    if (top === "jobs" && p.length >= 2) {
      jobId = p[1];
      rel = p.slice(2);
    } else if (top === "runs" && p[1] === "steps" && p.length >= 3) {
      jobId = "runs";
      rel = p.slice(1);
    } else continue;
    if (jobId === undefined) continue;
    const job = jobOf(jobId, e.line);
    job.endLine = Math.max(job.endLine, e.line);
    if (rel.length === 0) continue;

    if (rel[0] === "permissions" && rel.length === 1 && e.kind === "key") {
      job.permissions = readPermissions(entries, i, p);
    } else if (rel[0] === "if" && rel.length === 1 && e.kind === "key") {
      job.if = { value: unquoteYaml(e.value), line: e.line };
    } else if (rel[0] === "uses" && rel.length === 1 && e.kind === "key") {
      job.uses = parseActionRef(e.value, e.line);
    } else if (rel[0] === "env" && rel.length === 2 && e.kind === "key" && e.key) {
      job.env[e.key] = { value: unquoteYaml(e.value), line: e.line };
    } else if (rel[0] === "steps" && rel.length >= 2 && /^\[\d+\]$/.test(rel[1] ?? "")) {
      const stepKey = `${jobId}\u0000${rel[1]}`;
      let step = steps.get(stepKey);
      if (!step) {
        step = {
          index: job.steps.length,
          line: e.line,
          name: undefined,
          uses: undefined,
          run: undefined,
          with: {},
          env: {},
          if: undefined,
        };
        steps.set(stepKey, step);
        job.steps.push(step);
      }
      const field = rel[2];
      if (e.kind !== "key" || field === undefined) continue;
      if (rel.length === 3) {
        if (field === "uses") step.uses = parseActionRef(e.value, e.line);
        else if (field === "run") step.run = collectText(entries, i, p);
        else if (field === "name") step.name = { value: unquoteYaml(e.value), line: e.line };
        else if (field === "if") step.if = { value: unquoteYaml(e.value), line: e.line };
      } else if (rel.length === 4 && e.key) {
        if (field === "with") step.with[e.key] = collectText(entries, i, p);
        else if (field === "env") step.env[e.key] = { value: unquoteYaml(e.value), line: e.line };
      }
    }
  }
  return wf;
}

// ─── Compose ─────────────────────────────────────────────────────────────────

/** One published port mapping. */
export interface ComposePort {
  raw: string;
  line: number;
  /** Host interface; undefined means all interfaces. */
  hostIp: string | undefined;
  /** Host port (or range); undefined when only the container port is given. */
  published: string | undefined;
  target: string | undefined;
}

export interface ComposeEnvVar {
  key: string;
  value: string;
  line: number;
}

export interface ComposeService {
  name: string;
  line: number;
  image: YamlValue | undefined;
  ports: ComposePort[];
  environment: ComposeEnvVar[];
  privileged: YamlValue | undefined;
  volumes: YamlValue[];
  capAdd: YamlValue[];
  /** Highest line that belongs to the service. */
  endLine: number;
}

export interface ComposeFile {
  services: ComposeService[];
}

/** Parses a short-syntax port (`"127.0.0.1:5432:5432"`, `"5432:5432/tcp"`, `"[::1]:80:80"`). */
export function parseShortPort(value: string, line: number): ComposePort {
  const raw = unquoteYaml(value);
  // `${HOST_IP:-127.0.0.1}` -> its default; `${PORT}` -> a colon-free token.
  const spec = raw
    .replace(/\$\{([^}:?-]*)(?::?[-?]([^}]*))?\}/g, (_m, n: string, d: string | undefined) =>
      d !== undefined && d !== "" ? d : `$${n}`,
    )
    .replace(/\/(?:tcp|udp|sctp)$/i, "");
  let hostIp: string | undefined;
  let restSpec = spec;
  const v6 = /^\[([^\]]*)\]:(.*)$/.exec(spec);
  if (v6) {
    hostIp = v6[1];
    restSpec = v6[2] ?? "";
  }
  const parts = restSpec.split(":");
  if (!v6 && parts.length >= 3) {
    hostIp = parts.slice(0, parts.length - 2).join(":");
    return { raw, line, hostIp, published: parts.at(-2), target: parts.at(-1) };
  }
  if (parts.length === 2) return { raw, line, hostIp, published: parts[0], target: parts[1] };
  return { raw, line, hostIp, published: undefined, target: parts[0] };
}

/** Reads the service-level settings of a compose file that the security rules need. */
export function parseCompose(text: string): ComposeFile {
  const entries = scanYamlLines(text);
  const services = new Map<string, ComposeService>();
  const out: ComposeFile = { services: [] };
  /** Long-syntax port items keyed by service + item path. */
  const longPorts = new Map<string, ComposePort>();

  for (let i = 0; i < entries.length; i++) {
    const e = entries[i]!;
    const p = e.path;
    if (p[0] !== "services" || p.length < 2) continue;
    const name = p[1]!;
    let svc = services.get(name);
    if (!svc) {
      svc = {
        name,
        line: e.line,
        image: undefined,
        ports: [],
        environment: [],
        privileged: undefined,
        volumes: [],
        capAdd: [],
        endLine: e.line,
      };
      services.set(name, svc);
      out.services.push(svc);
    }
    svc.endLine = Math.max(svc.endLine, e.line);
    const field = p[2];
    if (field === undefined) continue;

    if (p.length === 3 && e.kind === "key") {
      const list = parseFlowList(e.value);
      if (field === "image") svc.image = { value: unquoteYaml(e.value), line: e.line };
      else if (field === "privileged")
        svc.privileged = { value: unquoteYaml(e.value), line: e.line };
      else if (list && field === "ports")
        for (const v of list) svc.ports.push(parseShortPort(v, e.line));
      else if (list && field === "volumes")
        for (const v of list) svc.volumes.push({ value: v, line: e.line });
      else if (list && field === "cap_add")
        for (const v of list) svc.capAdd.push({ value: v, line: e.line });
      else if (list && field === "environment") for (const v of list) pushEnvItem(svc, v, e.line);
      continue;
    }

    if (field === "ports") {
      if (p.length === 4 && e.kind === "item") svc.ports.push(parseShortPort(e.value, e.line));
      else if (p.length === 5 && e.kind === "key" && e.key) {
        const k = `${name}\u0000${p[3]}`;
        let port = longPorts.get(k);
        if (!port) {
          port = {
            raw: "",
            line: e.line,
            hostIp: undefined,
            published: undefined,
            target: undefined,
          };
          longPorts.set(k, port);
          svc.ports.push(port);
        }
        const v = unquoteYaml(e.value);
        port.raw = port.raw ? `${port.raw}, ${e.key}: ${v}` : `${e.key}: ${v}`;
        if (e.key === "host_ip") port.hostIp = v;
        else if (e.key === "published") {
          port.published = v;
          port.line = e.line;
        } else if (e.key === "target") port.target = v;
      }
    } else if (field === "environment") {
      if (p.length === 4 && e.kind === "key" && e.key) {
        svc.environment.push({ key: e.key, value: unquoteYaml(e.value), line: e.line });
      } else if (p.length === 4 && e.kind === "item") {
        pushEnvItem(svc, e.value, e.line);
      }
    } else if (field === "volumes") {
      if (p.length === 4 && e.kind === "item")
        svc.volumes.push({ value: unquoteYaml(e.value), line: e.line });
      else if (p.length === 5 && e.kind === "key" && e.key === "source")
        svc.volumes.push({ value: unquoteYaml(e.value), line: e.line });
    } else if (field === "cap_add" && p.length === 4 && e.kind === "item") {
      svc.capAdd.push({ value: unquoteYaml(e.value), line: e.line });
    }
  }
  return out;
}

function pushEnvItem(svc: ComposeService, value: string, line: number): void {
  const v = unquoteYaml(value);
  const eq = v.indexOf("=");
  if (eq <= 0) return;
  svc.environment.push({ key: v.slice(0, eq).trim(), value: v.slice(eq + 1), line });
}
