/**
 * Line-based Dockerfile reader: parser directives (`# escape=`), line continuations,
 * comment lines inside continuations, heredocs (`RUN <<EOF`, `<<-EOF`, quoted
 * delimiters) and build stages. Nothing here throws.
 */

export interface DockerInstruction {
  /** Upper-cased instruction keyword (`FROM`, `RUN`, ...). */
  keyword: string;
  /** Arguments of the logical line with continuations joined by a space. */
  args: string;
  /** 1-based first line. */
  line: number;
  /** 1-based last line (including continuations and heredoc bodies). */
  endLine: number;
  /** Heredoc bodies, in order of appearance. */
  heredocs: string[];
  /** Index of the stage the instruction belongs to (-1 before the first FROM). */
  stage: number;
}

export interface DockerFrom {
  /** Image reference as written (`node:20-alpine`, `${BASE}`, `builder`). */
  image: string;
  /** Tag, if any (`20-alpine`). */
  tag: string | undefined;
  /** Digest, if any (`sha256:...`). */
  digest: string | undefined;
  /** `AS <name>` alias, lower-cased. */
  alias: string | undefined;
  platform: string | undefined;
  /** True when `image` names an earlier stage. */
  fromStage: boolean;
  /** True when the reference contains a build-arg (`$`). */
  variable: boolean;
}

export interface DockerStage {
  index: number;
  from: DockerFrom;
  /** Line of the FROM instruction. */
  line: number;
  instructions: DockerInstruction[];
}

export interface Dockerfile {
  escape: "\\" | "`";
  instructions: DockerInstruction[];
  stages: DockerStage[];
}

const DIRECTIVE_RE = /^#\s*([a-zA-Z]+)\s*=\s*(\S+)\s*$/;
const KEYWORD_RE = /^([A-Za-z]+)(?:\s+|$)([\s\S]*)$/;
const HEREDOC_RE = /(?<!<)<<(?!<)(-?)\s*(["']?)([A-Za-z_][\w.-]*)\2/g;

/** Parses `FROM [--platform=x] image[:tag][@digest] [AS name]`. */
export function parseFrom(args: string, previousAliases: ReadonlySet<string>): DockerFrom {
  const tokens = args.trim().split(/\s+/).filter(Boolean);
  let platform: string | undefined;
  while (tokens[0]?.startsWith("--")) {
    const flag = tokens.shift()!;
    const m = /^--platform=(.*)$/i.exec(flag);
    if (m) platform = m[1];
  }
  const image = tokens[0] ?? "";
  let alias: string | undefined;
  if (tokens.length >= 3 && tokens[1]?.toLowerCase() === "as") alias = tokens[2]?.toLowerCase();

  let digest: string | undefined;
  let ref = image;
  const at = ref.indexOf("@");
  if (at !== -1) {
    digest = ref.slice(at + 1);
    ref = ref.slice(0, at);
  }
  // A tag is the part after the last colon that comes after the last slash
  // (`localhost:5000/app` has a registry port, not a tag).
  const slash = ref.lastIndexOf("/");
  const colon = ref.lastIndexOf(":");
  const tag = colon > slash ? ref.slice(colon + 1) : undefined;
  return {
    image,
    tag,
    digest,
    alias,
    platform,
    fromStage: previousAliases.has(image.toLowerCase()),
    variable: image.includes("$"),
  };
}

/** Parses a Dockerfile into instructions and stages. */
export function parseDockerfile(text: string): Dockerfile {
  const lines = text.split(/\r?\n/);
  let escape: "\\" | "`" = "\\";

  // Parser directives: leading `# key=value` comment lines before anything else.
  let start = 0;
  for (; start < lines.length; start++) {
    const l = (lines[start] ?? "").trim();
    const m = DIRECTIVE_RE.exec(l);
    if (!m) break;
    if (m[1]!.toLowerCase() === "escape" && (m[2] === "`" || m[2] === "\\")) {
      escape = m[2] as "\\" | "`";
    }
  }

  const instructions: DockerInstruction[] = [];
  const stages: DockerStage[] = [];
  const aliases = new Set<string>();

  let i = start;
  while (i < lines.length) {
    const first = lines[i] ?? "";
    const trimmed = first.trim();
    if (trimmed === "" || trimmed.startsWith("#")) {
      i++;
      continue;
    }
    const line = i + 1;
    // Join continuation lines; comment and blank lines inside a continuation are dropped.
    let logical = "";
    let cur = first;
    for (;;) {
      const t = cur.replace(/\s+$/, "");
      if (t.endsWith(escape) && i + 1 < lines.length) {
        logical += t.slice(0, -1) + " ";
        i++;
        while (i < lines.length && /^\s*(?:#|$)/.test(lines[i] ?? "") && i + 1 < lines.length) i++;
        cur = lines[i] ?? "";
        continue;
      }
      logical += t;
      break;
    }

    const km = KEYWORD_RE.exec(logical.trim());
    const keyword = (km?.[1] ?? "").toUpperCase();
    const args = (km?.[2] ?? "").trim();

    // Heredocs: bodies follow the instruction line until the delimiter line.
    const heredocs: string[] = [];
    if ((keyword === "RUN" || keyword === "COPY" || keyword === "ADD") && args.includes("<<")) {
      for (const m of args.matchAll(HEREDOC_RE)) {
        const stripTabs = m[1] === "-";
        const delim = m[3]!;
        const body: string[] = [];
        while (i + 1 < lines.length) {
          i++;
          const raw = lines[i] ?? "";
          const cmp = stripTabs ? raw.replace(/^\t+/, "") : raw;
          if (cmp.trimEnd() === delim) break;
          body.push(stripTabs ? cmp : raw);
        }
        heredocs.push(body.join("\n"));
      }
    }

    const stageIndex = keyword === "FROM" ? stages.length : stages.length - 1;
    const instr: DockerInstruction = {
      keyword,
      args,
      line,
      endLine: i + 1,
      heredocs,
      stage: stageIndex,
    };
    instructions.push(instr);
    if (keyword === "FROM") {
      const from = parseFrom(args, aliases);
      if (from.alias) aliases.add(from.alias);
      stages.push({ index: stageIndex, from, line, instructions: [instr] });
    } else if (stageIndex >= 0) {
      stages[stageIndex]!.instructions.push(instr);
    }
    i++;
  }
  return { escape, instructions, stages };
}

/**
 * Splits `ENV`/`ARG`/`LABEL` arguments into key/value pairs. Supports `K=V` pairs
 * (quoted values, several per line) and the legacy `ENV K V...` form. A key with no
 * `=` (`ARG TOKEN`) has value undefined.
 */
export function parseKeyValues(args: string): { key: string; value: string | undefined }[] {
  const out: { key: string; value: string | undefined }[] = [];
  const s = args.trim();
  if (s === "") return out;
  const firstToken = /^[^\s=]+/.exec(s)?.[0] ?? "";
  if (!s.slice(firstToken.length).startsWith("=")) {
    // Legacy `ENV KEY value with spaces` or bare `ARG KEY`.
    const rest = s.slice(firstToken.length).trim();
    out.push({ key: firstToken, value: rest === "" ? undefined : unquote(rest) });
    return out;
  }
  let i = 0;
  while (i < s.length) {
    while (i < s.length && /\s/.test(s[i]!)) i++;
    if (i >= s.length) break;
    let key = "";
    while (i < s.length && s[i] !== "=" && !/\s/.test(s[i]!)) key += s[i++];
    if (s[i] !== "=") {
      out.push({ key, value: undefined });
      continue;
    }
    i++;
    let value = "";
    while (i < s.length && !/\s/.test(s[i]!)) {
      const ch = s[i]!;
      if (ch === '"' || ch === "'") {
        i++;
        while (i < s.length && s[i] !== ch) {
          if (s[i] === "\\" && ch === '"' && i + 1 < s.length) i++;
          value += s[i++];
        }
        i++;
      } else if (ch === "\\" && i + 1 < s.length) {
        value += s[i + 1];
        i += 2;
      } else {
        value += ch;
        i++;
      }
    }
    out.push({ key, value });
  }
  return out;
}

function unquote(v: string): string {
  const t = v.trim();
  if (t.length >= 2 && (t[0] === '"' || t[0] === "'") && t[t.length - 1] === t[0]) {
    return t.slice(1, -1);
  }
  return t;
}
