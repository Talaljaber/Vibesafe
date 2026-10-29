// ─────────────────────────────────────────────────────────────────────────────
// Minimal in-house semver
//
// Just enough of npm's semver semantics to match package.json specs and lockfile
// versions against advisory ranges, with no runtime dependency:
// - parseVersion / compareVersions (prerelease ordering per semver 2.0.0),
// - parseRange for exact, x-ranges, caret, tilde, hyphen, comparators and `||`,
// - satisfies / minVersion,
// - classifySpec (exact pin vs range vs git/url/file/alias/tag),
// - resolvedVersions for package-lock v1-v3, pnpm-lock v5-v9 and yarn classic/berry.
//
// Differences from npm: `satisfies` compares prereleases like ordinary versions
// (npm's `includePrerelease` behaviour), which is what advisory matching wants.
// Nothing here throws; unparseable input yields `null` or an empty result.
// ─────────────────────────────────────────────────────────────────────────────

export interface SemVer {
  major: number;
  minor: number;
  patch: number;
  /** Dot-separated prerelease identifiers; numeric ones as numbers. Empty for a release. */
  prerelease: (string | number)[];
}

export type ComparatorOp = "<" | "<=" | ">" | ">=" | "=";

export interface Comparator {
  op: ComparatorOp;
  version: SemVer;
}

/** A range: OR of AND-sets of comparators. An empty AND-set matches every version. */
export type Range = Comparator[][];

const VERSION_RE =
  /^[=v\s]*(\d{1,9})\.(\d{1,9})\.(\d{1,9})(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$/;

function parseIdentifiers(pre: string | undefined): (string | number)[] {
  if (!pre) return [];
  return pre.split(".").map((id) => (/^\d+$/.test(id) ? Number(id) : id));
}

/** Parses a full `major.minor.patch[-pre][+build]` version (leading `v`/`=` allowed). */
export function parseVersion(input: string): SemVer | null {
  if (typeof input !== "string" || input.length > 256) return null;
  const m = VERSION_RE.exec(input.trim());
  if (!m) return null;
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: Number(m[3]),
    prerelease: parseIdentifiers(m[4]),
  };
}

/** Formats a parsed version back to `major.minor.patch[-pre]`. */
export function formatVersion(v: SemVer): string {
  const base = `${v.major}.${v.minor}.${v.patch}`;
  return v.prerelease.length > 0 ? `${base}-${v.prerelease.join(".")}` : base;
}

function toSemVer(v: SemVer | string): SemVer | null {
  return typeof v === "string" ? parseVersion(v) : v;
}

function compareIdentifiers(a: string | number, b: string | number): number {
  const an = typeof a === "number";
  const bn = typeof b === "number";
  if (an && bn) return a === b ? 0 : a < b ? -1 : 1;
  if (an) return -1; // numeric identifiers sort before alphanumeric ones
  if (bn) return 1;
  return a === b ? 0 : a < b ? -1 : 1;
}

/**
 * Compares two versions: -1, 0 or 1. A release sorts after its prereleases
 * (1.0.0-rc.1 < 1.0.0). Unparseable strings compare as equal (0).
 */
export function compareVersions(a: SemVer | string, b: SemVer | string): -1 | 0 | 1 {
  const x = toSemVer(a);
  const y = toSemVer(b);
  if (!x || !y) return 0;
  for (const k of ["major", "minor", "patch"] as const) {
    if (x[k] !== y[k]) return x[k] < y[k] ? -1 : 1;
  }
  const xp = x.prerelease;
  const yp = y.prerelease;
  if (xp.length === 0 && yp.length === 0) return 0;
  if (xp.length === 0) return 1;
  if (yp.length === 0) return -1;
  for (let i = 0; i < Math.max(xp.length, yp.length); i++) {
    const xi = xp[i];
    const yi = yp[i];
    if (xi === undefined) return -1;
    if (yi === undefined) return 1;
    const c = compareIdentifiers(xi, yi);
    if (c !== 0) return c < 0 ? -1 : 1;
  }
  return 0;
}

// ─── Ranges ──────────────────────────────────────────────────────────────────

interface PartialVersion {
  major: number | undefined;
  minor: number | undefined;
  patch: number | undefined;
  prerelease: (string | number)[];
}

const PARTIAL_RE =
  /^[=v]*(\d{1,9}|[xX*])(?:\.(\d{1,9}|[xX*])(?:\.(\d{1,9}|[xX*])(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?)?)?$/;

function parsePartial(input: string): PartialVersion | null {
  const m = PARTIAL_RE.exec(input);
  if (!m) return null;
  const num = (s: string | undefined): number | undefined =>
    s === undefined || /^[xX*]$/.test(s) ? undefined : Number(s);
  const major = num(m[1]);
  const minor = major === undefined ? undefined : num(m[2]);
  const patch = minor === undefined ? undefined : num(m[3]);
  return { major, minor, patch, prerelease: patch === undefined ? [] : parseIdentifiers(m[4]) };
}

const v = (major: number, minor: number, patch: number, prerelease: (string | number)[] = []) => ({
  major,
  minor,
  patch,
  prerelease,
});

/** `<x.y.z-0`: the lowest possible version of x.y.z, used as an exclusive upper bound. */
const lowest = (major: number, minor: number, patch: number): SemVer => v(major, minor, patch, [0]);

function floor(p: PartialVersion): SemVer {
  return v(p.major ?? 0, p.minor ?? 0, p.patch ?? 0, p.prerelease);
}

function expandCaret(p: PartialVersion): Comparator[] {
  if (p.major === undefined) return [];
  const lo: Comparator = { op: ">=", version: floor(p) };
  let hi: SemVer;
  if (p.major > 0 || p.minor === undefined) hi = lowest(p.major + 1, 0, 0);
  else if (p.minor > 0 || p.patch === undefined) hi = lowest(0, p.minor + 1, 0);
  else hi = lowest(0, 0, p.patch + 1);
  return [lo, { op: "<", version: hi }];
}

function expandTilde(p: PartialVersion): Comparator[] {
  if (p.major === undefined) return [];
  const lo: Comparator = { op: ">=", version: floor(p) };
  const hi = p.minor === undefined ? lowest(p.major + 1, 0, 0) : lowest(p.major, p.minor + 1, 0);
  return [lo, { op: "<", version: hi }];
}

/** A bare partial (`1`, `1.2`, `1.2.x`, `1.2.3`) as comparators. */
function expandPlain(p: PartialVersion): Comparator[] {
  if (p.major === undefined) return [];
  if (p.minor === undefined)
    return [
      { op: ">=", version: v(p.major, 0, 0) },
      { op: "<", version: lowest(p.major + 1, 0, 0) },
    ];
  if (p.patch === undefined)
    return [
      { op: ">=", version: v(p.major, p.minor, 0) },
      { op: "<", version: lowest(p.major, p.minor + 1, 0) },
    ];
  return [{ op: "=", version: floor(p) }];
}

function expandOperator(op: string, p: PartialVersion): Comparator[] | null {
  if (op === "" || op === "=") return expandPlain(p);
  if (p.major === undefined) {
    // `<*` matches nothing; `>=*`, `>*`, `<=*` behave as `*`.
    return op === "<" || op === ">" ? null : [];
  }
  const full = p.minor !== undefined && p.patch !== undefined;
  if (full) return [{ op: op as ComparatorOp, version: floor(p) }];
  // Partial versions with an operator.
  switch (op) {
    case ">=":
      return [{ op: ">=", version: floor(p) }];
    case "<":
      return [{ op: "<", version: lowest(p.major, p.minor ?? 0, 0) }];
    case ">":
      return [
        {
          op: ">=",
          version: p.minor === undefined ? v(p.major + 1, 0, 0) : v(p.major, p.minor + 1, 0),
        },
      ];
    case "<=":
      return [
        {
          op: "<",
          version:
            p.minor === undefined ? lowest(p.major + 1, 0, 0) : lowest(p.major, p.minor + 1, 0),
        },
      ];
    default:
      return null;
  }
}

function parseAndSet(input: string): Comparator[] | null {
  const text = input.trim();
  if (text === "" || text === "*" || /^[xX]$/.test(text)) return [];

  const hyphen = /^(\S+)\s+-\s+(\S+)$/.exec(text);
  if (hyphen) {
    const from = parsePartial(hyphen[1]!);
    const to = parsePartial(hyphen[2]!);
    if (!from || !to) return null;
    const set: Comparator[] = [];
    if (from.major !== undefined) set.push({ op: ">=", version: floor(from) });
    if (to.major !== undefined) {
      if (to.minor === undefined) set.push({ op: "<", version: lowest(to.major + 1, 0, 0) });
      else if (to.patch === undefined)
        set.push({ op: "<", version: lowest(to.major, to.minor + 1, 0) });
      else set.push({ op: "<=", version: floor(to) });
    }
    return set;
  }

  // Glue operators to their versions (`>= 1.2.3` -> `>=1.2.3`), then split on whitespace.
  const tokens = text.replace(/(<=|>=|<|>|=|\^|~>?)\s+/g, "$1").split(/\s+/);
  const set: Comparator[] = [];
  for (const token of tokens) {
    const m = /^(<=|>=|<|>|=|\^|~>?)?(.*)$/.exec(token);
    if (!m) return null;
    const op = m[1] ?? "";
    const p = parsePartial(m[2] ?? "");
    if (!p) return null;
    let expanded: Comparator[] | null;
    if (op === "^") expanded = expandCaret(p);
    else if (op === "~" || op === "~>") expanded = expandTilde(p);
    else expanded = expandOperator(op, p);
    if (expanded === null) return null;
    set.push(...expanded);
  }
  return set;
}

/**
 * Parses an npm range (`^1.2.3`, `~1.2`, `1.x`, `>=1 <2`, `1.0.0 - 2.0.0`, `a || b`).
 * Returns null when any part is not a range (tags, URLs, git specs, garbage).
 */
export function parseRange(spec: string): Range | null {
  if (typeof spec !== "string" || spec.length > 1024) return null;
  const sets: Range = [];
  for (const part of spec.split("||")) {
    const set = parseAndSet(part);
    if (set === null) return null;
    sets.push(set);
  }
  return sets.length > 0 ? sets : null;
}

function testComparator(version: SemVer, c: Comparator): boolean {
  const cmp = compareVersions(version, c.version);
  switch (c.op) {
    case "<":
      return cmp < 0;
    case "<=":
      return cmp <= 0;
    case ">":
      return cmp > 0;
    case ">=":
      return cmp >= 0;
    case "=":
      return cmp === 0;
  }
}

/** True when `version` falls in `range` (a parsed Range or a range string). */
export function satisfies(version: SemVer | string, range: Range | string): boolean {
  const ver = toSemVer(version);
  const r = typeof range === "string" ? parseRange(range) : range;
  if (!ver || !r) return false;
  return r.some((set) => set.every((c) => testComparator(ver, c)));
}

/** The lowest version a range admits, or null when it admits none. */
export function minVersion(range: Range | string): SemVer | null {
  const r = typeof range === "string" ? parseRange(range) : range;
  if (!r) return null;
  let best: SemVer | null = null;
  for (const set of r) {
    let candidate: SemVer = v(0, 0, 0);
    for (const c of set) {
      if (c.op === ">=" || c.op === "=") {
        if (compareVersions(c.version, candidate) > 0 || c.op === "=") candidate = c.version;
      } else if (c.op === ">") {
        const next =
          c.version.prerelease.length > 0
            ? v(c.version.major, c.version.minor, c.version.patch, [...c.version.prerelease, 0])
            : v(c.version.major, c.version.minor, c.version.patch + 1);
        if (compareVersions(next, candidate) > 0) candidate = next;
      }
    }
    let found: SemVer | null = null;
    if (set.every((c) => testComparator(candidate, c))) found = candidate;
    else {
      const pre = v(candidate.major, candidate.minor, candidate.patch, [0]);
      if (candidate.prerelease.length === 0 && set.every((c) => testComparator(pre, c)))
        found = pre;
    }
    if (found && (!best || compareVersions(found, best) < 0)) best = found;
  }
  return best;
}

// ─── Specs ───────────────────────────────────────────────────────────────────

export type SpecKind =
  "exact" | "range" | "tag" | "git" | "url" | "file" | "workspace" | "alias" | "invalid";

/** Classifies a package.json dependency spec. Only `exact` and `range` are registry versions. */
export function classifySpec(spec: string): SpecKind {
  if (typeof spec !== "string") return "invalid";
  const s = spec.trim();
  if (s.startsWith("npm:")) return "alias";
  if (s.startsWith("workspace:")) return "workspace";
  if (/^(?:file|link|portal|patch):/.test(s)) return "file";
  if (/^(?:git\+|git:|github:|gitlab:|bitbucket:|gist:)/.test(s)) return "git";
  if (/^https?:\/\//i.test(s)) return /\.git(?:#|$)/.test(s) ? "git" : "url";
  if (/^(?:\.{0,2}\/|~\/)/.test(s)) return "file";
  if (/^[\w.-]+\/[\w.-]+(?:#.*)?$/.test(s) && !/^\d/.test(s)) return "git"; // user/repo shorthand
  if (parseVersion(s) !== null && !/^[<>~^]/.test(s)) return "exact";
  if (parseRange(s) !== null) return "range";
  if (/^[A-Za-z][\w.-]*$/.test(s)) return "tag";
  return "invalid";
}

// ─── Lockfiles ───────────────────────────────────────────────────────────────

export interface ResolvedEntry {
  version: string;
  /** 1-based line of the entry in the lockfile (undefined when it cannot be located). */
  line?: number | undefined;
}

/** Package name -> every version the lockfile resolves it to (first occurrence per version). */
export type ResolvedVersions = Map<string, ResolvedEntry[]>;

function add(map: ResolvedVersions, name: string, version: string, line?: number): void {
  if (!name || !parseVersion(version)) return;
  const list = map.get(name) ?? [];
  if (!list.some((e) => e.version === version)) list.push({ version, line });
  map.set(name, list);
}

/** First 1-based line of each `"key": {` in a JSON lockfile, built in one pass. */
function jsonKeyLines(text: string): Map<string, number> {
  const out = new Map<string, number>();
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*"((?:[^"\\]|\\.)*)":\s*\{/.exec(lines[i]!);
    if (m && !out.has(m[1]!)) out.set(m[1]!, i + 1);
  }
  return out;
}

function fromPackageLock(text: string): ResolvedVersions {
  const map: ResolvedVersions = new Map();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return map;
  }
  if (typeof json !== "object" || json === null) return map;
  const root = json as Record<string, unknown>;
  const keyLines = jsonKeyLines(text);
  const packages = root.packages;
  if (typeof packages === "object" && packages !== null) {
    // lockfileVersion 2 and 3: "node_modules/a/node_modules/@s/b": { version }.
    for (const [key, value] of Object.entries(packages as Record<string, unknown>)) {
      const idx = key.lastIndexOf("node_modules/");
      if (idx < 0 || typeof value !== "object" || value === null) continue;
      const name = key.slice(idx + "node_modules/".length);
      const version = (value as Record<string, unknown>).version;
      if (typeof version === "string") add(map, name, version, keyLines.get(key));
    }
    return map;
  }
  // lockfileVersion 1: nested "dependencies": { name: { version, dependencies } }.
  const walk = (deps: unknown, depth: number): void => {
    if (depth > 64 || typeof deps !== "object" || deps === null) return;
    for (const [name, value] of Object.entries(deps as Record<string, unknown>)) {
      if (typeof value !== "object" || value === null) continue;
      const entry = value as Record<string, unknown>;
      if (typeof entry.version === "string") add(map, name, entry.version, keyLines.get(name));
      walk(entry.dependencies, depth + 1);
    }
  };
  walk(root.dependencies, 0);
  return map;
}

const PNPM_KEY_RE =
  /^ {2}['"]?\/?((?:@[^/\s'"@]+\/)?[^/\s'"@()]+)[@/](\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)(?=[\s'"():_]|$)/;

function fromPnpmLock(text: string): ResolvedVersions {
  const map: ResolvedVersions = new Map();
  const lines = text.split(/\r?\n/);
  let inPackages = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (/^\S/.test(line)) {
      inPackages = /^(?:packages|snapshots):\s*$/.test(line);
      continue;
    }
    if (!inPackages) continue;
    const m = PNPM_KEY_RE.exec(line);
    if (m) add(map, m[1]!, m[2]!, i + 1);
  }
  return map;
}

function descriptorName(descriptor: string): string {
  const d = descriptor.trim().replace(/^["']|["']$/g, "");
  const at = d.indexOf("@", d.startsWith("@") ? 1 : 0);
  return at > 0 ? d.slice(0, at) : d;
}

function fromYarnLock(text: string): ResolvedVersions {
  const map: ResolvedVersions = new Map();
  const lines = text.split(/\r?\n/);
  let names: string[] = [];
  let headerLine = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (line.startsWith("#") || line.trim() === "") continue;
    if (/^\S.*:\s*$/.test(line)) {
      const header = line.replace(/:\s*$/, "");
      if (header === "__metadata" || /@(?:workspace|link|portal|file):/.test(header)) {
        names = [];
        continue;
      }
      names = [...new Set(header.split(/,\s*/).map(descriptorName))].filter(Boolean);
      headerLine = i + 1;
      continue;
    }
    const m = /^\s+version:?\s+["']?([^"'\s]+)["']?\s*$/.exec(line);
    if (m && names.length > 0) {
      for (const name of names) add(map, name, m[1]!, headerLine);
      names = [];
    }
  }
  return map;
}

/**
 * Every version a lockfile resolves each package to. `fileName` is the lockfile's
 * basename (`package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`).
 * Returns an empty map for unknown names or unparseable content.
 */
export function resolvedVersions(fileName: string, content: string): ResolvedVersions {
  if (typeof content !== "string" || content.length === 0) return new Map();
  const base = fileName.replace(/\\/g, "/").split("/").pop() ?? "";
  if (base === "package-lock.json" || base === "npm-shrinkwrap.json")
    return fromPackageLock(content);
  if (base === "pnpm-lock.yaml") return fromPnpmLock(content);
  if (base === "yarn.lock") return fromYarnLock(content);
  return new Map();
}
