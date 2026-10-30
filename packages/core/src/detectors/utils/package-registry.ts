// ─────────────────────────────────────────────────────────────────────────────
// Registry helpers for the opt-in online package existence check.
//
// Pure functions (URL builders, response parsers, .npmrc / .yarnrc.yml / lockfile
// readers) plus a tiny concurrency helper. Nothing here performs I/O: the detector
// passes in an injectable fetch. Every parser treats an unexpected shape as "no data"
// and never throws.
// ─────────────────────────────────────────────────────────────────────────────

export const NPM_REGISTRY = "https://registry.npmjs.org";
export const NPM_DOWNLOADS = "https://api.npmjs.org/downloads/point/last-week";
export const PYPI_JSON = "https://pypi.org/pypi";

/** Hosts that count as the public npm registry (lockfiles and config pointing here are "default"). */
export const DEFAULT_NPM_REGISTRY_HOSTS: readonly string[] = [
  "registry.npmjs.org",
  "registry.yarnpkg.com",
  "registry.npmmirror.com",
];

/**
 * Called without a `redirect` option, so `globalThis.fetch` follows redirects (PyPI 301s
 * non-normalised names); test mocks return the final response directly.
 */
export type FetchLike = (
  url: string,
  init: { method: "GET"; headers: Record<string, string>; signal: AbortSignal },
) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

/** .npmrc / .yarnrc.yml: scopes with their own registry, and whether the default one is overridden. */
export interface RegistryConfig {
  /** Scopes including the leading "@", for example "@acme". */
  privateScopes: Set<string>;
  defaultIsPrivate: boolean;
}

function hostOf(url: string): string | undefined {
  try {
    return new URL(url.trim()).host.toLowerCase();
  } catch {
    return undefined;
  }
}

/** True when `url` parses and points at a host other than the public npm registries. */
function isPrivateRegistryUrl(url: string): boolean {
  const host = hostOf(url);
  return host !== undefined && !DEFAULT_NPM_REGISTRY_HOSTS.includes(host);
}

const unquote = (s: string): string => s.trim().replace(/^(["'])(.*)\1$/, "$2");

/** `@acme:registry=https://npm.acme.dev/` and `registry=https://...` lines of an .npmrc. */
export function parseNpmrc(text: string): RegistryConfig {
  const config: RegistryConfig = { privateScopes: new Set(), defaultIsPrivate: false };
  if (typeof text !== "string") return config;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#") || line.startsWith(";")) continue;
    const m = /^(?:(@[A-Za-z0-9._~-]+):)?registry\s*=\s*(.+)$/.exec(line);
    if (!m || !isPrivateRegistryUrl(unquote(m[2]!))) continue;
    if (m[1]) config.privateScopes.add(m[1].toLowerCase());
    else config.defaultIsPrivate = true;
  }
  return config;
}

/** `npmRegistryServer:` and `npmScopes: { acme: { npmRegistryServer } }` of a .yarnrc.yml. */
export function parseYarnrc(text: string): RegistryConfig {
  const config: RegistryConfig = { privateScopes: new Set(), defaultIsPrivate: false };
  if (typeof text !== "string") return config;
  let inScopes = false;
  let scope: string | undefined;
  for (const raw of text.split(/\r?\n/)) {
    if (raw.trim() === "" || raw.trim().startsWith("#")) continue;
    const indent = raw.length - raw.trimStart().length;
    const line = raw.trim();
    if (indent === 0) {
      inScopes = /^npmScopes\s*:/.test(line);
      scope = undefined;
      const top = /^npmRegistryServer\s*:\s*(.+)$/.exec(line);
      if (top && isPrivateRegistryUrl(unquote(top[1]!))) config.defaultIsPrivate = true;
      continue;
    }
    if (!inScopes) continue;
    const key = /^["']?([A-Za-z0-9._~-]+)["']?\s*:\s*$/.exec(line);
    if (key && indent <= 2) {
      scope = `@${key[1]!.toLowerCase()}`;
      continue;
    }
    const server = /^npmRegistryServer\s*:\s*(.+)$/.exec(line);
    if (server && scope && isPrivateRegistryUrl(unquote(server[1]!))) {
      config.privateScopes.add(scope);
    }
  }
  return config;
}

export function mergeRegistryConfig(a: RegistryConfig, b: RegistryConfig): RegistryConfig {
  return {
    privateScopes: new Set([...a.privateScopes, ...b.privateScopes]),
    defaultIsPrivate: a.defaultIsPrivate || b.defaultIsPrivate,
  };
}

const NON_DEFAULT_HOST = (host: string): boolean =>
  !DEFAULT_NPM_REGISTRY_HOSTS.includes(host.toLowerCase());

/** Names a lockfile resolves from a non-default registry. Linear, line based. */
export function nonDefaultRegistryNames(lockfileName: string, content: string): Set<string> {
  const out = new Set<string>();
  if (typeof content !== "string" || content === "") return out;
  const base = lockfileName.replace(/\\/g, "/").split("/").pop() ?? "";
  const lines = content.split(/\r?\n/);

  if (base === "package-lock.json") {
    let name: string | undefined;
    for (const line of lines) {
      const key = /^\s*"(?:.*\/)?node_modules\/((?:@[^/"]+\/)?[^/"]+)"\s*:\s*\{/.exec(line);
      if (key) {
        name = key[1];
        continue;
      }
      const resolved = /^\s*"resolved"\s*:\s*"https?:\/\/([^/"]+)/i.exec(line);
      if (resolved && name !== undefined && NON_DEFAULT_HOST(resolved[1]!)) out.add(name);
    }
  } else if (base === "pnpm-lock.yaml") {
    let name: string | undefined;
    for (const line of lines) {
      const key = /^\s{2}['"]?\/?((?:@[^/@\s]+\/)?[^/@\s:'"]+)[@/]/.exec(line);
      if (key) {
        name = key[1];
        continue;
      }
      const tarball = /tarball:\s*['"]?https?:\/\/([^/'"\s,}]+)/i.exec(line);
      if (tarball && name !== undefined && NON_DEFAULT_HOST(tarball[1]!)) out.add(name);
    }
  } else if (base === "yarn.lock") {
    let name: string | undefined;
    for (const line of lines) {
      if (line !== "" && !/^\s/.test(line) && !line.startsWith("#") && line.endsWith(":")) {
        const first = (line.slice(0, -1).split(",")[0] ?? "").trim().replace(/^["']|["']$/g, "");
        const at = first.lastIndexOf("@");
        name = at > 0 ? first.slice(0, at) : undefined;
        continue;
      }
      const resolved = /^\s+resolved\s+["']https?:\/\/([^/"']+)/i.exec(line);
      if (resolved && name !== undefined && NON_DEFAULT_HOST(resolved[1]!)) out.add(name);
    }
  }
  return out;
}

/** Runs fn over items with at most `limit` in flight; stops starting new work once `signal` aborts. */
export async function mapLimit<T, R>(
  items: readonly T[],
  limit: number,
  signal: AbortSignal,
  fn: (item: T) => Promise<R>,
): Promise<(R | undefined)[]> {
  const results: (R | undefined)[] = new Array<R | undefined>(items.length).fill(undefined);
  let next = 0;
  const worker = async (): Promise<void> => {
    while (!signal.aborted) {
      const i = next++;
      if (i >= items.length) return;
      try {
        results[i] = await fn(items[i] as T);
      } catch {
        results[i] = undefined;
      }
    }
  };
  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker);
  await Promise.all(workers);
  return results;
}

// ─── URLs ────────────────────────────────────────────────────────────────────

const encodeName = (name: string): string => name.replace("/", "%2f");

/** Full packument; a scoped "/" is encoded: https://registry.npmjs.org/@acme%2fui */
export function npmPackumentUrl(name: string): string {
  return `${NPM_REGISTRY}/${encodeName(name)}`;
}

/** Latest version document, unscoped names only: https://registry.npmjs.org/<name>/latest */
export function npmLatestUrl(name: string): string {
  return `${NPM_REGISTRY}/${name}/latest`;
}

/** Comma-joined unscoped names (the API takes up to 128) or one scoped name. */
export function npmDownloadsUrl(names: readonly string[]): string {
  return `${NPM_DOWNLOADS}/${names.join(",")}`;
}

/** PEP 503 normalisation. Applied before dedupe and URL building. */
export function normalizePypiName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, "-");
}

export function pypiUrl(normalizedName: string): string {
  return `${PYPI_JSON}/${normalizedName}/json`;
}

// ─── Response parsers ────────────────────────────────────────────────────────

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/** True when `json` looks like a downloads response for `names` (bulk map or single object). */
export function isDownloadsShape(names: readonly string[], json: unknown): boolean {
  if (!isObject(json)) return false;
  if (names.length === 1) return typeof json.downloads === "number" || names[0]! in json;
  return true;
}

/** Weekly downloads per name from a downloads response; null for unknown names. */
export function parseDownloads(
  names: readonly string[],
  json: unknown,
): Map<string, number | null> {
  const out = new Map<string, number | null>();
  for (const n of names) out.set(n, null);
  if (!isObject(json)) return out;
  if (names.length === 1 && typeof json.downloads === "number") {
    out.set(names[0]!, json.downloads);
    return out;
  }
  for (const n of names) {
    const entry = json[n];
    if (isObject(entry) && typeof entry.downloads === "number") out.set(n, entry.downloads);
  }
  return out;
}

const SECURITY_HOLDER_DESCRIPTION = /^security holding package$/i;

function describesSecurityHolder(json: Record<string, unknown>): boolean {
  const description = typeof json.description === "string" ? json.description : "";
  return SECURITY_HOLDER_DESCRIPTION.test(description.trim());
}

/** From a full packument. */
export function parsePackument(json: unknown): {
  created: number | undefined;
  unpublished: boolean;
  securityHolder: boolean;
} {
  if (!isObject(json)) return { created: undefined, unpublished: false, securityHolder: false };
  const time = isObject(json.time) ? json.time : {};
  const parsed = typeof time.created === "string" ? Date.parse(time.created) : Number.NaN;
  const tags = isObject(json["dist-tags"]) ? json["dist-tags"] : {};
  return {
    created: Number.isFinite(parsed) ? parsed : undefined,
    unpublished: "unpublished" in time && time.unpublished !== undefined,
    securityHolder: tags.latest === "0.0.1-security" || describesSecurityHolder(json),
  };
}

/** From a `/<name>/latest` version document. */
export function parseLatest(json: unknown): { securityHolder: boolean } {
  if (!isObject(json)) return { securityHolder: false };
  return { securityHolder: json.version === "0.0.1-security" || describesSecurityHolder(json) };
}

/**
 * First upload time (minimum over every file of every release) and the number of releases
 * with files. `undefined` when `json.releases` is not an object (malformed, so "failed").
 */
export function parsePypi(
  json: unknown,
): { created: number | undefined; releases: number } | undefined {
  if (!isObject(json) || !isObject(json.releases)) return undefined;
  let releases = 0;
  let created: number | undefined;
  for (const files of Object.values(json.releases)) {
    if (!Array.isArray(files) || files.length === 0) continue;
    releases++;
    for (const file of files) {
      if (!isObject(file) || typeof file.upload_time_iso_8601 !== "string") continue;
      const t = Date.parse(file.upload_time_iso_8601);
      if (Number.isFinite(t) && (created === undefined || t < created)) created = t;
    }
  }
  return { created, releases };
}
