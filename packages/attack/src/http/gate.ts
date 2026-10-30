/**
 * Pure request gate (spec 3.1). Runs before any socket opens, on the raw URL string and a WHATWG URL.
 * A request is allowed only for loopback (exact host set) or the pinned Supabase project.
 */

export type GateReason =
  | "method"
  | "body"
  | "malformed"
  | "protocol"
  | "userinfo"
  | "not-loopback"
  | "https-only-supabase"
  | "remote-off"
  | "ref-mismatch"
  | "path"
  | "query"
  | "headers"
  | "cross-host"
  | "loop"
  | "ceiling";

export interface GateRequest {
  method: string;
  url: string;
  /** Anything other than undefined/null is a body and is refused. */
  body?: unknown;
  headers?: Readonly<Record<string, string>> | undefined;
}

export interface GateConfig {
  /** --supabase-project value. Remote access stays off unless set. */
  supabaseProject?: string | undefined;
  /** Ref derived from the project env (NEXT_PUBLIC_SUPABASE_URL and friends). */
  envSupabaseRef?: string | undefined;
}

export type GateDecision =
  | { allowed: true; url: URL; kind: "loopback" | "supabase" }
  | { allowed: false; reason: GateReason; detail?: string };

export const MAX_URL_LENGTH = 2048;
const ALLOWED_HEADERS = new Set([
  "cookie",
  "authorization",
  "apikey",
  "accept",
  "user-agent",
  "x-vibesafe-attack",
]);
const LOOPBACK_RAW_HOSTS = new Set(["127.0.0.1", "[::1]", "localhost"]);
const SUPABASE_PATH_RE = /^\/rest\/v1\/[A-Za-z0-9_]{1,63}$/;
const SUPABASE_HOST_RE = /^([a-z0-9]{1,63})\.supabase\.co$/;
// anything outside printable ASCII (whitespace, control characters, non-ASCII), a backslash, or an encoded NUL
const MALFORMED_RE = /[^\x21-\x7e]|\\|%00/i;

function deny(reason: GateReason, detail?: string): GateDecision {
  return detail === undefined ? { allowed: false, reason } : { allowed: false, reason, detail };
}

function rawAuthority(raw: string): { host: string; path: string } | undefined {
  const m = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/([^/?#]*)([^?#]*)/.exec(raw);
  if (!m) return undefined;
  const authority = m[1] ?? "";
  const at = authority.lastIndexOf("@");
  const hostPort = at >= 0 ? authority.slice(at + 1) : authority;
  const host = hostPort.startsWith("[")
    ? hostPort.slice(0, hostPort.indexOf("]") + 1)
    : (hostPort.split(":")[0] ?? "");
  return { host, path: m[2] ?? "" };
}

function checkHeaders(headers: Readonly<Record<string, string>> | undefined): boolean {
  if (!headers) return true;
  for (const [name, value] of Object.entries(headers)) {
    const lower = name.toLowerCase();
    if (!ALLOWED_HEADERS.has(lower)) return false;
    if (typeof value !== "string" || !/^[\t\x20-\x7e]*$/.test(value)) return false;
    if (lower === "user-agent" && !value.startsWith("vibesafe-attack/")) return false;
    if (lower === "x-vibesafe-attack" && value !== "1") return false;
  }
  return true;
}

export function checkRequest(req: GateRequest, config: GateConfig = {}): GateDecision {
  if (req.method !== "GET") return deny("method", String(req.method));
  if (req.body !== undefined && req.body !== null) return deny("body");

  const raw = req.url;
  if (typeof raw !== "string" || raw.length === 0 || raw.length > MAX_URL_LENGTH) {
    return deny("malformed", "length");
  }
  if (MALFORMED_RE.test(raw)) return deny("malformed", "characters");
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return deny("malformed", "unparseable");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return deny("protocol", url.protocol);
  if (url.username !== "" || url.password !== "" || /^[^/]*\/\/[^/?#]*@/.test(raw)) {
    return deny("userinfo");
  }
  const parts = rawAuthority(raw);
  if (!parts) return deny("malformed", "authority");
  if (url.hash !== "") return deny("malformed", "fragment");

  if (url.protocol === "http:") {
    // The raw host must be in the exact set: WHATWG normalises 127.1, 2130706433 and 0x7f000001
    // to 127.0.0.1, which must not be accepted.
    if (
      !LOOPBACK_RAW_HOSTS.has(parts.host.toLowerCase()) ||
      !LOOPBACK_RAW_HOSTS.has(url.hostname.toLowerCase())
    ) {
      return deny("not-loopback", parts.host);
    }
    if (!checkHeaders(req.headers)) return deny("headers");
    return { allowed: true, url, kind: "loopback" };
  }

  // https: only the pinned Supabase project
  const hostMatch = SUPABASE_HOST_RE.exec(url.hostname);
  if (!hostMatch || parts.host.toLowerCase() !== url.hostname) return deny("https-only-supabase");
  if (url.port !== "") return deny("https-only-supabase");
  const project = config.supabaseProject;
  if (project === undefined || project === "") return deny("remote-off");
  if (config.envSupabaseRef === undefined || config.envSupabaseRef !== project) {
    return deny("ref-mismatch");
  }
  if (hostMatch[1] !== project) return deny("ref-mismatch");
  if (!SUPABASE_PATH_RE.test(parts.path) || !SUPABASE_PATH_RE.test(url.pathname)) {
    return deny("path");
  }
  const entries = [...url.searchParams.entries()];
  const keys = entries.map(([k]) => k).sort();
  if (
    entries.length !== 2 ||
    keys[0] !== "limit" ||
    keys[1] !== "select" ||
    url.searchParams.get("select") !== "*" ||
    url.searchParams.get("limit") !== "1"
  ) {
    return deny("query");
  }
  if (!checkHeaders(req.headers)) return deny("headers");
  return { allowed: true, url, kind: "supabase" };
}
