/** Builds copy-paste curl lines that use environment placeholders, never credential values. */

export interface CurlOptions {
  /** Base URL of the target as stored in the run (the run's targetUrl). */
  targetUrl: string;
  /** Concrete request path, e.g. "/api/notes/2". */
  path: string;
  /** Session label; yields a $<LABEL>_COOKIE placeholder. Omit for anonymous requests. */
  session?: string | undefined;
  /** Header the session credential is sent in. Defaults to Cookie. */
  headerName?: "Cookie" | "Authorization" | undefined;
  /** Defaults to process.platform. */
  platform?: string | undefined;
}

/** Environment variable name for a session label, e.g. "alice" -> "ALICE_COOKIE". */
export function placeholderName(session: string, headerName: string = "Cookie"): string {
  const base =
    session
      .toUpperCase()
      .replace(/[^A-Z0-9]+/g, "_")
      .replace(/^_+|_+$/g, "") || "SESSION";
  const prefixed = /^[0-9]/.test(base) ? `S_${base}` : base;
  return `${prefixed}_${headerName === "Cookie" ? "COOKIE" : "TOKEN"}`;
}

/** Percent-encodes everything that could break out of a quoted shell argument. */
function safePath(path: string): string {
  const p = path.startsWith("/") ? path : `/${path}`;
  return p.replace(/[^A-Za-z0-9\-._~/%?=&:@,+]/g, (c) => {
    const code = c.codePointAt(0) ?? 0;
    return code < 128 ? `%${code.toString(16).toUpperCase().padStart(2, "0")}` : "_";
  });
}

function safeBase(targetUrl: string): string {
  const trimmed = targetUrl.replace(/\/+$/, "");
  return /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[A-Za-z0-9.:[\]-]+$/.test(trimmed) ? trimmed : "<target>";
}

export function formatCurl(o: CurlOptions): string {
  const win = (o.platform ?? process.platform) === "win32";
  const url = `${safeBase(o.targetUrl)}${safePath(o.path)}`;
  const parts = [win ? "curl.exe" : "curl", "-s"];
  if (o.session !== undefined) {
    const header = o.headerName ?? "Cookie";
    const name = placeholderName(o.session, header);
    parts.push("-H", win ? `"${header}: $env:${name}"` : `"${header}: $${name}"`);
  }
  parts.push(win ? `"${url}"` : `'${url}'`);
  return parts.join(" ");
}

/** The replay line avoids shell-quoting problems entirely. */
export function replayLine(attackId: string): string {
  return `npx vibesafe attack --replay ${attackId}`;
}
