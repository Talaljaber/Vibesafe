import { randomBytes } from "crypto";

/** Random nonce for inline webview scripts. */
export function getNonce(): string {
  return randomBytes(16).toString("base64url");
}

/** Content-Security-Policy for a webview; scripts only run with the given nonce. */
export function buildCsp(cspSource: string, nonce?: string): string {
  const script = nonce ? `script-src 'nonce-${nonce}'` : "script-src 'none'";
  return `default-src 'none'; style-src ${cspSource} 'unsafe-inline'; ${script};`;
}

/** The `<meta>` tag carrying the CSP. */
export function cspMeta(cspSource: string, nonce?: string): string {
  return `<meta http-equiv="Content-Security-Policy" content="${buildCsp(cspSource, nonce)}">`;
}
