import type { Finding, ScanResult } from "@vibesafe/shared";

/**
 * In-memory cache of the most recent scan.
 *
 * MCP tools are stateless RPC calls — the server process is the only thing
 * that persists between them. Finding IDs returned by vibesafe_scan are only
 * meaningful for the lifetime of this cache; a fresh vibesafe_scan replaces it.
 */
export interface ScanState {
  result: ScanResult | null;
  rootPath: string | null;
  findingsById: Map<string, Finding>;
}

export function createScanState(): ScanState {
  return { result: null, rootPath: null, findingsById: new Map() };
}

export function setScanResult(state: ScanState, rootPath: string, result: ScanResult): void {
  state.result = result;
  state.rootPath = rootPath;
  state.findingsById = new Map(result.findings.map((f) => [f.id, f]));
}
