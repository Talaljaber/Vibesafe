import { createHash, randomBytes } from "node:crypto";
import type { ControlSet, Fingerprint, ProbeRequest } from "./types.js";

const MAX_KEYS = 200;
const ISO_TIMESTAMP_RE =
  /\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?/g;
const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
const HEX_RUN_RE = /[0-9a-f]{8,}/gi;

export function contentClassOf(contentType: string): Fingerprint["contentClass"] {
  const ct = contentType.toLowerCase();
  if (ct.includes("json")) return "json";
  if (ct.includes("html")) return "html";
  if (ct.startsWith("text/")) return "text";
  return "other";
}

/** Strips only ISO timestamps, UUIDs and hex runs of 8+ characters. */
export function normalizeBody(body: string): string {
  return body.replace(ISO_TIMESTAMP_RE, "").replace(UUID_RE, "").replace(HEX_RUN_RE, "");
}

function jsonKeys(body: string): string[] | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return undefined;
  }
  const keys = new Set<string>();
  let target: unknown = parsed;
  if (Array.isArray(parsed)) {
    keys.add("[]");
    target = parsed[0];
  }
  if (target !== null && typeof target === "object" && !Array.isArray(target)) {
    for (const k of Object.keys(target as Record<string, unknown>).slice(0, MAX_KEYS)) keys.add(k);
  }
  return [...keys].sort();
}

/** Builds the fingerprint of a response (spec section 8). */
export function fingerprintResponse(
  status: number,
  contentType: string,
  body: string,
): Fingerprint {
  const contentClass = contentClassOf(contentType);
  const fp: Fingerprint = { status, contentClass };
  if (contentClass === "json") {
    const keys = jsonKeys(body);
    if (keys) {
      fp.keys = keys;
      return fp;
    }
  }
  fp.lengthBucket = Math.floor(Math.log2(body.length + 1));
  fp.hash = createHash("sha256").update(normalizeBody(body)).digest("hex");
  return fp;
}

function sameKeys(a: string[] | undefined, b: string[] | undefined): boolean {
  return !!a && !!b && a.length === b.length && a.every((k, i) => k === b[i]);
}

/** True when status and class are equal and either key sets or hashes are equal. */
export function fingerprintsMatch(a: Fingerprint, b: Fingerprint): boolean {
  if (a.status !== b.status || a.contentClass !== b.contentClass) return false;
  if (sameKeys(a.keys, b.keys)) return true;
  return a.hash !== undefined && a.hash === b.hash;
}

export function buildControlSet(fingerprints: readonly Fingerprint[]): ControlSet {
  const list = [...fingerprints];
  return { fingerprints: list, matches: (fp) => list.some((c) => fingerprintsMatch(c, fp)) };
}

const rand = (bytes: number): string => randomBytes(bytes).toString("hex");

export interface ControlPlanOptions {
  /** Route patterns, e.g. "/api/notes/[id]". Only dynamic ones get a Cr. */
  dynamicRoutes?: readonly string[] | undefined;
  /** Label of the first session, when sessions exist. */
  firstSession?: string | undefined;
  /** Injectable randomness for tests: returns n random bytes as hex (2n chars). */
  random?: ((bytes: number) => string) | undefined;
}

/** Replaces every [segment], [...segment] and [[...segment]] with the given value. */
export function substituteSegments(pattern: string, value: string): string {
  return pattern.replace(/\[\[?\.{0,3}[^\]]+\]\]?/g, value);
}

/** The control requests of a run: C1, C2, then one Cr per dynamic route (anon, plus first session). */
export function planControlRequests(opts: ControlPlanOptions = {}): ProbeRequest[] {
  const r = opts.random ?? rand;
  const out: ProbeRequest[] = [
    { label: "C1", method: "GET", host: "target", path: `/__vibesafe_${r(8)}` },
    { label: "C2", method: "GET", host: "target", path: `/__vibesafe_${r(8)}.env` },
  ];
  const seen = new Set<string>();
  for (const route of opts.dynamicRoutes ?? []) {
    if (!route.includes("[") || seen.has(route)) continue;
    seen.add(route);
    const path = substituteSegments(route, `__vs_${r(4)}`);
    const n = seen.size;
    out.push({ label: `Cr${n}`, method: "GET", host: "target", path });
    if (opts.firstSession !== undefined) {
      out.push({
        label: `Cr${n}s`,
        method: "GET",
        host: "target",
        path,
        session: opts.firstSession,
      });
    }
  }
  return out;
}
