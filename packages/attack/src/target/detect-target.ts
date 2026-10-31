/**
 * Target detection (spec 6): pick the dev server, then verify it looks like this project before
 * any probe is sent. Every request goes through the SafeHttpClient passed in.
 */
import type { SafeHttpClient, SafeResponse } from "../http/safe-client.js";
import { checkLoopbackTarget } from "../sessions.js";

/** Thrown when no usable target is found or it does not look like this project. Exit code 2. */
export class AttackTargetError extends Error {
  readonly exitCode = 2 as const;
  constructor(message: string) {
    super(message);
    this.name = "AttackTargetError";
  }
}

/** Probed in order when neither --target nor .vibesafe/attack.json names a target. */
export const DEFAULT_TARGETS: readonly string[] = [
  "http://127.0.0.1:3000",
  "http://[::1]:3000",
  "http://127.0.0.1:3001",
  "http://[::1]:3001",
];

export const TARGET_MISMATCH_MESSAGE = "target does not look like this project";
export const NO_TARGET_MESSAGE =
  "no dev server answered on 127.0.0.1 / [::1] ports 3000 and 3001; start your app or pass --target";

/** Max owner-control requests sent to verify a target that has no recognisable header. */
const MAX_OWNER_CHECKS = 3;

/**
 * Validates a loopback target and reduces it to its origin ("http://127.0.0.1:3000").
 * Throws AttackTargetError for anything that is not loopback http.
 */
export function normalizeTarget(raw: string, source = "target"): string {
  const check = checkLoopbackTarget(raw);
  if (!check.ok) throw new AttackTargetError(`${source} ${check.reason}`);
  const url = new URL(raw);
  return `${url.protocol}//${url.host}`;
}

/** The header-based reason a pre-warm response identifies the project, or undefined. */
export function recognisedBy(res: SafeResponse): string | undefined {
  if (res.headers["x-vibesafe-harness"] === "1") return "x-vibesafe-harness header";
  if (/next\.js/i.test(res.headers["x-powered-by"] ?? "")) return "x-powered-by: Next.js";
  return undefined;
}

export interface OwnerControl {
  path: string;
  session: string;
  headers: Record<string, string>;
}

export interface DetectTargetOptions {
  client: SafeHttpClient;
  /** --target. When set, it is the only candidate. */
  explicit?: string | undefined;
  /** .vibesafe/attack.json#target. Used when there is no --target. */
  configured?: string | undefined;
  /** Extra candidates tried before the defaults (e.g. the saved run's target on replay). */
  remembered?: string | undefined;
  /** Owner-control requests of planned groups (signed-in reads of the owner's own record). */
  ownerControls?: readonly OwnerControl[] | undefined;
  log?: ((line: string) => void) | undefined;
}

export interface DetectedTarget {
  targetUrl: string;
  /** Why the target was accepted. */
  via: string;
}

const isUnreachable = (r: SafeResponse): boolean => r.status === 0;

/**
 * Picks the first candidate that answers the pre-warm `GET /` (30 s timeout), then accepts it
 * only when it carries the harness header, an `x-powered-by: Next.js` header, or one owner-control
 * request returns something other than 404 (and is not a failure). Throws AttackTargetError.
 */
export async function detectTarget(opts: DetectTargetOptions): Promise<DetectedTarget> {
  const pinned =
    opts.explicit !== undefined
      ? normalizeTarget(opts.explicit, "--target")
      : opts.configured !== undefined
        ? normalizeTarget(opts.configured, ".vibesafe/attack.json target")
        : undefined;
  const candidates: string[] = [];
  if (pinned !== undefined) candidates.push(pinned);
  else {
    if (opts.remembered !== undefined && checkLoopbackTarget(opts.remembered).ok) {
      candidates.push(normalizeTarget(opts.remembered));
    }
    for (const c of DEFAULT_TARGETS) if (!candidates.includes(c)) candidates.push(c);
  }

  for (const base of candidates) {
    const prewarm = await opts.client.request({ url: `${base}/`, prewarm: true });
    if (isUnreachable(prewarm)) {
      if (prewarm.blocked !== undefined) {
        throw new AttackTargetError(`refused to contact ${base}: ${prewarm.blocked}`);
      }
      if (pinned !== undefined) {
        throw new AttackTargetError(`${base} did not answer (${prewarm.error ?? "no response"})`);
      }
      continue;
    }
    const header = recognisedBy(prewarm);
    if (header !== undefined) {
      opts.log?.(`Target ${base} (${header})`);
      return { targetUrl: base, via: header };
    }
    for (const owner of (opts.ownerControls ?? []).slice(0, MAX_OWNER_CHECKS)) {
      const r = await opts.client.request({
        url: `${base}${owner.path}`,
        headers: owner.headers,
        session: owner.session,
      });
      if (r.status !== 0 && r.status !== 404 && r.status < 500) {
        const via = `owner control ${owner.path} returned ${r.status}`;
        opts.log?.(`Target ${base} (${via})`);
        return { targetUrl: base, via };
      }
    }
    throw new AttackTargetError(`${base}: ${TARGET_MISMATCH_MESSAGE}`);
  }
  throw new AttackTargetError(NO_TARGET_MESSAGE);
}
