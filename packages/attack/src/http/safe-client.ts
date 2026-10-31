/**
 * The only place in the package that performs network I/O (spec 3.2, 3.4).
 * GET only, never HEAD, no bodies, manual redirects, 5 rps by default, 300-request ceiling.
 */
import http from "node:http";
import https from "node:https";
import { VIBESAFE_VERSION } from "@talaljaber/vibesafe-shared";
import type { RequestLogEntry } from "../types.js";
import { checkRequest, type GateConfig, type GateDecision, type GateReason } from "./gate.js";
import { DEFAULT_RATE, RateLimiter } from "./rate-limiter.js";

export const REQUEST_CEILING = 300;
export const MAX_BODY_BYTES = 256 * 1024;
export const REQUEST_TIMEOUT_MS = 10_000;
export const PREWARM_TIMEOUT_MS = 30_000;
export const MAX_SAME_HOST_REDIRECTS = 3;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const KEPT_HEADERS = ["content-type", "location", "x-powered-by", "x-vibesafe-harness"];

export interface SafeRequest {
  url: string;
  /** Only "GET" is ever allowed; any other value is refused by the gate. Defaults to GET. */
  method?: string | undefined;
  /** Never allowed; present so a caller mistake is refused rather than silently dropped. */
  body?: unknown;
  headers?: Record<string, string> | undefined;
  /** Session label, recorded in the request log. */
  session?: string | undefined;
  /** Pre-warm requests get a 30 s timeout instead of 10 s. */
  prewarm?: boolean | undefined;
}

export interface SafeResponse {
  /** 0 = blocked, dry-run or connection error. */
  status: number;
  contentType: string;
  /** content-type, location, x-powered-by, x-vibesafe-harness; set-cookie reduced to names. */
  headers: Record<string, string>;
  body: string;
  bodyTruncated: boolean;
  location?: string | undefined;
  redirectBlocked?: boolean | undefined;
  /** Gate reason (or "ceiling"/"loop"/"cross-host") when the request or a redirect was refused. */
  blocked?: GateReason | undefined;
  dryRun?: boolean | undefined;
  error?: string | undefined;
  ms: number;
}

export interface SafeClientOptions extends GateConfig {
  /** Requests per second (default 5). */
  rate?: number | undefined;
  /** Lower the per-run ceiling (it can never exceed 300). */
  maxRequests?: number | undefined;
  /** Test seam: per-request total deadline in ms (default 10 s, 30 s for pre-warm). */
  timeoutMs?: number | undefined;
  /** Gate and log only; sends nothing. */
  dryRun?: boolean | undefined;
  /** Test seams for the limiter. */
  now?: (() => number) | undefined;
  sleep?: ((ms: number) => Promise<void>) | undefined;
}

interface Hop {
  status: number;
  contentType: string;
  headers: Record<string, string>;
  body: string;
  bodyTruncated: boolean;
  location?: string | undefined;
  error?: string | undefined;
}

type LookupCb = (
  err: Error | null,
  address: string | { address: string; family: number }[],
  family?: number,
) => void;

function pinnedLookup(address: "127.0.0.1" | "::1") {
  const family = address === "::1" ? 6 : 4;
  return (_host: string, options: { all?: boolean } | undefined, cb: LookupCb): void => {
    if (options && options.all) cb(null, [{ address, family }]);
    else cb(null, address, family);
  };
}

function cookieNames(raw: string | string[] | undefined): string {
  const list = Array.isArray(raw) ? raw : raw === undefined ? [] : [raw];
  return list
    .map((c) => (c.split("=")[0] ?? "").trim())
    .filter((n) => /^[\w.-]{1,64}$/.test(n))
    .join(", ");
}

function errorHop(error: string): Hop {
  return { status: 0, contentType: "", headers: {}, body: "", bodyTruncated: false, error };
}

function sendOnce(
  url: URL,
  kind: "loopback" | "supabase",
  headers: Record<string, string>,
  timeoutMs: number,
  loopbackAddress: "127.0.0.1" | "::1",
): Promise<Hop> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (hop: Hop): void => {
      if (!settled) {
        settled = true;
        resolve(hop);
      }
    };
    const isLocalhostName = url.hostname === "localhost";
    const bare = url.hostname.replace(/^\[|\]$/g, "");
    const options: http.RequestOptions = {
      method: "GET",
      host: bare,
      port: url.port === "" ? undefined : Number(url.port),
      path: `${url.pathname}${url.search}`,
      headers,
      agent: false,
    };
    if (kind === "loopback" && isLocalhostName) {
      options.lookup = pinnedLookup(loopbackAddress) as http.RequestOptions["lookup"];
    }
    const lib = kind === "supabase" ? https : http;
    let req: http.ClientRequest;
    try {
      req = lib.request(options, onResponse);
    } catch (err) {
      done(errorHop((err as NodeJS.ErrnoException).code ?? (err as Error).message));
      return;
    }
    function onResponse(res: http.IncomingMessage): void {
      const chunks: Buffer[] = [];
      let size = 0;
      let truncated = false;
      const finish = (): void => {
        const out: Record<string, string> = {};
        for (const name of KEPT_HEADERS) {
          const v = res.headers[name];
          if (typeof v === "string") out[name] = v;
        }
        const cookies = cookieNames(res.headers["set-cookie"]);
        if (cookies !== "") out["set-cookie"] = cookies;
        const location = res.headers.location;
        done({
          status: res.statusCode ?? 0,
          contentType:
            typeof res.headers["content-type"] === "string" ? res.headers["content-type"] : "",
          headers: out,
          body: Buffer.concat(chunks).toString("utf8"),
          bodyTruncated: truncated,
          location: typeof location === "string" ? location : undefined,
          ...(!res.complete && !truncated ? { error: "incomplete" } : {}),
        });
      };
      res.on("data", (chunk: Buffer) => {
        if (truncated) return;
        const room = MAX_BODY_BYTES - size;
        if (chunk.length > room) {
          chunks.push(chunk.subarray(0, room));
          size = MAX_BODY_BYTES;
          truncated = true;
          res.destroy();
          finish();
          return;
        }
        chunks.push(chunk);
        size += chunk.length;
      });
      res.on("end", finish);
      res.on("error", () => finish());
      res.on("close", finish);
    }
    // Idle timeout plus a whole-request deadline so a dripping server cannot hold the slot.
    const deadline = setTimeout(() => req.destroy(new Error("timeout")), timeoutMs);
    req.on("close", () => clearTimeout(deadline));
    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error("timeout"));
    });
    req.on("error", (err: NodeJS.ErrnoException) => {
      if (
        kind === "loopback" &&
        isLocalhostName &&
        loopbackAddress === "127.0.0.1" &&
        err.code === "ECONNREFUSED"
      ) {
        void sendOnce(url, kind, headers, timeoutMs, "::1").then(done);
        return;
      }
      done(errorHop(err.message === "timeout" ? "timeout" : (err.code ?? err.message)));
    });
    req.end();
  });
}

export class SafeHttpClient {
  private readonly gateConfig: GateConfig;
  private readonly limiter: RateLimiter;
  private readonly ceiling: number;
  private readonly dryRun: boolean;
  private readonly timeoutOverride: number | undefined;
  private readonly entries: RequestLogEntry[] = [];
  private sentCount = 0;

  constructor(options: SafeClientOptions = {}) {
    this.gateConfig = {
      supabaseProject: options.supabaseProject,
      envSupabaseRef: options.envSupabaseRef,
    };
    this.limiter = new RateLimiter(options.rate ?? DEFAULT_RATE, {
      ...(options.now ? { now: options.now } : {}),
      ...(options.sleep ? { sleep: options.sleep } : {}),
    });
    const max = options.maxRequests;
    this.ceiling =
      max === undefined || !Number.isFinite(max)
        ? REQUEST_CEILING
        : Math.min(REQUEST_CEILING, Math.max(0, Math.floor(max)));
    this.timeoutOverride = options.timeoutMs;
    this.dryRun = options.dryRun === true;
  }

  /** Every request, including blocked and planned ones, in order. */
  get log(): readonly RequestLogEntry[] {
    return this.entries;
  }

  /** Requests that actually reached the transport (redirect hops included). */
  get sent(): number {
    return this.sentCount;
  }

  private record(
    method: string,
    url: string,
    status: number,
    ms: number,
    session: string | undefined,
    blocked?: string,
  ): void {
    const entry: RequestLogEntry = { method, url, status, ms };
    if (session !== undefined) entry.session = session;
    if (blocked !== undefined) entry.blocked = blocked;
    this.entries.push(entry);
  }

  private blocked(
    req: SafeRequest,
    url: string,
    reason: GateReason | "dry-run",
    extra: Partial<SafeResponse> = {},
  ): SafeResponse {
    this.record(req.method ?? "GET", url, 0, 0, req.session, reason);
    return {
      status: 0,
      contentType: "",
      headers: {},
      body: "",
      bodyTruncated: false,
      ms: 0,
      ...(reason === "dry-run"
        ? { dryRun: true }
        : { blocked: reason, error: `blocked: ${reason}` }),
      ...extra,
    };
  }

  async request(req: SafeRequest): Promise<SafeResponse> {
    const method = req.method ?? "GET";
    const headers: Record<string, string> = {
      Accept: "application/json, text/html;q=0.9, */*;q=0.8",
      "User-Agent": `vibesafe-attack/${VIBESAFE_VERSION}`,
      "X-VibeSafe-Attack": "1",
      ...req.headers,
    };
    const timeoutMs =
      this.timeoutOverride ?? (req.prewarm === true ? PREWARM_TIMEOUT_MS : REQUEST_TIMEOUT_MS);
    let current = req.url;
    let hops = 0;

    for (;;) {
      const decision: GateDecision = checkRequest(
        { method, url: current, body: req.body, headers },
        this.gateConfig,
      );
      if (!decision.allowed) return this.blocked(req, current, decision.reason);
      if (this.dryRun) return this.blocked(req, current, "dry-run");
      // Reserve the slot synchronously, before any await, so concurrent callers cannot overshoot.
      if (this.sentCount >= this.ceiling) return this.blocked(req, current, "ceiling");
      this.sentCount += 1;
      await this.limiter.acquire();

      const started = Date.now();
      const hop = await sendOnce(decision.url, decision.kind, headers, timeoutMs, "127.0.0.1");
      const ms = Date.now() - started;
      this.record(method, decision.url.href, hop.status, ms, req.session);

      const response: SafeResponse = {
        status: hop.status,
        contentType: hop.contentType,
        headers: hop.headers,
        body: hop.body,
        bodyTruncated: hop.bodyTruncated,
        ms,
        ...(hop.location !== undefined ? { location: hop.location } : {}),
        ...(hop.error !== undefined ? { error: hop.error } : {}),
      };
      if (!REDIRECT_STATUSES.has(hop.status) || hop.location === undefined) return response;

      // Redirect handling: same origin only, at most 3 hops, every hop goes through the gate.
      const blockRedirect = (reason: GateReason): SafeResponse => {
        // Persisted logs never carry a server-controlled query (OAuth or magic-link tokens).
        let shown = "(redirect)";
        try {
          const u = new URL(hop.location ?? "", decision.url);
          shown = `${u.origin}${u.pathname}`;
        } catch {
          // keep the placeholder
        }
        this.record(method, shown, 0, 0, req.session, reason);
        return { ...response, redirectBlocked: true, blocked: reason };
      };
      const loc = hop.location;
      const absolute = /^[A-Za-z][A-Za-z0-9+.-]*:/.test(loc) || loc.startsWith("//");
      // A fragment is never sent, so drop it before gating, as the relative path does below.
      const hashAt = loc.indexOf("#");
      const locNoHash = hashAt >= 0 ? loc.slice(0, hashAt) : loc;
      const rawTarget = locNoHash.startsWith("//")
        ? `${decision.url.protocol}${locNoHash}`
        : locNoHash;
      let next: URL;
      try {
        next = new URL(loc, decision.url);
      } catch {
        return blockRedirect("malformed");
      }
      if (absolute) {
        const g = checkRequest({ method, url: rawTarget, headers }, this.gateConfig);
        if (!g.allowed) return blockRedirect(g.reason);
      }
      if (next.origin !== decision.url.origin) return blockRedirect("cross-host");
      if (hops >= MAX_SAME_HOST_REDIRECTS) return blockRedirect("loop");
      next.hash = "";
      const g2 = checkRequest({ method, url: next.href, headers }, this.gateConfig);
      if (!g2.allowed) return blockRedirect(g2.reason);
      if (this.sentCount >= this.ceiling) return blockRedirect("ceiling");
      hops += 1;
      current = next.href;
    }
  }
}
