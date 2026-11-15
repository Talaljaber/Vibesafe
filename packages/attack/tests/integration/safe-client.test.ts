import http from "node:http";
import net from "node:net";
import type { AddressInfo } from "node:net";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { SafeHttpClient, REQUEST_CEILING } from "../../src/http/safe-client.js";

/** Zero-dependency loopback harness. Records every request it sees. */
let server: http.Server;
let port = 0;
const seen: { method: string; url: string; headers: http.IncomingHttpHeaders }[] = [];

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const url = req.url ?? "/";
    seen.push({ method: req.method ?? "", url, headers: req.headers });
    res.setHeader("x-vibesafe-harness", "1");
    if (url === "/ok") {
      res.setHeader("set-cookie", ["sid=secretvalue; Path=/", "theme=dark"]);
      res.setHeader("content-type", "application/json");
      res.end('{"ok":true}');
    } else if (url === "/big") {
      res.end("x".repeat(400 * 1024));
    } else if (url === "/to-ok") {
      res.writeHead(302, { location: "/ok" }).end();
    } else if (url === "/to-external") {
      res.writeHead(302, { location: "http://example.com/" }).end();
    } else if (url === "/to-localhost-name") {
      res.writeHead(302, { location: `http://localhost:${port}/ok` }).end();
    } else if (url === "/to-short-ip") {
      res.writeHead(302, { location: `http://127.1:${port}/ok` }).end();
    } else if (url.startsWith("/hop/")) {
      const n = Number(url.slice(5));
      res.writeHead(302, { location: `/hop/${n + 1}` }).end();
    } else if (url === "/to-absolute-fragment") {
      res.writeHead(302, { location: `http://127.0.0.1:${port}/login#next` }).end();
    } else if (url === "/to-token-external") {
      res.writeHead(302, { location: "http://example.com/cb?token=SECRETTOKEN#frag" }).end();
    } else if (url === "/to-query") {
      res.writeHead(302, { location: "/login?token=SECRETQ" }).end();
    } else if (url === "/to-login") {
      res.writeHead(302, { location: "/login#next" }).end();
    } else if (url.split("?")[0] === "/login") {
      res.end("login");
    } else if (url === "/slow") {
      // never answers
    } else {
      res.statusCode = 404;
      res.end("nope");
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  port = (server.address() as AddressInfo).port;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

afterEach(() => {
  seen.length = 0;
  vi.restoreAllMocks();
});

const base = () => `http://127.0.0.1:${port}`;
const fast = { rate: 1000 };

describe("SafeHttpClient", () => {
  it("sends a plain GET with the fixed headers and keeps only cookie names", async () => {
    const client = new SafeHttpClient({ ...fast });
    const res = await client.request({
      url: `${base()}/ok`,
      headers: { Cookie: "a=1" },
      session: "alice",
    });
    expect(res.status).toBe(200);
    expect(res.body).toBe('{"ok":true}');
    expect(res.headers["set-cookie"]).toBe("sid, theme");
    expect(JSON.stringify(res)).not.toContain("secretvalue");
    expect(res.headers["x-vibesafe-harness"]).toBe("1");
    expect(seen).toHaveLength(1);
    expect(seen[0]?.method).toBe("GET");
    expect(seen[0]?.headers["x-vibesafe-attack"]).toBe("1");
    expect(seen[0]?.headers["user-agent"]).toMatch(/^vibesafe-attack\//);
    expect(client.log).toEqual([
      expect.objectContaining({ method: "GET", status: 200, session: "alice" }),
    ]);
  });

  it("refuses non-GET methods and bodies before any socket opens", async () => {
    const connect = vi.spyOn(net.Socket.prototype, "connect");
    const client = new SafeHttpClient({ ...fast });
    for (const method of ["POST", "HEAD", "DELETE"]) {
      const r = await client.request({ url: `${base()}/ok`, method });
      expect(r.status).toBe(0);
      expect(r.blocked).toBe("method");
    }
    const withBody = await client.request({ url: `${base()}/ok`, body: "x" });
    expect(withBody.blocked).toBe("body");
    expect(connect).not.toHaveBeenCalled();
    expect(seen).toHaveLength(0);
    expect(client.sent).toBe(0);
    expect(client.log.every((e) => e.blocked !== undefined)).toBe(true);
  });

  it("truncates bodies at 256 KiB", async () => {
    const res = await new SafeHttpClient({ ...fast }).request({ url: `${base()}/big` });
    expect(res.bodyTruncated).toBe(true);
    expect(res.body.length).toBe(256 * 1024);
  });

  it("logs a blocked redirect without its query string or fragment", async () => {
    const client = new SafeHttpClient({ ...fast });
    const res = await client.request({ url: `${base()}/to-token-external` });
    expect(res.redirectBlocked).toBe(true);
    const logged = JSON.stringify(client.log);
    expect(logged).not.toContain("SECRETTOKEN");
    expect(logged).toContain("http://example.com/cb");
  });

  it("never logs the query of a followed same-origin redirect hop", async () => {
    const client = new SafeHttpClient({ ...fast });
    const res = await client.request({ url: `${base()}/to-query` });
    expect(res.status).toBe(200);
    const logged = JSON.stringify(client.log);
    expect(logged).not.toContain("SECRETQ");
    expect(logged).toContain("/login");
  });

  it("follows a same-host redirect through the gate", async () => {
    const client = new SafeHttpClient({ ...fast });
    const res = await client.request({ url: `${base()}/to-ok` });
    expect(res.status).toBe(200);
    expect(res.redirectBlocked).toBeUndefined();
    expect(client.log.map((e) => e.status)).toEqual([302, 200]);
  });

  it("returns a redirect to a non-allowed URL with redirectBlocked and connects only to loopback", async () => {
    const connect = vi.spyOn(net.Socket.prototype, "connect");
    const client = new SafeHttpClient({ ...fast });
    const res = await client.request({ url: `${base()}/to-external` });
    expect(res.status).toBe(302);
    expect(res.redirectBlocked).toBe(true);
    expect(res.blocked).toBe("not-loopback");
    expect(res.location).toBe("http://example.com/");
    expect(client.sent).toBe(1);
    const targets = connect.mock.calls.map((c) => JSON.stringify(c[0]));
    expect(targets.length).toBeGreaterThan(0);
    for (const t of targets) expect(t).toMatch(/127\.0\.0\.1|::1/);
  });

  it("never follows a cross-host redirect, even between loopback names or normalised IPs", async () => {
    const client = new SafeHttpClient({ ...fast });
    const a = await client.request({ url: `${base()}/to-localhost-name` });
    expect(a.redirectBlocked).toBe(true);
    expect(a.blocked).toBe("cross-host");
    const b = await client.request({ url: `${base()}/to-short-ip` });
    expect(b.redirectBlocked).toBe(true);
    expect(b.blocked).toBe("not-loopback");
    expect(seen.map((s) => s.url)).toEqual(["/to-localhost-name", "/to-short-ip"]);
  });

  it("stops a redirect chain at the 4th same-host redirect", async () => {
    const client = new SafeHttpClient({ ...fast });
    const res = await client.request({ url: `${base()}/hop/0` });
    expect(res.redirectBlocked).toBe(true);
    expect(res.blocked).toBe("loop");
    expect(seen.map((s) => s.url)).toEqual(["/hop/0", "/hop/1", "/hop/2", "/hop/3"]);
  });

  it("blocks the 301st request and sends nothing more", async () => {
    const client = new SafeHttpClient({ rate: 100_000 });
    for (let i = 0; i < REQUEST_CEILING; i += 1) {
      const r = await client.request({ url: `${base()}/ok` });
      expect(r.status).toBe(200);
    }
    const over = await client.request({ url: `${base()}/ok` });
    expect(over.status).toBe(0);
    expect(over.blocked).toBe("ceiling");
    expect(seen).toHaveLength(REQUEST_CEILING);
    expect(client.sent).toBe(REQUEST_CEILING);
  }, 60_000);

  it("holds the ceiling under concurrency", async () => {
    const client = new SafeHttpClient({ rate: 100_000, maxRequests: 10 });
    const results = await Promise.all(
      Array.from({ length: 25 }, () => client.request({ url: `${base()}/ok` })),
    );
    expect(seen).toHaveLength(10);
    expect(client.sent).toBe(10);
    expect(results.filter((r) => r.blocked === "ceiling")).toHaveLength(15);
  });

  it("fails closed on a NaN maxRequests", () => {
    const client = new SafeHttpClient({ maxRequests: Number.NaN });
    expect(client.sent).toBe(0);
    // ceiling falls back to 300, not unlimited
    expect((client as unknown as { ceiling: number }).ceiling).toBe(REQUEST_CEILING);
  });

  it("keeps the 3xx when a relative redirect with a fragment is followed", async () => {
    const r = await new SafeHttpClient({ ...fast }).request({ url: `${base()}/to-login` });
    expect(r.status).toBe(200);
    expect(r.body).toBe("login");
    expect(seen.map((s) => s.url)).toEqual(["/to-login", "/login"]);
  });

  it("follows an absolute same-origin redirect with a fragment, sending no fragment", async () => {
    const client = new SafeHttpClient({ ...fast });
    const r = await client.request({ url: `${base()}/to-absolute-fragment` });
    expect(r.redirectBlocked).toBeUndefined();
    expect(r.status).toBe(200);
    expect(r.body).toBe("login");
    expect(seen.map((s) => s.url)).toEqual(["/to-absolute-fragment", "/login"]);
    expect(client.log.every((e) => !e.url.includes("#"))).toBe(true);
  });

  it("keeps the 3xx when the ceiling stops a redirect hop", async () => {
    const client = new SafeHttpClient({ ...fast, maxRequests: 1 });
    const r = await client.request({ url: `${base()}/to-ok` });
    expect(r.status).toBe(302);
    expect(r.redirectBlocked).toBe(true);
    expect(r.blocked).toBe("ceiling");
  });

  it("returns an error result for a header value node refuses", async () => {
    const r = await new SafeHttpClient({ ...fast }).request({
      url: `${base()}/ok`,
      headers: { Cookie: "a=“b" },
    });
    expect(r.status).toBe(0);
    expect(r.blocked).toBe("headers");
    expect(seen).toHaveLength(0);
  });

  it("--dry-run opens zero connections and records the plan", async () => {
    const connect = vi.spyOn(net.Socket.prototype, "connect");
    const client = new SafeHttpClient({ dryRun: true });
    const res = await client.request({ url: `${base()}/ok` });
    expect(res.dryRun).toBe(true);
    expect(res.status).toBe(0);
    expect(connect).not.toHaveBeenCalled();
    expect(seen).toHaveLength(0);
    expect(client.sent).toBe(0);
    expect(client.log).toEqual([expect.objectContaining({ blocked: "dry-run" })]);
  });

  it("dry-run still refuses requests the gate would refuse", async () => {
    const client = new SafeHttpClient({ dryRun: true });
    const res = await client.request({ url: "http://10.0.0.1/" });
    expect(res.blocked).toBe("not-loopback");
  });

  it("paces requests at the configured rate", async () => {
    const waits: number[] = [];
    let t = 0;
    const client = new SafeHttpClient({
      rate: 5,
      now: () => t,
      sleep: (ms) => {
        waits.push(ms);
        t += ms;
        return Promise.resolve();
      },
    });
    for (let i = 0; i < 7; i += 1) await client.request({ url: `${base()}/ok` });
    expect(waits.length).toBeGreaterThan(0);
    expect(t).toBeGreaterThanOrEqual(380);
  });

  it("resolves localhost without DNS", async () => {
    const dns = await import("node:dns");
    const lookup = vi.spyOn(dns.default, "lookup");
    const client = new SafeHttpClient({ ...fast });
    const res = await client.request({ url: `http://localhost:${port}/ok` });
    expect(res.status).toBe(200);
    expect(lookup).not.toHaveBeenCalled();
  });

  it("reports connection errors as status 0", async () => {
    const closed = http.createServer();
    await new Promise<void>((r) => closed.listen(0, "127.0.0.1", r));
    const p = (closed.address() as AddressInfo).port;
    await new Promise<void>((r) => closed.close(() => r()));
    const res = await new SafeHttpClient({ ...fast }).request({ url: `http://127.0.0.1:${p}/` });
    expect(res.status).toBe(0);
    expect(res.error).toBeDefined();
  });

  it("times out a hung request", async () => {
    const client = new SafeHttpClient({ ...fast, timeoutMs: 200 });
    const started = Date.now();
    const res = await client.request({ url: `${base()}/slow` });
    expect(res.status).toBe(0);
    expect(res.error).toBe("timeout");
    expect(Date.now() - started).toBeLessThan(3000);
    server.closeAllConnections();
  });
});
