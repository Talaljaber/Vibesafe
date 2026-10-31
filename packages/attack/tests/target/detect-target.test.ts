import http from "node:http";
import net from "node:net";
import type { AddressInfo } from "node:net";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { SafeHttpClient } from "../../src/http/safe-client.js";
import {
  AttackTargetError,
  TARGET_MISMATCH_MESSAGE,
  detectTarget,
  normalizeTarget,
  recognisedBy,
} from "../../src/target/detect-target.js";

/** One loopback server whose behaviour each test picks through `mode`. */
let mode: "harness" | "next" | "plain" | "owner" = "plain";
const seen: { url: string; cookie: string | undefined }[] = [];
let server: http.Server;
let base = "";

beforeAll(async () => {
  server = http.createServer((req, res) => {
    seen.push({ url: req.url ?? "", cookie: req.headers.cookie });
    if (mode === "harness") res.setHeader("x-vibesafe-harness", "1");
    if (mode === "next") res.setHeader("x-powered-by", "Next.js");
    if (mode === "owner" && req.url === "/api/notes/n1" && req.headers.cookie === "s=a") {
      res.setHeader("content-type", "application/json");
      res.end('{"id":"n1"}');
      return;
    }
    res.statusCode = 404;
    res.end("not found");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

afterEach(() => {
  seen.length = 0;
  vi.restoreAllMocks();
});

const client = () => new SafeHttpClient({ rate: 1000 });
const owner = { path: "/api/notes/n1", session: "alice", headers: { Cookie: "s=a" } };

describe("normalizeTarget", () => {
  it("keeps the loopback origin only", () => {
    expect(normalizeTarget("http://127.0.0.1:3000/")).toBe("http://127.0.0.1:3000");
    expect(normalizeTarget("http://localhost:4000/app")).toBe("http://localhost:4000");
    expect(normalizeTarget("http://[::1]:3000")).toBe("http://[::1]:3000");
  });

  it("rejects anything that is not loopback http, with exit code 2", () => {
    for (const bad of [
      "http://10.0.0.1:3000",
      "https://127.0.0.1:3000",
      "http://127.1:3000",
      "http://user:pw@127.0.0.1/",
      "http://localhost.evil.com/",
    ]) {
      const err = (() => {
        try {
          normalizeTarget(bad);
          return undefined;
        } catch (e) {
          return e;
        }
      })();
      expect(err, bad).toBeInstanceOf(AttackTargetError);
      expect((err as AttackTargetError).exitCode).toBe(2);
    }
  });
});

describe("detectTarget", () => {
  it("accepts the harness header after a pre-warm GET /", async () => {
    mode = "harness";
    const t = await detectTarget({ client: client(), explicit: base });
    expect(t).toEqual({ targetUrl: base, via: "x-vibesafe-harness header" });
    expect(seen.map((s) => s.url)).toEqual(["/"]);
  });

  it("accepts x-powered-by: Next.js", async () => {
    mode = "next";
    const t = await detectTarget({ client: client(), configured: `${base}/` });
    expect(t.via).toBe("x-powered-by: Next.js");
  });

  it("accepts an unrecognised server when an owner control is not 404", async () => {
    mode = "owner";
    const t = await detectTarget({ client: client(), explicit: base, ownerControls: [owner] });
    expect(t.via).toMatch(/owner control \/api\/notes\/n1 returned 200/);
    expect(seen).toEqual([
      { url: "/", cookie: undefined },
      { url: "/api/notes/n1", cookie: "s=a" },
    ]);
  });

  it("refuses a server that does not look like this project (exit code 2)", async () => {
    mode = "plain";
    const err = await detectTarget({
      client: client(),
      explicit: base,
      ownerControls: [owner],
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AttackTargetError);
    expect((err as AttackTargetError).exitCode).toBe(2);
    expect((err as Error).message).toContain(TARGET_MISMATCH_MESSAGE);
  });

  it("refuses a non-loopback --target before opening any socket", async () => {
    const connect = vi.spyOn(net.Socket.prototype, "connect");
    const err = await detectTarget({ client: client(), explicit: "http://192.168.1.1:3000" }).catch(
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(AttackTargetError);
    expect(connect).not.toHaveBeenCalled();
  });

  it("an explicit target that does not answer is an error, not a fallback", async () => {
    const closed = net.createServer();
    await new Promise<void>((resolve) => closed.listen(0, "127.0.0.1", resolve));
    const port = (closed.address() as AddressInfo).port;
    await new Promise<void>((resolve) => closed.close(() => resolve()));
    const err = await detectTarget({
      client: client(),
      explicit: `http://127.0.0.1:${port}`,
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AttackTargetError);
    expect((err as Error).message).toMatch(/did not answer/);
  });

  it("recognisedBy ignores unrelated headers", () => {
    const res = {
      status: 200,
      contentType: "text/html",
      headers: { "x-powered-by": "Express", "x-vibesafe-harness": "0" },
      body: "",
      bodyTruncated: false,
      ms: 1,
    };
    expect(recognisedBy(res)).toBeUndefined();
  });
});
