import { describe, expect, it } from "vitest";
import { checkRequest, type GateReason } from "../src/http/gate.js";
import { RateLimiter } from "../src/http/rate-limiter.js";

const SB = { supabaseProject: "abcdefghij", envSupabaseRef: "abcdefghij" };
const OK_SB = "https://abcdefghij.supabase.co/rest/v1/notes?select=*&limit=1";

type Row = [
  name: string,
  req: Parameters<typeof checkRequest>[0],
  reason: GateReason,
  cfg?: object,
];
const get = (url: string): Row[1] => ({ method: "GET", url });

const DENY: Row[] = [
  ["POST", { method: "POST", url: "http://127.0.0.1/" }, "method"],
  ["PUT", { method: "PUT", url: "http://127.0.0.1/" }, "method"],
  ["PATCH", { method: "PATCH", url: "http://127.0.0.1/" }, "method"],
  ["DELETE", { method: "DELETE", url: "http://127.0.0.1/" }, "method"],
  ["OPTIONS", { method: "OPTIONS", url: "http://127.0.0.1/" }, "method"],
  ["HEAD", { method: "HEAD", url: "http://127.0.0.1/" }, "method"],
  ["lowercase get", { method: "get", url: "http://127.0.0.1/" }, "method"],
  ["GET with body", { method: "GET", url: "http://127.0.0.1/", body: "x" }, "body"],
  ["GET with empty-string body", { method: "GET", url: "http://127.0.0.1/", body: "" }, "body"],
  ["10.0.0.1", get("http://10.0.0.1/"), "not-loopback"],
  ["192.168.1.1", get("http://192.168.1.1/"), "not-loopback"],
  ["172.16.0.1", get("http://172.16.0.1/"), "not-loopback"],
  ["metadata", get("http://169.254.169.254/latest/meta-data"), "not-loopback"],
  ["0.0.0.0", get("http://0.0.0.0/"), "not-loopback"],
  ["127.1", get("http://127.1/"), "not-loopback"],
  ["decimal ip", get("http://2130706433/"), "not-loopback"],
  ["hex ip", get("http://0x7f000001/"), "not-loopback"],
  ["v4-mapped v6", get("http://[::ffff:127.0.0.1]/"), "not-loopback"],
  ["127.0.0.2", get("http://127.0.0.2/"), "not-loopback"],
  ["localhost.evil.com", get("http://localhost.evil.com/"), "not-loopback"],
  ["foo.localhost", get("http://foo.localhost/"), "not-loopback"],
  ["nip.io", get("http://127.0.0.1.nip.io/"), "not-loopback"],
  ["docker host", get("http://host.docker.internal/"), "not-loopback"],
  ["trailing dot", get("http://localhost./"), "not-loopback"],
  ["userinfo double at", get("http://a@evil.com@localhost/"), "userinfo"],
  ["userinfo ip", get("http://127.0.0.1@evil.com/"), "userinfo"],
  ["userinfo pw", get("http://user:pw@127.0.0.1/"), "userinfo"],
  ["https loopback", get("https://127.0.0.1/"), "https-only-supabase"],
  ["supabase without flag", get(OK_SB), "remote-off", {}],
  [
    "supabase auth path",
    get("https://abcdefghij.supabase.co/auth/v1/token?select=*&limit=1"),
    "path",
    SB,
  ],
  [
    "supabase rpc",
    get("https://abcdefghij.supabase.co/rest/v1/rpc/fn?select=*&limit=1"),
    "path",
    SB,
  ],
  [
    "supabase dotdot",
    get("https://abcdefghij.supabase.co/rest/v1/x/../auth?select=*&limit=1"),
    "path",
    SB,
  ],
  [
    "supabase storage",
    get("https://abcdefghij.supabase.co/storage/v1/object/x?select=*&limit=1"),
    "path",
    SB,
  ],
  [
    "supabase limit 50",
    get("https://abcdefghij.supabase.co/rest/v1/notes?select=*&limit=50"),
    "query",
    SB,
  ],
  [
    "supabase select email",
    get("https://abcdefghij.supabase.co/rest/v1/notes?select=email&limit=1"),
    "query",
    SB,
  ],
  ["supabase extra key", get(`${OK_SB}&order=id`), "query", SB],
  ["supabase no query", get("https://abcdefghij.supabase.co/rest/v1/notes"), "query", SB],
  [
    "supabase ref mismatch (flag)",
    get(OK_SB),
    "ref-mismatch",
    { supabaseProject: "abc", envSupabaseRef: "abcdefghij" },
  ],
  [
    "supabase ref mismatch (env)",
    get(OK_SB),
    "ref-mismatch",
    { supabaseProject: "abcdefghij", envSupabaseRef: "xyz" },
  ],
  ["supabase no env ref", get(OK_SB), "ref-mismatch", { supabaseProject: "abcdefghij" }],
  [
    "other supabase host",
    get("https://other.supabase.co/rest/v1/notes?select=*&limit=1"),
    "ref-mismatch",
    SB,
  ],
  ["ftp", get("ftp://127.0.0.1/"), "protocol"],
  ["file", get("file:///etc/passwd"), "protocol"],
  ["ws", get("ws://127.0.0.1/"), "protocol"],
  ["data", get("data:text/plain,hi"), "protocol"],
  ["backslash", get("http://127.0.0.1\\@evil.com/"), "malformed"],
  ["encoded nul", get("http://127.0.0.1/a%00b"), "malformed"],
  ["tab", get("http://127.0.0.1/a\tb"), "malformed"],
  ["space", get("http://127.0.0.1/a b"), "malformed"],
  ["newline", get("http://127.0.0.1/a\nb"), "malformed"],
  ["unicode host", get("http://lоcalhost/"), "malformed"],
  ["punycode host", get("http://xn--lcalhost-9ve/"), "not-loopback"],
  ["too long", get(`http://127.0.0.1/${"a".repeat(2100)}`), "malformed"],
  ["empty", get(""), "malformed"],
  ["not a url", get("localhost:3000/x"), "protocol"],
  [
    "forbidden header",
    { method: "GET", url: "http://127.0.0.1/", headers: { "X-Forwarded-For": "1" } },
    "headers",
  ],
  [
    "header injection",
    { method: "GET", url: "http://127.0.0.1/", headers: { Cookie: "a=b\r\nHost: evil" } },
    "headers",
  ],
  [
    "spoofed user-agent",
    { method: "GET", url: "http://127.0.0.1/", headers: { "User-Agent": "curl/8" } },
    "headers",
  ],
];

describe("gate deny table", () => {
  it("has at least 25 rows", () => {
    expect(DENY.length).toBeGreaterThanOrEqual(25);
  });

  it.each(DENY)("denies %s", (_name, req, reason, cfg) => {
    const d = checkRequest(req, cfg ?? {});
    expect(d.allowed).toBe(false);
    if (!d.allowed) expect(d.reason).toBe(reason);
  });
});

describe("gate allow table", () => {
  it.each([
    "http://127.0.0.1/",
    "http://127.0.0.1:3000/api/notes/1?x=1",
    "http://localhost:3000/",
    "http://LOCALHOST/",
    "http://[::1]:8080/a",
  ])("allows %s", (url) => {
    const d = checkRequest({
      method: "GET",
      url,
      headers: { Cookie: "s=1", "User-Agent": "vibesafe-attack/0.5.0", "X-VibeSafe-Attack": "1" },
    });
    expect(d.allowed).toBe(true);
  });

  it("allows the pinned Supabase read, in either parameter order", () => {
    expect(checkRequest(get(OK_SB), SB).allowed).toBe(true);
    expect(
      checkRequest(get("https://abcdefghij.supabase.co/rest/v1/notes?limit=1&select=*"), SB)
        .allowed,
    ).toBe(true);
  });
});

describe("rate limiter", () => {
  it("allows a burst up to the rate, then paces at the rate", async () => {
    let t = 0;
    const slept: number[] = [];
    const limiter = new RateLimiter(5, {
      now: () => t,
      sleep: (ms) => {
        slept.push(ms);
        t += ms;
        return Promise.resolve();
      },
    });
    for (let i = 0; i < 5; i += 1) await limiter.acquire();
    expect(slept).toEqual([]);
    for (let i = 0; i < 5; i += 1) await limiter.acquire();
    // 5 more tokens at 5 rps take about one second of simulated time
    expect(t).toBeGreaterThanOrEqual(990);
    expect(t).toBeLessThan(1300);
  });

  it("rejects non-positive rates", () => {
    expect(() => new RateLimiter(0)).toThrow();
    expect(() => new RateLimiter(Number.NaN)).toThrow();
  });
});
