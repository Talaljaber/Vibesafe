import { describe, it, expect } from "vitest";
import { CorsDetector } from "../../src/detectors/cors-detector";
import type { ScanContext } from "@vibesafe/shared";

const detector = new CorsDetector();

const ctx = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake/path",
  projectContext: {} as never,
  files: Object.keys(files),
  config: {} as never,
  readFile: async (f) => files[f] ?? "",
});

const run = (files: Record<string, string>) => detector.detect(ctx(files));

describe("CorsDetector", () => {
  it("flags origin '*' with credentials as medium (browsers block it)", async () => {
    const f = await run({
      "server.ts": `import cors from "cors";\napp.use(cors({ origin: "*", credentials: true }));`,
    });
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("medium");
    expect(f[0]?.ruleId).toBe("security_config/cors-wildcard-credentials");
    expect(f[0]?.category).toBe("security_config");
    expect(f[0]?.line).toBe(2);
  });

  it("flags origin: true with credentials, multi-line options", async () => {
    const f = await run({
      "server.js": `const cors = require("cors");\napp.use(cors({\n  origin: true,\n  credentials: true,\n}));`,
    });
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("high");
  });

  it("resolves an options object declared in the same file", async () => {
    const f = await run({
      "server.ts": `import cors from "cors";\nconst opts = { origin: "*", credentials: true };\napp.use(cors(opts));`,
    });
    expect(f).toHaveLength(1);
    expect(f[0]?.line).toBe(3);
  });

  it("flags bare cors() as medium when the app uses cookies", async () => {
    const f = await run({
      "server.ts": `import cors from "cors";\napp.use(cors());`,
      "session.ts": `import session from "express-session";`,
    });
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("medium");
    expect(f[0]?.ruleId).toBe("security_config/cors-default-with-cookies");
  });

  it("does not flag bare cors() without cookie usage", async () => {
    expect(await run({ "server.ts": `import cors from "cors";\napp.use(cors());` })).toHaveLength(
      0,
    );
  });

  it("does not flag allowlist array, regex, string or checking function", async () => {
    const f = await run({
      "a.ts": `import cors from "cors";\napp.use(cors({ origin: ["https://a.com"], credentials: true }));`,
      "b.ts": `import cors from "cors";\napp.use(cors({ origin: /\\.example\\.com$/, credentials: true }));`,
      "c.ts": `import cors from "cors";\napp.use(cors({ origin: "https://a.com", credentials: true }));`,
      "d.ts": `import cors from "cors";\napp.use(cors({ origin: (o, cb) => { if (ALLOWED.includes(o)) cb(null, true); else cb(new Error("no")); }, credentials: true }));`,
    });
    expect(f).toHaveLength(0);
  });

  it("flags an origin function that accepts everything", async () => {
    const f = await run({
      "server.ts": `import cors from "cors";\napp.use(cors({ origin: (origin, cb) => cb(null, true), credentials: true }));`,
    });
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("high");
  });

  it("ignores cors() calls when the cors package is not imported", async () => {
    expect(await run({ "x.ts": `cors({ origin: "*", credentials: true });` })).toHaveLength(0);
  });

  it("flags wildcard header in a Next.js route handler as medium", async () => {
    const f = await run({
      "app/api/data/route.ts": `export async function GET() {\n  return new Response("ok", { headers: { "Access-Control-Allow-Origin": "*" } });\n}`,
    });
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("medium");
    expect(f[0]?.ruleId).toBe("security_config/cors-wildcard-header");
  });

  it("flags wildcard header with Allow-Credentials true as medium", async () => {
    const f = await run({
      "middleware.ts": `res.headers.set("Access-Control-Allow-Origin", "*");\nres.headers.set("Access-Control-Allow-Credentials", "true");`,
    });
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("medium");
  });

  it("flags wildcard in next.config headers()", async () => {
    const f = await run({
      "next.config.js": `module.exports = { async headers() { return [{ source: "/api/:path*", headers: [{ key: "Access-Control-Allow-Origin", value: "*" }] }]; } };`,
    });
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("medium");
  });

  it("does not flag a specific origin header or a wildcard outside Next surfaces", async () => {
    const f = await run({
      "app/api/x/route.ts": `headers.set("Access-Control-Allow-Origin", "https://app.example.com");`,
      "lib/util.ts": `res.setHeader("Access-Control-Allow-Origin", "*");`,
    });
    expect(f).toHaveLength(0);
  });

  it("flags reflecting the Origin header without an allowlist", async () => {
    const f = await run({
      "app/api/x/route.ts": `export async function GET(req: Request) {\n  return new Response("ok", { headers: { "Access-Control-Allow-Origin": req.headers.get("origin")! } });\n}`,
      "server.js": `app.use((req, res, next) => {\n  res.setHeader("Access-Control-Allow-Origin", req.headers.origin);\n  next();\n});`,
    });
    expect(f).toHaveLength(2);
    expect(
      f.every((x) => x.ruleId === "security_config/cors-reflected-origin" && x.severity === "high"),
    ).toBe(true);
  });

  it("does not flag reflection guarded by an allowlist", async () => {
    const f = await run({
      "server.js": `const allowed = ["https://a.com"];\napp.use((req, res, next) => {\n  const origin = req.headers.origin;\n  if (allowed.includes(origin)) res.setHeader("Access-Control-Allow-Origin", origin);\n  next();\n});`,
    });
    expect(f).toHaveLength(0);
  });

  it("skips test files and comments", async () => {
    const f = await run({
      "server.test.ts": `import cors from "cors";\napp.use(cors({ origin: "*", credentials: true }));`,
      "server.ts": `import cors from "cors";\n// app.use(cors({ origin: "*", credentials: true }));`,
    });
    expect(f).toHaveLength(0);
  });

  it("flags wildcard header in Express when credentials are allowed in the file", async () => {
    const f = await run({
      "server.js": `res.header("Access-Control-Allow-Origin", "*");\nres.header("Access-Control-Allow-Credentials", "true");`,
    });
    expect(f).toHaveLength(1);
    expect(f[0]?.ruleId).toBe("security_config/cors-wildcard-header");
  });

  it("ignores commented-out options next to credentials", async () => {
    const f = await run({
      "a.ts": `import cors from "cors";\napp.use(cors({\n  // origin: "*",\n  origin: ["https://a.com"],\n  credentials: true,\n}));`,
      "b.ts": `import cors from "cors";\napp.use(cors({\n  /* origin: true, */\n  origin: ["https://a.com"],\n  credentials: true,\n}));`,
    });
    expect(f).toHaveLength(0);
  });

  it("handles apostrophes in comments and quotes in regex literals inside the call", async () => {
    const f = await run({
      "a.ts": `import cors from "cors";\napp.use(cors({ // don't restrict\n  origin: true,\n  credentials: true,\n}));`,
      "b.ts": `import cors from "cors";\napp.use(cors({ origin: /'x/, credentials: true }));\napp.use(cors({ origin: "*", credentials: true }));`,
    });
    expect(f.map((x) => x.file).sort()).toEqual(["a.ts", "b.ts"]);
    expect(f.find((x) => x.file === "a.ts")?.severity).toBe("high");
  });

  it("follows aliased cors imports", async () => {
    const f = await run({
      "a.ts": `import corsMiddleware from "cors";\napp.use(corsMiddleware({ origin: true, credentials: true }));`,
      "b.js": `const c = require("cors");\napp.use(c({ origin: true, credentials: true }));`,
      "c.ts": `import * as expressCors from "cors";\napp.use(expressCors({ origin: true, credentials: true }));`,
    });
    expect(f).toHaveLength(3);
  });

  it("resolves an options identifier containing $", async () => {
    const f = await run({
      "a.ts": `import cors from "cors";\nconst $opts = { origin: true, credentials: true };\napp.use(cors($opts));`,
    });
    expect(f).toHaveLength(1);
  });

  it("does not flag explicit wildcard or true origin without credentials or cookies", async () => {
    const f = await run({
      "a.ts": `import cors from "cors";\napp.use(cors({ origin: "*" }));`,
      "b.ts": `import cors from "cors";\napp.use(cors({ origin: true }));`,
    });
    expect(f).toHaveLength(0);
  });

  it("flags explicit wildcard origin without credentials in a cookie app", async () => {
    const f = await run({
      "a.ts": `import cors from "cors";\napp.use(cors({ origin: "*" }));`,
      "s.ts": `import session from "express-session";`,
    });
    expect(f).toHaveLength(1);
    expect(f[0]?.ruleId).toBe("security_config/cors-default-with-cookies");
  });

  it("flags a reflecting origin function without credentials", async () => {
    const f = await run({
      "a.ts": `import cors from "cors";\napp.use(cors({ origin: (o, cb) => cb(null, true) }));`,
      "b.ts": `import cors from "cors";\napp.use(cors({ origin: (origin, cb) => cb(null, origin) }));`,
    });
    expect(f).toHaveLength(2);
    expect(f.every((x) => x.ruleId === "security_config/cors-reflected-origin")).toBe(true);
  });

  it("detects reflected header split across lines", async () => {
    const f = await run({
      "server.js": `res.setHeader(\n  "Access-Control-Allow-Origin",\n  req.headers.origin\n);`,
    });
    expect(f).toHaveLength(1);
    expect(f[0]?.line).toBe(2);
  });

  it("is not suppressed by an unrelated .test() call, but is by a check within the 25-line window", async () => {
    const unrelated = await run({
      "server.js": `const ok = /abc/.test(name);\nres.setHeader("Access-Control-Allow-Origin", req.headers.origin);`,
    });
    expect(unrelated).toHaveLength(1);
    const far = await run({
      "server.js": `const origin = req.headers.origin;\nif (!allowed.includes(origin)) return;\n${"// pad\n".repeat(12)}res.setHeader("Access-Control-Allow-Origin", origin);`,
    });
    expect(far).toHaveLength(0);
  });

  it("ignores a commented-out Allow-Credentials header", async () => {
    const f = await run({
      "app/api/x/route.ts": `// res.headers.set("Access-Control-Allow-Credentials", "true");\nheaders.set("Access-Control-Allow-Origin", "*");`,
    });
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("medium");
  });
  it("produces stable ids with the CFG prefix", async () => {
    const files = {
      "s.ts": `import cors from "cors";\napp.use(cors({ origin: "*", credentials: true }));`,
    };
    const a = await run(files);
    const b = await run(files);
    expect(a[0]?.id).toBe(b[0]?.id);
    expect(a[0]?.id.startsWith("CFG-")).toBe(true);
  });

  it("is not confused by JSX closing tags on the same line as cors()", async () => {
    const f = await run({
      "server.tsx": `import cors from "cors";\nconst el = <div>hi</div>; app.use(cors({ origin: true, credentials: true }));`,
    });
    expect(f).toHaveLength(1);
    expect(f[0]?.ruleId).toBe("security_config/cors-reflected-origin");
  });

  it("falls back to a bounded window when brackets are unbalanced", async () => {
    const f = await run({
      "server.ts": `import cors from "cors";\napp.use(cors({ origin: true, credentials: true`,
    });
    expect(f).toHaveLength(1);
  });

  it('recognises `import { default as x } from "cors"`', async () => {
    const f = await run({
      "server.ts": `import { default as corsMw } from "cors";\napp.use(corsMw({ origin: true, credentials: true }));`,
    });
    expect(f).toHaveLength(1);
  });
});
