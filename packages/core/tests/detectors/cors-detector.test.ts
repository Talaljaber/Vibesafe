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
  it("flags origin '*' with credentials as high", async () => {
    const f = await run({
      "server.ts": `import cors from "cors";\napp.use(cors({ origin: "*", credentials: true }));`,
    });
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("high");
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
    expect(await run({ "server.ts": `import cors from "cors";\napp.use(cors());` })).toHaveLength(0);
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

  it("escalates wildcard header to high with Allow-Credentials true", async () => {
    const f = await run({
      "middleware.ts": `res.headers.set("Access-Control-Allow-Origin", "*");\nres.headers.set("Access-Control-Allow-Credentials", "true");`,
    });
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe("high");
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
    expect(f.every((x) => x.ruleId === "security_config/cors-reflected-origin" && x.severity === "high")).toBe(true);
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

  it("produces stable ids with the CFG prefix", async () => {
    const files = { "s.ts": `import cors from "cors";\napp.use(cors({ origin: "*", credentials: true }));` };
    const a = await run(files);
    const b = await run(files);
    expect(a[0]?.id).toBe(b[0]?.id);
    expect(a[0]?.id.startsWith("CFG-")).toBe(true);
  });
});
