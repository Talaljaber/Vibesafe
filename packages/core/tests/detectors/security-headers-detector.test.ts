import { describe, it, expect } from "vitest";
import type { ScanContext } from "@vibesafe/shared";
import { SecurityHeadersDetector } from "../../src/detectors/security-headers-detector.js";

const ctx = (files: Record<string, string>): ScanContext =>
  ({
    rootPath: "/fake",
    projectContext: {},
    files: Object.keys(files),
    config: {},
    readFile: async (f: string) => files[f] ?? "",
  }) as unknown as ScanContext;

const detector = new SecurityHeadersDetector();

describe("SecurityHeadersDetector: Express", () => {
  it("flags an Express app without helmet", async () => {
    const findings = await detector.detect(
      ctx({
        "src/server.ts": `import express from "express";\nconst app = express();\napp.get("/", (_q, r) => r.send("hi"));`,
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe("security_config/missing-helmet");
    expect(findings[0]?.severity).toBe("medium");
    expect(findings[0]?.category).toBe("security_config");
    expect(findings[0]?.line).toBe(2);
    expect(findings[0]?.plainEnglishProblem).toContain("X-Powered-By");
    expect(findings[0]?.id.startsWith("SECCFG-")).toBe(true);
  });

  it("flags CommonJS require('express')", async () => {
    const findings = await detector.detect(
      ctx({ "server.js": `const express = require("express");\nconst app = express();` }),
    );
    expect(findings).toHaveLength(1);
  });

  it("does not flag when helmet is imported and used", async () => {
    const findings = await detector.detect(
      ctx({
        "server.ts": `import express from "express";\nimport helmet from "helmet";\nconst app = express();\napp.use(helmet());`,
      }),
    );
    expect(findings).toHaveLength(0);
  });

  it("does not flag helmet with options or require form", async () => {
    const findings = await detector.detect(
      ctx({
        "server.js": `const express = require("express");\nconst helmet = require("helmet");\nconst app = express();\napp.use(helmet({ contentSecurityPolicy: false }));`,
      }),
    );
    expect(findings).toHaveLength(0);
  });

  it("treats helmet applied in another file as protecting the project", async () => {
    const findings = await detector.detect(
      ctx({
        "src/app.ts": `import express from "express";\nexport const app = express();`,
        "src/security.ts": `import helmet from "helmet";\nexport const secure = (a) => a.use(helmet());`,
      }),
    );
    expect(findings).toHaveLength(0);
  });

  it("flags when helmet is imported but never applied", async () => {
    const findings = await detector.detect(
      ctx({
        "server.ts": `import express from "express";\nimport helmet from "helmet";\nconst app = express();`,
      }),
    );
    expect(findings).toHaveLength(1);
  });

  it("flags when helmet use is only in a comment", async () => {
    const findings = await detector.detect(
      ctx({
        "server.ts": `import express from "express";\n// import helmet from "helmet";\n// app.use(helmet());\nconst app = express();`,
      }),
    );
    expect(findings).toHaveLength(1);
  });

  it("ignores routers, files without express import and test files", async () => {
    const findings = await detector.detect(
      ctx({
        "routes.ts": `import { Router } from "express";\nexport const r = Router();`,
        "other.ts": `const app = express();`,
        "server.test.ts": `import express from "express";\nconst app = express();`,
        "__tests__/a.ts": `import express from "express";\nconst app = express();`,
      }),
    );
    expect(findings).toHaveLength(0);
  });

  it("reports each Express entry file once", async () => {
    const findings = await detector.detect(
      ctx({
        "a/server.ts": `import express from "express";\nconst x = express();\nconst y = express();`,
        "b/server.ts": `import express from "express";\nconst x = express();`,
      }),
    );
    expect(findings).toHaveLength(2);
  });
});

describe("SecurityHeadersDetector: Express edge cases", () => {
  it("keeps app.use(helmet()) when an earlier string contains '/*' and a later doc block exists", async () => {
    const src = `import express from "express";\nimport helmet from "helmet";\nconst app = express();\napp.use("/api/*", (_q, _r, n) => n());\napp.use(helmet());\n/** doc */\nexport default app;`;
    expect(await detector.detect(ctx({ "server.ts": src }))).toHaveLength(0);
  });

  it("does not count helmet in a trailing comment", async () => {
    const src = `import express from "express";\nimport helmet from "helmet";\nconst app = express(); // app.use(helmet());`;
    expect(await detector.detect(ctx({ "server.ts": src }))).toHaveLength(1);
  });

  it("recognises dynamic import() of helmet and .mjs/.cjs files", async () => {
    const mjs = `import express from "express";\nconst app = express();\nconst helmet = (await import("helmet")).default;\napp.use(helmet());`;
    expect(await detector.detect(ctx({ "server.mjs": mjs }))).toHaveLength(0);
    const cjs = `const express = require("express");\nconst app = express();`;
    expect(await detector.detect(ctx({ "server.cjs": cjs }))).toHaveLength(1);
  });

  it("scopes helmet to the same package in a monorepo", async () => {
    const findings = await detector.detect(
      ctx({
        "apps/a/package.json": "{}",
        "apps/b/package.json": "{}",
        "apps/a/server.ts": `import express from "express";\nimport helmet from "helmet";\nconst app = express();\napp.use(helmet());`,
        "apps/b/server.ts": `import express from "express";\nconst app = express();`,
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.file).toBe("apps/b/server.ts");
  });
});

describe("SecurityHeadersDetector: Next.js", () => {
  it("flags next.config without headers() as medium listing all headers", async () => {
    const findings = await detector.detect(
      ctx({ "next.config.js": `module.exports = { reactStrictMode: true };` }),
    );
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.ruleId).toBe("security_config/missing-security-headers");
    expect(f.severity).toBe("medium");
    for (const h of [
      "Content-Security-Policy",
      "X-Frame-Options",
      "X-Content-Type-Options",
      "Strict-Transport-Security",
      "Referrer-Policy",
    ]) {
      expect(f.plainEnglishProblem).toContain(h);
    }
  });

  it("supports .mjs and .ts configs and nested apps", async () => {
    for (const name of ["next.config.mjs", "apps/web/next.config.ts"]) {
      const findings = await detector.detect(ctx({ [name]: `export default {};` }));
      expect(findings).toHaveLength(1);
      expect(findings[0]?.file).toBe(name);
    }
  });

  it("is low severity when only non-CSP headers are missing, and lists only those", async () => {
    const config = `module.exports = { async headers() { return [{ source: "/(.*)", headers: [
      { key: "Content-Security-Policy", value: "default-src 'self'" },
      { key: "X-Frame-Options", value: "DENY" },
      { key: "X-Content-Type-Options", value: "nosniff" },
    ] }]; } };`;
    const findings = await detector.detect(ctx({ "next.config.js": config }));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("low");
    expect(findings[0]?.plainEnglishProblem).toContain("Strict-Transport-Security");
    expect(findings[0]?.plainEnglishProblem).toContain("Referrer-Policy");
    expect(findings[0]?.plainEnglishProblem).not.toContain("X-Content-Type-Options");
    expect(findings[0]?.line).toBe(1);
  });

  it("is medium when CSP is missing but others are set", async () => {
    const config = `module.exports = { async headers() { return [{ source: "/(.*)", headers: [
      { key: "X-Frame-Options", value: "DENY" },
      { key: "X-Content-Type-Options", value: "nosniff" },
      { key: "Strict-Transport-Security", value: "max-age=1" },
      { key: "Referrer-Policy", value: "same-origin" },
    ] }]; } };`;
    const findings = await detector.detect(ctx({ "next.config.js": config }));
    expect(findings[0]?.severity).toBe("medium");
  });

  it("does not flag when all headers are set", async () => {
    const config = `module.exports = { async headers() { return [{ source: "/(.*)", headers: [
      { key: "Content-Security-Policy", value: "default-src 'self'; frame-ancestors 'none'" },
      { key: "x-content-type-options", value: "nosniff" },
      { key: "Strict-Transport-Security", value: "max-age=1" },
      { key: "Referrer-Policy", value: "same-origin" },
    ] }]; } };`;
    expect(await detector.detect(ctx({ "next.config.js": config }))).toHaveLength(0);
  });

  it("accepts headers set in middleware beside the config (root or src/)", async () => {
    const mw = `export function middleware() { const r = NextResponse.next();
      r.headers.set("Content-Security-Policy", "x"); r.headers.set("X-Frame-Options", "DENY");
      r.headers.set("X-Content-Type-Options", "nosniff"); r.headers.set("Strict-Transport-Security", "m");
      r.headers.set("Referrer-Policy", "r"); return r; }`;
    expect(
      await detector.detect(ctx({ "next.config.js": "module.exports = {};", "middleware.ts": mw })),
    ).toHaveLength(0);
    expect(
      await detector.detect(
        ctx({ "next.config.js": "module.exports = {};", "src/middleware.ts": mw }),
      ),
    ).toHaveLength(0);
  });

  it("does not use another app's middleware", async () => {
    const mw = `r.headers.set("Content-Security-Policy","x");`;
    const findings = await detector.detect(
      ctx({ "apps/web/next.config.js": "module.exports = {};", "apps/admin/middleware.ts": mw }),
    );
    expect(findings).toHaveLength(1);
  });

  it("ignores headers mentioned only in comments", async () => {
    const config = `// Content-Security-Policy, X-Frame-Options\nmodule.exports = {};`;
    const findings = await detector.detect(ctx({ "next.config.js": config }));
    expect(findings[0]?.severity).toBe("medium");
    for (const h of [
      "Content-Security-Policy",
      "X-Frame-Options",
      "X-Content-Type-Options",
      "Strict-Transport-Security",
      "Referrer-Policy",
    ]) {
      expect(findings[0]?.plainEnglishProblem).toContain(h);
    }
  });

  it("ignores block and trailing comments, and anchors the line on real code", async () => {
    const config = `/* Content-Security-Policy X-Frame-Options */\n// add headers later\nmodule.exports = {\n  poweredByHeader: false, // Referrer-Policy\n  async headers() { return []; },\n};`;
    const findings = await detector.detect(ctx({ "next.config.js": config }));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.line).toBe(5);
    expect(findings[0]?.plainEnglishProblem).toContain("Referrer-Policy");
    expect(findings[0]?.plainEnglishProblem).toContain("Content-Security-Policy");
  });

  it("does not let a '/*' inside a string blank out real headers", async () => {
    const config = `module.exports = { async headers() { return [{ source: "/api/*", headers: [
      { key: "Content-Security-Policy", value: "default-src https://*.example.com" },
      { key: "X-Frame-Options", value: "DENY" },
      { key: "X-Content-Type-Options", value: "nosniff" },
      { key: "Strict-Transport-Security", value: "max-age=1" },
      { key: "Referrer-Policy", value: "same-origin" },
    ] }]; } };\n/** doc */`;
    expect(await detector.detect(ctx({ "next.config.js": config }))).toHaveLength(0);
  });

  it("counts headers set in proxy.ts", async () => {
    const proxy = `r.headers.set("Content-Security-Policy","x");r.headers.set("X-Frame-Options","DENY");r.headers.set("X-Content-Type-Options","nosniff");r.headers.set("Strict-Transport-Security","m");r.headers.set("Referrer-Policy","r");`;
    expect(
      await detector.detect(ctx({ "next.config.js": "module.exports = {};", "proxy.ts": proxy })),
    ).toHaveLength(0);
  });

  it("counts headers from vercel.json beside the config or at the repo root", async () => {
    const vercel = JSON.stringify({
      headers: [
        {
          source: "/(.*)",
          headers: [
            { key: "Content-Security-Policy", value: "x" },
            { key: "X-Frame-Options", value: "DENY" },
            { key: "X-Content-Type-Options", value: "nosniff" },
            { key: "Strict-Transport-Security", value: "m" },
            { key: "Referrer-Policy", value: "r" },
          ],
        },
      ],
    });
    expect(
      await detector.detect(
        ctx({ "next.config.js": "module.exports = {};", "vercel.json": vercel }),
      ),
    ).toHaveLength(0);
    expect(
      await detector.detect(
        ctx({ "apps/web/next.config.js": "module.exports = {};", "vercel.json": vercel }),
      ),
    ).toHaveLength(0);
  });

  it("lists the remaining headers when vercel.json sets only some", async () => {
    const vercel = `{"headers":[{"source":"/(.*)","headers":[{"key":"X-Frame-Options","value":"DENY"}]}]}`;
    const findings = await detector.detect(
      ctx({ "next.config.js": "module.exports = {};", "vercel.json": vercel }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.plainEnglishProblem).toContain("Strict-Transport-Security");
    expect(findings[0]?.plainEnglishProblem).not.toContain("X-Frame-Options");
  });

  it("does not accept Content-Security-Policy-Report-Only as CSP", async () => {
    const config = `module.exports = { async headers() { return [{ source: "/(.*)", headers: [
      { key: "Content-Security-Policy-Report-Only", value: "default-src 'self'" },
    ] }]; } };`;
    const findings = await detector.detect(ctx({ "next.config.js": config }));
    expect(findings[0]?.plainEnglishProblem).toContain("Content-Security-Policy");
  });

  it("lowers confidence when headers come from an imported module or helper package", async () => {
    const imported = `import { securityHeaders } from "./security-headers";\nexport default { async headers() { return [{ source: "/(.*)", headers: securityHeaders }]; } };`;
    const pkg = `const { createSecureHeaders } = require("next-secure-headers");\nmodule.exports = {};`;
    for (const config of [imported, pkg]) {
      const findings = await detector.detect(ctx({ "next.config.js": config }));
      expect(findings).toHaveLength(1);
      expect(findings[0]?.confidence).toBe("low");
    }
    const plain = await detector.detect(ctx({ "next.config.js": "module.exports = {};" }));
    expect(plain[0]?.confidence).toBe("medium");
  });

  it("does not scan next.config.mts (not a scannable extension)", async () => {
    expect(await detector.detect(ctx({ "next.config.mts": "export default {};" }))).toHaveLength(0);
  });

  it("produces stable ids", async () => {
    const files = { "next.config.js": "module.exports = {};" };
    const a = await detector.detect(ctx(files));
    const b = await detector.detect(ctx(files));
    expect(a[0]?.id).toBe(b[0]?.id);
  });
});
