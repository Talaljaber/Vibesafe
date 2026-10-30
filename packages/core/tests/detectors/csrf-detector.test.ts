import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { CsrfDetector } from "../../src/detectors/csrf-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const detector = new CsrfDetector();
const RULE = "security_config/csrf-cookie-session-unprotected";

function ctx(
  files: Record<string, string>,
  opts: { deps?: Record<string, string>; targetFiles?: string[]; framework?: string } = {},
): ScanContext {
  return {
    rootPath: "/fake/path",
    projectContext: {
      framework: opts.framework ?? "express",
      dependencies: opts.deps ?? {},
      devDependencies: {},
    } as unknown as ScanContext["projectContext"],
    files: opts.targetFiles ?? Object.keys(files),
    config: { includeTests: false } as ScanContext["config"],
    readFile: async (f) => files[f] ?? "",
  };
}
const go = (files: Record<string, string>, deps?: Record<string, string>) =>
  detector.detect(ctx(files, deps === undefined ? {} : { deps }));

const APP = `const express = require("express");
const session = require("express-session");
const accountRoutes = require("./routes/account");
const app = express();
app.use(express.json());
app.use(session({ secret: process.env.SECRET, resave: false, saveUninitialized: false }));
app.use("/account", accountRoutes);
`;
const ACCOUNT = `const router = require("express").Router();
router.post("/account/email", requireLogin, async (req, res) => {
  await updateEmail(req.user.id, req.body.email);
  res.json({ ok: true });
});
module.exports = router;
`;

describe("CsrfDetector positives", () => {
  it("10: session + json-only POST route is medium/low, anchored at the session middleware", async () => {
    const f = await go({ "server.js": APP, "routes/account.js": ACCOUNT });
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({
      ruleId: RULE,
      severity: "medium",
      confidence: "low",
      file: "server.js",
      line: 6,
    });
    expect(f[0]!.plainEnglishProblem).toContain("POST /account/email (routes/account.js:2)");
    expect(f[0]!.plainEnglishProblem).toContain("Routes that only accept JSON");
    expectRubric(f);
  });
  it("11: SameSite=None raises confidence to medium and the cookie rule also fires", async () => {
    const app = APP.replace(
      "saveUninitialized: false }",
      'saveUninitialized: false, cookie: { sameSite: "none", secure: true } }',
    );
    const f = await go({ "server.js": app, "routes/account.js": ACCOUNT });
    expect(f[0]).toMatchObject({ ruleId: RULE, confidence: "medium" });
    expect(f[0]!.plainEnglishProblem).not.toContain("Routes that only accept JSON");
  });
  it("12: cookie JWT at login + DELETE route, anchored at the res.cookie line", async () => {
    const f = await go({
      "server.js": `const express = require("express");
const app = express();
app.post("/login", (req, res) => {
  res.cookie("token", jwt, { httpOnly: true });
  res.json({});
});
app.use((req, res, next) => { req.user = verify(req.cookies.token); next(); });
app.delete("/posts/:id", auth, (req, res) => { res.sendStatus(204); });
`,
    });
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ ruleId: RULE, confidence: "medium", line: 4 });
    expect(f[0]!.plainEnglishProblem).toContain("DELETE /posts/:id");
  });
  it("13: a urlencoded parser makes it medium", async () => {
    const app = APP.replace(
      "app.use(express.json());",
      "app.use(express.urlencoded({ extended: false }));",
    );
    const f = await go({ "server.js": app, "routes/account.js": ACCOUNT });
    expect(f[0]).toMatchObject({ confidence: "medium" });
  });
  it("14: a bodiless inline POST handler makes it medium", async () => {
    const f = await go({
      "server.js": APP,
      "routes/account.js": `const router = require("express").Router();
router.post("/posts/:id/like", requireLogin, async (req, res) => { await like(req.params.id, req.user.id); res.sendStatus(204); });
`,
    });
    expect(f[0]).toMatchObject({ ruleId: RULE, confidence: "medium" });
  });
  it("passport sessions count as cookie sessions", async () => {
    const f = await go({
      "server.js": `const express = require("express");\nconst passport = require("passport");\nconst app = express();\napp.use(passport.session());\napp.put("/profile", ensureLoggedIn, (req, res) => { res.json(req.body); });\n`,
    });
    expect(f).toHaveLength(1);
    expect(f[0]!.line).toBe(4);
  });
  it("ids are stable and a single targetFiles context works", async () => {
    const files = { "server.js": APP, "routes/account.js": ACCOUNT };
    const a = await go(files);
    const b = await go(files);
    expect(a.map((x) => x.id)).toEqual(b.map((x) => x.id));
    const single = await detector.detect(ctx(files, { targetFiles: ["server.js"] }));
    expect(single).toEqual([]);
  });
});

const SILENT: Array<[string, Record<string, string>, Record<string, string>?]> = [
  [
    "13 Next.js app with server actions and route handlers",
    {
      "app/actions.ts": `"use server";\nimport { cookies } from "next/headers";\nexport async function save() { cookies().set("session", t, { httpOnly: true }); }`,
      "app/api/orders/route.ts": `export async function POST(req: Request) { return Response.json({}); }`,
    },
    { next: "14.0.0" },
  ],
  [
    "14 Express API with Bearer authentication",
    {
      "server.js": `const express = require("express");\nconst app = express();\napp.post("/orders", (req, res) => { const t = req.headers.authorization; res.json({}); });\n`,
    },
  ],
  [
    "15a csrf-csrf double submit",
    {
      "server.js": APP.replace(
        'app.use("/account"',
        'const { doubleCsrfProtection } = doubleCsrf({ getSecret });\napp.use(doubleCsrfProtection);\napp.use("/account"',
      ),
      "routes/account.js": ACCOUNT,
    },
  ],
  [
    "15b lusca",
    {
      "server.js": APP.replace('app.use("/account"', 'app.use(lusca.csrf());\napp.use("/account"'),
      "routes/account.js": ACCOUNT,
    },
  ],
  [
    "15c origin check middleware",
    {
      "server.js": APP.replace(
        'app.use("/account"',
        'app.use((req, res, next) => { if (req.get("origin") !== process.env.APP_ORIGIN) return res.sendStatus(403); next(); });\napp.use("/account"',
      ),
      "routes/account.js": ACCOUNT,
    },
  ],
  [
    "16 explicit SameSite=Lax",
    {
      "server.js": APP.replace(
        "saveUninitialized: false }",
        'saveUninitialized: false, cookie: { sameSite: "lax" } }',
      ),
      "routes/account.js": ACCOUNT,
    },
  ],
  [
    "17 only login, logout, signup and signed webhooks",
    {
      "server.js": `${APP}
app.post("/login", (req, res) => res.json({}));
app.post("/logout", (req, res) => res.json({}));
app.post("/auth/sign-out", (req, res) => res.json({}));
app.post("/session/destroy", (req, res) => res.json({}));
app.post("/signup", (req, res) => res.json({}));
app.post("/webhooks/stripe", express.raw({ type: "*/*" }), (req, res) => {
  const event = stripe.webhooks.constructEvent(req.body, sig, secret);
  res.json({});
});
`,
    },
  ],
  [
    "csrf package in dependencies",
    { "server.js": APP, "routes/account.js": ACCOUNT },
    { "csrf-sync": "^4.0.0" },
  ],
  [
    "routes authenticated by an API key header chain",
    {
      "server.js": `${APP}\napp.post("/sync", passport.authenticate("jwt", { session: false }), (req, res) => res.json({}));\n`,
    },
  ],
  [
    "no cookie session at all",
    {
      "server.js": `const express = require("express");\nconst app = express();\napp.post("/orders", (req, res) => res.json({}));\n`,
    },
  ],
  [
    "session-looking text in comments only",
    {
      "server.js": `// const session = require("express-session");\nconst express = require("express");\nconst app = express();\n// app.use(session({}));\napp.post("/orders", (req, res) => res.json({}));\n`,
    },
  ],
  [
    "theme cookie only",
    {
      "server.js": `const express = require("express");\nconst app = express();\napp.get("/t", (req, res) => { res.cookie("theme", "dark"); res.end(); });\napp.post("/orders", (req, res) => res.json({}));\n`,
    },
  ],
  [
    "python file",
    {
      "app.py": `from flask import Flask\napp = Flask(__name__)\n@app.post("/x")\ndef x(): pass\n`,
    },
  ],
];

describe("CsrfDetector silent idioms", () => {
  it.each(SILENT)("%s", async (_n, files, deps) => {
    expect(await go(files, deps)).toEqual([]);
  });
  it("same project in a test path is skipped without includeTests", async () => {
    expect(
      await go({ "tests/server.test.js": APP, "tests/routes/account.test.js": ACCOUNT }),
    ).toEqual([]);
  });
});

describe("CsrfDetector review round 1", () => {
  it("reads session SameSite from a non-express config module (lax: silent)", async () => {
    const f = await go({
      "server.js": `const express = require("express");\nconst session = require("./config/session");\nconst passport = require("passport");\nconst app = express();\napp.use(session);\napp.use(passport.session());\napp.post("/orders", (req, res) => res.json({}));\napp.delete("/orders/:id", (req, res) => res.json({}));\n`,
      "config/session.js": `const session = require("express-session");\nmodule.exports = session({ secret: process.env.S, cookie: { sameSite: "lax" } });\n`,
    });
    expect(f).toEqual([]);
  });
  it("finds session middleware in a non-express config module (no SameSite: flags)", async () => {
    const f = await go({
      "server.js": `const express = require("express");\nconst session = require("./config/session");\nconst app = express();\napp.use(session);\napp.delete("/orders/:id", (req, res) => res.json({}));\n`,
      "config/session.js": `const session = require("express-session");\nmodule.exports = session({ secret: process.env.S });\n`,
    });
    expect(f).toHaveLength(1);
    expect(f[0]!.file).toBe("config/session.js");
  });
  it("Bearer API with a refresh-token cookie is silent", async () => {
    const f = await go({
      "server.js": `const express = require("express");\nconst app = express();\napp.post("/login", (req, res) => { res.cookie("refreshToken", rt, { httpOnly: true }); res.json({ at }); });\napp.post("/refresh", (req, res) => { const t = req.cookies.refreshToken; res.json({}); });\nconst protect = (req, res, next) => { const h = req.headers.authorization; next(); };\napp.delete("/items/:id", protect, (req, res) => res.json({}));\n`,
    });
    expect(f).toEqual([]);
  });
});

describe("CsrfDetector review round 2", () => {
  it("MERN refresh token in a jwt-named cookie plus Authorization header auth is silent", async () => {
    const f = await go({
      "server.js": `const express = require("express");\nconst verifyJWT = require("./mw/verifyJWT");\nconst app = express();\napp.use(express.json());\napp.use("/auth", require("./routes/auth"));\napp.use(verifyJWT);\napp.use("/employees", require("./routes/employees"));\n`,
      "routes/auth.js": `const router = require("express").Router();\nrouter.post("/", (req, res) => {\n  res.cookie("jwt", refreshToken, { httpOnly: true, secure: true });\n  res.json({ accessToken });\n});\nrouter.get("/refresh", (req, res) => {\n  const t = req.cookies.jwt;\n  res.json({ accessToken });\n});\nmodule.exports = router;\n`,
      "routes/employees.js": `const router = require("express").Router();\nrouter.put("/:id", (req, res) => res.json({}));\nrouter.delete("/:id", (req, res) => res.json({}));\nmodule.exports = router;\n`,
    });
    expect(f).toEqual([]);
  });
  it("a session cookie read stays evidence when a non-refresh res.cookie sets the same name", async () => {
    const f = await go({
      "server.js": `const express = require("express");\nconst app = express();\napp.post("/a", (req, res) => { res.cookie("jwt", refreshToken, { httpOnly: true }); res.json({}); });\napp.post("/b", (req, res) => { res.cookie("jwt", accessToken, { httpOnly: true }); res.json({}); });\napp.use((req, res, next) => { const t = req.cookies.jwt; next(); });\napp.delete("/items/:id", (req, res) => res.json({}));\n`,
    });
    expect(f.length).toBeGreaterThan(0);
  });
});

describe("CsrfDetector review round 3", () => {
  it("split MERN layout: refresh cookie set in a non-express controller is silent", async () => {
    const f = await go({
      "server.js": `const express = require("express");\nconst verifyJWT = require("./mw/verifyJWT");\nconst app = express();\napp.use(express.json());\napp.use("/refresh", require("./routes/refresh"));\napp.use(verifyJWT);\napp.use("/employees", require("./routes/employees"));\n`,
      "controllers/authController.js": `const handleLogin = async (req, res) => {\n  res.cookie("jwt", refreshToken, { httpOnly: true, secure: true });\n  res.json({ accessToken });\n};\nmodule.exports = { handleLogin };\n`,
      "routes/refresh.js": `const router = require("express").Router();\nrouter.get("/", (req, res) => {\n  const t = req.cookies.jwt;\n  res.json({ accessToken });\n});\nmodule.exports = router;\n`,
      "routes/employees.js": `const router = require("express").Router();\nrouter.put("/:id", (req, res) => res.json({}));\nrouter.delete("/:id", (req, res) => res.json({}));\nmodule.exports = router;\n`,
    });
    expect(f).toEqual([]);
  });
  it("a refresh-only read before a real session read does not hide the session read", async () => {
    const f = await go({
      "controllers/authController.js": `exports.login = (req, res) => { res.cookie("jwt", refreshToken, { httpOnly: true }); res.json({}); };\n`,
      "server.js": `const express = require("express");\nconst app = express();\napp.get("/r", (req, res) => { const t = req.cookies.jwt; res.json({}); });\napp.use((req, res, next) => { const s = req.cookies.token; next(); });\napp.delete("/items/:id", (req, res) => res.json({}));\n`,
    });
    expect(f.length).toBeGreaterThan(0);
  });
});

describe("CsrfDetector extra review round 1", () => {
  const SERVER = (cookieIdent: string) =>
    `const express = require("express");\nconst app = express();\nconst auth = (req, res, next) => { const token = ${cookieIdent}; next(); };\napp.put("/api/posts/:id", auth, (req, res) => res.json({}));\napp.delete("/api/posts/:id", auth, (req, res) => res.json({}));\n`;
  it("SameSite from a non-express controller cookie silences", async () => {
    const f = await go({
      "server.js": SERVER("req.cookies.token"),
      "controllers/authController.js": `exports.login = (req, res) => { res.cookie("token", jwt.sign({}, s), { httpOnly: true, sameSite: "strict", maxAge: 1 }); res.json({}); };\n`,
    });
    expect(f).toEqual([]);
  });
  it("positive control: controller cookie without sameSite is still reported", async () => {
    const f = await go({
      "server.js": SERVER("req.cookies.token"),
      "controllers/authController.js": `exports.login = (req, res) => { res.cookie("token", jwt.sign({}, s), { httpOnly: true, maxAge: 1 }); res.json({}); };\n`,
    });
    expect(f.length).toBeGreaterThan(0);
  });
  it("chained res.status(200).cookie with strict is silent", async () => {
    const f = await go({
      "server.js": `const express = require("express");\nconst app = express();\nconst options = { httpOnly: true, secure: true, sameSite: "strict" };\napp.post("/api/login", (req, res) => { res.status(200).cookie("token", token, options).json({ success: true }); });\nconst isAuth = (req, res, next) => { const token = req.cookies.token; next(); };\napp.delete("/api/orders/:id", isAuth, (req, res) => res.json({}));\n`,
    });
    expect(f).toEqual([]);
  });
  it("optional-chaining cookie read counts as evidence", async () => {
    const f = await go({
      "server.js": SERVER("req.cookies?.accessToken"),
    });
    expect(f.length).toBeGreaterThan(0);
  });
});

describe("CsrfDetector review extra round 2", () => {
  it("handles long whitespace after req.cookies in linear time", async () => {
    const code = `const express = require("express");\nconst app = express();\nconst a = req.cookies${" ".repeat(60000)};\nconst b = 1;\n`;
    const t0 = Date.now();
    await go({ "server.js": code });
    expect(Date.now() - t0).toBeLessThan(1500);
  });
});
