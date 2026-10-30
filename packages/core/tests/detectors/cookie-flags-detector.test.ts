import { describe, it, expect } from "vitest";
import { CookieFlagsDetector } from "../../src/detectors/cookie-flags-detector.js";
import { expectRubric } from "../helpers/rubric.js";
import { run } from "../helpers/injection.js";

const detector = new CookieFlagsDetector();
const NO_HTTPONLY = "security_config/session-cookie-no-httponly";
const SAMESITE = "security_config/session-cookie-samesite-none";
const NOT_SECURE = "security_config/session-cookie-not-secure";

const one = async (file: string, code: string) => run(detector, { [file]: code });

describe("CookieFlagsDetector positives", () => {
  it("1: flags a jwt.sign value cookie with no flags, listing both weak flags", async () => {
    const f = await one(
      "server.js",
      `const jwt = require("jsonwebtoken");\nfunction login(req, res) {\n  res.cookie("token", jwt.sign(payload, secret));\n}`,
    );
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({
      ruleId: NO_HTTPONLY,
      severity: "medium",
      confidence: "medium",
      line: 3,
    });
    expect(f[0]!.plainEnglishProblem).toContain("no HttpOnly, no Secure");
    expectRubric(f);
  });
  it("2: explicit httpOnly false is medium/high", async () => {
    const f = await one("server.js", `res.cookie("sid", id, { httpOnly: false, secure: true });`);
    expect(f[0]).toMatchObject({ ruleId: NO_HTTPONLY, severity: "medium", confidence: "high" });
  });
  it("3: cookies().set without options in an App Router handler", async () => {
    const f = await one(
      "app/api/login/route.ts",
      `import { cookies } from "next/headers";\nexport async function POST() {\n  cookies().set("session", token);\n  return Response.json({});\n}`,
    );
    expect(f[0]).toMatchObject({ ruleId: NO_HTTPONLY, confidence: "medium", line: 3 });
  });
  it("4: object-form set with SameSite=None", async () => {
    const f = await one(
      "app/api/login/route.ts",
      `import { cookies } from "next/headers";\nexport async function POST() {\n  const store = await cookies();\n  store.set({ name: "auth-token", value: t, httpOnly: true, sameSite: "none", secure: true });\n}`,
    );
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ ruleId: SAMESITE, severity: "medium", confidence: "medium" });
  });
  it("5: NextResponse cookies.set without secure", async () => {
    const f = await one(
      "app/api/refresh/route.ts",
      `import { NextResponse } from "next/server";\nexport async function POST() {\n  const response = NextResponse.json({});\n  response.cookies.set("refreshToken", rt, { httpOnly: true, sameSite: "lax" });\n  return response;\n}`,
    );
    expect(f[0]).toMatchObject({ ruleId: NOT_SECURE, severity: "low", confidence: "medium" });
  });
  it("6: express-session cookie.secure false is low/high", async () => {
    const f = await one(
      "server.js",
      `const session = require("express-session");\napp.use(session({ secret, cookie: { secure: false } }));`,
    );
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({
      ruleId: NOT_SECURE,
      severity: "low",
      confidence: "high",
      line: 2,
    });
  });
  it("7: cookie-session httpOnly false", async () => {
    const f = await one(
      "server.js",
      `import cookieSession from "cookie-session";\napp.use(cookieSession({ name: "session", keys, httpOnly: false }));`,
    );
    expect(f[0]).toMatchObject({ ruleId: NO_HTTPONLY, confidence: "high" });
  });
  it("8: literal Set-Cookie header", async () => {
    const f = await one("server.js", 'res.setHeader("Set-Cookie", `session=${id}; Path=/`);');
    expect(f[0]).toMatchObject({ ruleId: NO_HTTPONLY, confidence: "medium" });
  });
  it("9: value-marked cookie with httpOnly only", async () => {
    const f = await one("server.js", `res.cookie("u", accessToken, { httpOnly: true });`);
    expect(f[0]).toMatchObject({ ruleId: NOT_SECURE, severity: "low", confidence: "medium" });
  });
  it("15: bare sign() with a jsonwebtoken import marks the value", async () => {
    const f = await one(
      "server.js",
      `import jwt, { sign } from "jsonwebtoken";\nres.cookie("u", sign(claims));`,
    );
    expect(f[0]).toMatchObject({ ruleId: NO_HTTPONLY, confidence: "medium" });
  });
  it("16: refreshToken is still a session value", async () => {
    const f = await run(detector, {
      "a.js": `res.cookie("session", refreshToken);`,
      "b.js": `res.cookie("rt", refreshToken);`,
    });
    expect(f.map((x) => x.ruleId)).toEqual([NO_HTTPONLY, NO_HTTPONLY]);
    expect(f.every((x) => x.confidence === "medium")).toBe(true);
    expectRubric(f);
  });
  it("koa httpOnly false and serialize without flags", async () => {
    const f = await run(detector, {
      "koa.js": `ctx.cookies.set("session", id, { httpOnly: false });`,
      "ser.js": `import { serialize } from "cookie";\nres.setHeader("x", serialize("session", t, { path: "/" }));`,
    });
    expect(f.map((x) => x.ruleId)).toEqual([NO_HTTPONLY, NO_HTTPONLY]);
  });
  it("iron-session cookieOptions secure false", async () => {
    const f = await one(
      "lib/session.ts",
      `import { getIronSession } from "iron-session";\nexport const sessionOptions = {\n  password: p,\n  cookieName: "app",\n  cookieOptions: { secure: false },\n};`,
    );
    expect(f[0]).toMatchObject({ ruleId: NOT_SECURE, confidence: "high", line: 5 });
  });
  it("ids are stable across runs and a single targetFiles context works", async () => {
    const files = { "a.js": `res.cookie("session", t);`, "b.js": `res.cookie("session", t);` };
    const a = await run(detector, files);
    const b = await run(detector, files);
    expect(a.map((x) => x.id)).toEqual(b.map((x) => x.id));
    const single = await run(detector, files, { targetFiles: ["a.js"] });
    expect(single).toHaveLength(1);
  });
  it("caps findings per rule per file", async () => {
    const code = Array.from({ length: 30 }, (_, i) => `res.cookie("session", t${i});`).join("\n");
    const f = await one("server.js", code);
    expect(f.length).toBe(26);
    expectRubric(f);
  });
});

const SILENT: Array<[string, string, string]> = [
  [
    "1 theme, locale, consent, sidebar",
    "server.js",
    `res.cookie("theme", "dark");\nres.cookie("cookie_consent", "yes", { maxAge });\ncookies().set("NEXT_LOCALE", "fr");\ncookies().set("sidebar_state", "open");`,
  ],
  ["2 XSRF double-submit token", "server.js", `res.cookie("XSRF-TOKEN", req.csrfToken());`],
  [
    "3 imported options constant",
    "server.js",
    `import { COOKIE_OPTIONS } from "./cfg";\nres.cookie("session", token, COOKIE_OPTIONS);`,
  ],
  [
    "4 spread of a same-file const",
    "server.js",
    `const baseCookie = { httpOnly: true, secure: true, sameSite: "lax" };\nres.cookie("session", token, { ...baseCookie, maxAge });`,
  ],
  [
    "5 dynamic secure",
    "server.js",
    `res.cookie("token", jwt, { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax" });`,
  ],
  [
    "6 supabase ssr helper",
    "lib/supabase/server.ts",
    `import { cookies } from "next/headers";\nexport async function create() {\n  const cookieStore = await cookies();\n  return make({ cookies: { setAll(cookiesToSet) { cookiesToSet.forEach(({ name, value, options }) => cookieStore.set(name, value, options)); } } });\n}`,
  ],
  [
    "7 deleting",
    "server.js",
    `res.cookie("session", "", { maxAge: 0 });\nres.clearCookie("session");\ncookies().delete("session");`,
  ],
  [
    "8 express-session defaults",
    "server.js",
    `const session = require("express-session");\napp.use(session({ secret, resave: false, saveUninitialized: false }));`,
  ],
  [
    "9 express-session dynamic secure",
    "server.js",
    `const session = require("express-session");\napp.use(session({ secret, cookie: { secure: app.get("env") === "production", sameSite: "lax" } }));`,
  ],
  [
    "10 request.cookies.set in middleware",
    "middleware.ts",
    `import { NextResponse } from "next/server";\nexport function middleware(request) {\n  request.cookies.set("session", "1");\n  return NextResponse.next();\n}`,
  ],
  [
    "11 __Host- prefix",
    "server.js",
    `res.cookie("__Host-session", token, { httpOnly: true, path: "/" });`,
  ],
  ["12 client code", "src/client.ts", `document.cookie = "token=" + t;\nCookies.set("token", t);`],
  ["18a encrypt value", "server.js", `res.cookie("prefs", encrypt(prefs));`],
  ["18b bare sign without jwt import", "server.js", `res.cookie("ab_bucket", sign(bucket));`],
  [
    "19 invite and reset tokens",
    "server.js",
    `res.cookie("invite", inviteToken);\nres.cookie("reset", resetToken);`,
  ],
  [
    "20 preview token in a route handler",
    "app/api/preview/route.ts",
    `import { cookies } from "next/headers";\nexport async function GET() {\n  cookies().set("preview", previewToken);\n}`,
  ],
  [
    "21 otp and verify",
    "server.js",
    `res.cookie("otp_pending", otpToken, { maxAge: 300_000 });\nres.cookie("verify", verificationToken);`,
  ],
  [
    "comment and string only",
    "server.js",
    `// res.cookie("session", token);\nconst s = 'res.cookie("session", token)';\n/* cookies().set("session", t) */`,
  ],
  ["python file", "app.py", `response.set_cookie("session", token)\nres.cookie("session", token)`],
  [
    "secure explicit with prefix __Secure-",
    "server.js",
    `res.cookie("__Secure-session", token, { httpOnly: true });`,
  ],
];

describe("CookieFlagsDetector silent idioms", () => {
  it.each(SILENT)("%s", async (_n, file, code) => {
    expect(await one(file, code)).toEqual([]);
  });
  it("same code in tests/server.test.js is skipped without includeTests", async () => {
    const files = { "tests/server.test.js": `res.cookie("session", t);` };
    expect(await run(detector, files)).toEqual([]);
    expect(await run(detector, files, { includeTests: true })).toHaveLength(1);
  });
  it("client-runtime files are out of scope", async () => {
    expect(
      await one("src/components/Login.tsx", `"use client";\nres.cookie("session", t);`),
    ).toEqual([]);
  });
});

describe("CookieFlagsDetector review round 1", () => {
  it.each([
    [
      "logout idiom jwt",
      `res.cookie("jwt", "loggedout", { expires: new Date(Date.now() + 10000), httpOnly: true });`,
    ],
    ["logout idiom token none", `res.cookie("token", "none", { httpOnly: true });`],
    ["rememberMe literal", `res.cookie("rememberMe", "true");`],
    ["has_session flag", `res.cookie("has_session", "1", { secure: true });`],
    ["remember_email", `res.cookie("remember_email", req.body.email);`],
    ["literal Set-Cookie value", 'res.setHeader("Set-Cookie", "session=abc; Path=/");'],
    [
      "interpolated attributes",
      "res.setHeader('Set-Cookie', `session=${id}; HttpOnly; ${isProd ? 'Secure; ' : ''}SameSite=Lax`);",
    ],
  ])("silent: %s", async (_n, code) => {
    expect(await one("server.js", code)).toEqual([]);
  });
  it("bare serialize import scan is linear on pathological input", async () => {
    const code = Array.from({ length: 4000 }, () => "{ serialize serialize serialize").join("\n");
    const t0 = Date.now();
    await one("server.js", `${code}\nconst c = require("cookie");`);
    expect(Date.now() - t0).toBeLessThan(3000);
  });
  it("still finds a bare serialize import", async () => {
    const f = await one(
      "server.js",
      `import { serialize } from "cookie";\nres.setHeader("x", serialize("session", t, { path: "/" }));`,
    );
    expect(f.length).toBeGreaterThan(0);
  });
});
