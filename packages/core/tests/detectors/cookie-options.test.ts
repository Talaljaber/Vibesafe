import { describe, it, expect } from "vitest";
import { createJsSource } from "../../src/detectors/utils/js-source.js";
import {
  cookieNameTokens,
  findCookieSites,
  flagsOfArgument,
  flagsOfHeaderString,
  importsJwtLib,
  isSessionCookieName,
  isSessionCookieValue,
  readCookieFlags,
} from "../../src/detectors/utils/cookie-options.js";

const flagsOf = (code: string) => {
  const src = createJsSource(code);
  return readCookieFlags(src, src.code.indexOf("{", src.code.indexOf("OPTS")));
};

describe("cookieNameTokens", () => {
  it("splits camelCase, dots and dashes and adds adjacent joins", () => {
    expect(cookieNameTokens("next-auth.session-token")).toEqual([
      "next",
      "auth",
      "session",
      "token",
      "nextauth",
      "authsession",
      "sessiontoken",
    ]);
    expect(cookieNameTokens("previewToken")).toEqual(["preview", "token", "previewtoken"]);
    expect(cookieNameTokens("XSRF-TOKEN")).toEqual(["xsrf", "token", "xsrftoken"]);
    expect(cookieNameTokens("NEXT_LOCALE")).toContain("locale");
    expect(cookieNameTokens("sessionId")).toContain("sessionid");
  });
});

describe("isSessionCookieName", () => {
  it("marks session names and ignores flow cookies", () => {
    for (const n of [
      "session",
      "sid",
      "connect.sid",
      "auth-token",
      "next-auth.session-token",
      "jwt",
    ])
      expect(isSessionCookieName(n), n).toBe(true);
    for (const n of [
      "theme",
      "NEXT_LOCALE",
      "XSRF-TOKEN",
      "csrf_token",
      "oauth_state",
      "invite",
      "preview_token",
      "otp_pending",
      "magic-link",
    ])
      expect(isSessionCookieName(n), n).toBe(false);
  });
});

describe("isSessionCookieValue", () => {
  it("is false for session-object reads and bare identifiers", () => {
    for (const v of ["session.user.theme", "req.session.cartId", "sessionToken", "accessToken"])
      expect(isSessionCookieValue(v, false), v).toBe(false);
  });
  it("is false for one-purpose flow tokens", () => {
    for (const v of [
      "inviteToken",
      "previewToken",
      "resetToken",
      "otpToken",
      "verificationToken",
      "magicLinkToken",
    ])
      expect(isSessionCookieValue(v, false), v).toBe(false);
  });
  it("is true for credential-looking values", () => {
    for (const v of ["jwt.sign(p, s)", "signToken(user)", "createSessionFor(u)"])
      expect(isSessionCookieValue(v, false), v).toBe(true);
  });
  it("needs a JWT library import for a bare sign()", () => {
    expect(isSessionCookieValue("sign(claims)", false)).toBe(false);
    expect(isSessionCookieValue("sign(claims)", true)).toBe(true);
    expect(isSessionCookieValue("new SignJWT(c)", true)).toBe(true);
    expect(isSessionCookieValue("encrypt(prefs)", true)).toBe(false);
    expect(isSessionCookieValue("sealData(x)", true)).toBe(false);
  });
});

describe("importsJwtLib", () => {
  it("detects imports and ignores comments", () => {
    expect(importsJwtLib(createJsSource(`import jwt from "jsonwebtoken";`))).toBe(true);
    expect(importsJwtLib(createJsSource(`const { SignJWT } = require("jose");`))).toBe(true);
    expect(importsJwtLib(createJsSource(`// import jwt from "jsonwebtoken";\n`))).toBe(false);
  });
});

describe("readCookieFlags", () => {
  it("reads literal flags", () => {
    expect(flagsOf(`f(OPTS, { httpOnly: true, secure: false, sameSite: "None" })`)).toEqual({
      httpOnly: "true",
      secure: "false",
      sameSite: "none",
      deletes: false,
    });
  });
  it("treats expressions and shorthand as dynamic, missing keys as missing", () => {
    const f = flagsOf(`f(OPTS, { httpOnly: true, secure: process.env.NODE_ENV === "production" })`);
    expect(f.secure).toBe("dynamic");
    expect(f.sameSite).toBe("missing");
    expect(flagsOf(`f(OPTS, { httpOnly, sameSite: true })`)).toMatchObject({
      httpOnly: "dynamic",
      sameSite: "strict",
    });
  });
  it("resolves spreads of same-file consts, depth 2, and marks others dynamic", () => {
    const base = `const inner = { httpOnly: true };\nconst base = { ...inner, secure: true, sameSite: "lax" };\n`;
    expect(flagsOf(`${base}f(OPTS, { ...base, maxAge: 5 })`)).toMatchObject({
      httpOnly: "true",
      secure: "true",
      sameSite: "lax",
    });
    expect(flagsOf(`f(OPTS, { ...imported, maxAge: 5 })`)).toMatchObject({
      httpOnly: "dynamic",
      secure: "dynamic",
    });
  });
  it("ignores as const and satisfies tails and detects deletion", () => {
    expect(
      flagsOf(
        `f(OPTS, { httpOnly: true as const, sameSite: "lax" as const, secure: true } satisfies X)`,
      ),
    ).toMatchObject({
      httpOnly: "true",
      sameSite: "lax",
    });
    expect(flagsOf(`f(OPTS, { maxAge: 0 })`).deletes).toBe(true);
    expect(flagsOf(`f(OPTS, { expires: new Date(0) })`).deletes).toBe(true);
  });
  it("resolves a const identifier argument and leaves imports dynamic", () => {
    const src = createJsSource(`const o = { httpOnly: true };\nf(o);\ng(imported);`);
    const a = src.code.indexOf("f(o)") + 2;
    expect(flagsOfArgument(src, a, a + 1).httpOnly).toBe("true");
    const b = src.code.indexOf("g(imported)") + 2;
    expect(flagsOfArgument(src, b, b + 8).httpOnly).toBe("dynamic");
  });
});

describe("flagsOfHeaderString", () => {
  it("parses SameSite=None and Secure", () => {
    expect(flagsOfHeaderString("sid=abc; Path=/; HttpOnly; Secure; SameSite=None")).toEqual({
      name: "sid",
      httpOnly: "true",
      secure: "true",
      sameSite: "none",
      deletes: false,
    });
    expect(flagsOfHeaderString("sid=abc; Path=/")).toMatchObject({
      httpOnly: "missing",
      secure: "missing",
    });
    expect(flagsOfHeaderString("sid=; Max-Age=0").deletes).toBe(true);
  });
});

describe("findCookieSites", () => {
  it("finds express, next and session-config call sites", () => {
    const src = createJsSource(
      `import session from "express-session";\napp.use(session({ secret, cookie: { secure: false } }));\nres.cookie("session", t);\n`,
    );
    const kinds = findCookieSites(src).map((s) => s.kind);
    expect(kinds).toEqual(["express-session", "express"]);
  });
});
