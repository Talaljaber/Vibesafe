import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { createJsSource } from "../../src/detectors/utils/js-source.js";
import { findCookieSites } from "../../src/detectors/utils/cookie-options.js";
import { CookieFlagsDetector } from "../../src/detectors/cookie-flags-detector.js";
import { CsrfDetector } from "../../src/detectors/csrf-detector.js";

const time = (code: string): number => {
  const t = performance.now();
  findCookieSites(createJsSource(code));
  return performance.now() - t;
};
const N = 10_000;

describe("cookie site resolution stays near-linear on ~1 MB inputs", () => {
  it("10k sites sharing one options identifier", () => {
    let c = 'const opts = { httpOnly: true, secure: true, sameSite: "lax" };\n';
    for (let i = 0; i < N; i++)
      c += `app.get("/r${i}", (req, res) => res.cookie("token", t${i}, opts));\n`;
    expect(time(c)).toBeLessThan(2500);
  });
  it("10k distinct mutated options identifiers", () => {
    let c = "";
    for (let i = 0; i < N; i++)
      c += `const o${i} = { httpOnly: true }; o${i}.secure = isProd; res.cookie("session", tok, o${i});\n`;
    expect(time(c)).toBeLessThan(2500);
  });
  it("10k distinct cookie name identifiers", () => {
    let c = "";
    for (let i = 0; i < N; i++) c += `const n${i} = "pref${i}"; res.cookie(n${i}, t);\n`;
    expect(time(c)).toBeLessThan(2500);
  });
  it("10k cookies() bindings and express-session bindings", () => {
    let c = 'import { cookies } from "next/headers";\n';
    for (let i = 0; i < N; i++) c += `const c${i} = cookies(); c${i}.set("a", "b");\n`;
    expect(time(c)).toBeLessThan(2500);
    let d = "";
    for (let i = 0; i < N; i++) d += `const s${i} = require("express-session"); s${i}({});\n`;
    expect(time(d)).toBeLessThan(2500);
  });
  it("deeply nested cookie calls", () => {
    const k = 3000;
    const c = 'res.cookie("token",\n'.repeat(k) + "t" + ")".repeat(k) + ";";
    expect(time(c)).toBeLessThan(2500);
  });
});

describe("spread budget is per call", () => {
  it("CookieFlags then Csrf on one context keeps a spread-based strict cookie resolved", async () => {
    let c = `const express = require("express");
const jwt = require("jsonwebtoken");
const app = express();
const prefOpts = { httpOnly: true, secure: true, sameSite: "lax" };
const authCookie = { httpOnly: true, secure: true, sameSite: "strict" };
`;
    for (let i = 0; i < 30; i++)
      c += `app.get("/p${i}", (req, res) => res.cookie("pref_${i}", req.body.p${i}, { ...prefOpts }));\n`;
    c += `app.get("/login", (req, res) => res.cookie("token", jwt.sign({}, k), { ...authCookie }));
function auth(req, res, next) { const t = req.cookies.token; next(); }
app.delete("/account", auth, (req, res) => res.json({}));
`;
    const files = { "app.js": c };
    const ctx: ScanContext = {
      rootPath: "/fake/path",
      projectContext: {
        framework: "express",
        dependencies: {},
        devDependencies: {},
      } as unknown as ScanContext["projectContext"],
      files: Object.keys(files),
      config: { includeTests: false } as ScanContext["config"],
      readFile: async (f) => files[f as keyof typeof files] ?? "",
    };
    await new CookieFlagsDetector().detect(ctx);
    const after = await new CsrfDetector().detect(ctx);
    const alone = await new CsrfDetector().detect({ ...ctx });
    expect(after.filter((f) => f.ruleId.includes("csrf"))).toEqual(
      alone.filter((f) => f.ruleId.includes("csrf")),
    );
    expect(after.filter((f) => f.ruleId.includes("csrf-cookie-session"))).toHaveLength(0);
  });
});
