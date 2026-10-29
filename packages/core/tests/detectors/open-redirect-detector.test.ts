import { describe, it, expect } from "vitest";
import { OpenRedirectDetector } from "../../src/detectors/open-redirect-detector.js";
import { expectRubric } from "../helpers/rubric.js";
import { run } from "../helpers/injection.js";

const detector = new OpenRedirectDetector();
const RULE = "injection/open-redirect";

describe("OpenRedirectDetector", () => {
  it("flags NextResponse.redirect to a callback URL from the query string", async () => {
    const findings = await run(detector, {
      "app/api/auth/callback/route.ts": `import { NextResponse, type NextRequest } from "next/server";
export async function GET(req: NextRequest) {
  const next = req.nextUrl.searchParams.get("next") ?? "/";
  return NextResponse.redirect(next);
}`,
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe(RULE);
    expect(findings[0]!.severity).toBe("high");
    expect(findings[0]!.line).toBe(4);
    expectRubric(findings);
  });

  it("flags res.redirect and a Location header in Express", async () => {
    const findings = await run(detector, {
      "server.js": `const express = require("express");
const app = express();
app.get("/go", (req, res) => {
  res.redirect(302, req.query.returnTo);
});
app.get("/go2", (req, res) => {
  res.setHeader("Location", req.query.url);
  res.status(302).end();
});`,
    });
    expect(findings.map((f) => f.line)).toEqual([4, 7]);
    expectRubric(findings);
  });

  it("reports an origin-prefixed value without a leading slash at medium", async () => {
    const findings = await run(detector, {
      "app/api/login/route.ts": `export async function GET(req: Request) {
  const u = new URL(req.url);
  const next = u.searchParams.get("next") ?? "";
  return Response.redirect(\`\${u.origin}\${next}\`);
}`,
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("medium");
    expectRubric(findings);
  });

  it("does not flag same-origin construction, relative-path checks or allowlists", async () => {
    const findings = await run(detector, {
      "app/api/auth/callback/route.ts": `import { NextResponse, type NextRequest } from "next/server";
const ALLOWED = ["/dashboard", "/settings"];
export async function GET(req: NextRequest) {
  const next = req.nextUrl.searchParams.get("next") ?? "/";
  if (req.nextUrl.searchParams.has("login")) return NextResponse.redirect(new URL("/login", req.url));
  if (next.startsWith("/") && !next.startsWith("//")) return NextResponse.redirect(new URL(next, req.url));
  const dest = ALLOWED.includes(next) ? next : "/dashboard";
  return NextResponse.redirect(new URL(dest, req.url));
}`,
    });
    expect(findings).toHaveLength(0);
  });

  it("ignores redirects in comments and strings", async () => {
    const findings = await run(detector, {
      "app/api/go/route.ts": `export async function GET(req: Request) {
  const next = new URL(req.url).searchParams.get("next");
  // return Response.redirect(next);
  return Response.json({ doc: "Response.redirect(next)" });
}`,
    });
    expect(findings).toHaveLength(0);
  });

  it("does not run on client components", async () => {
    const findings = await run(detector, {
      "app/go/page.tsx": `"use client";
import { redirect } from "next/navigation";
export default function Go() {
  const p = useSearchParams();
  redirect(p.get("next")!);
}`,
    });
    expect(findings).toHaveLength(0);
  });

  it("produces stable ids across runs", async () => {
    const files = {
      "pages/api/go.ts": `export default function handler(req, res) {
  res.redirect(req.query.to);
}`,
    };
    const a = await run(detector, files);
    expect(a).toHaveLength(1);
    expect(a.map((f) => f.id)).toEqual((await run(detector, files)).map((f) => f.id));
  });
});
