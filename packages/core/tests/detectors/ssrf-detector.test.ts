import { describe, it, expect } from "vitest";
import { SsrfDetector } from "../../src/detectors/ssrf-detector.js";
import { expectRubric } from "../helpers/rubric.js";
import { run } from "../helpers/injection.js";

const detector = new SsrfDetector();
const RULE = "injection/ssrf-user-controlled-url";

describe("SsrfDetector", () => {
  it("flags fetch of a URL taken from the request body", async () => {
    const findings = await run(detector, {
      "app/api/preview/route.ts": `export async function POST(req: Request) {
  const { url } = await req.json();
  const res = await fetch(url);
  return new Response(await res.text());
}`,
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe(RULE);
    expect(findings[0]!.severity).toBe("high");
    expect(findings[0]!.confidence).toBe("high");
    expect(findings[0]!.line).toBe(3);
    expectRubric(findings);
  });

  it("flags axios with a user-chosen host and a scheme-only regex check", async () => {
    const findings = await run(detector, {
      "server.js": `const express = require("express");
const axios = require("axios");
const app = express();
app.get("/proxy", async (req, res) => {
  const target = req.query.target;
  if (!/^https?:\\/\\//.test(target)) return res.status(400).end();
  const r = await axios.get(target);
  res.send(r.data);
});
app.get("/host", async (req, res) => {
  const r = await axios.get(\`https://\${req.query.host}/status\`);
  res.send(r.data);
});`,
    });
    expect(findings.map((f) => f.line)).toEqual([7, 11]);
    expect(findings[1]!.confidence).toBe("medium");
    expectRubric(findings);
  });

  it("does not flag a tainted path under a fixed origin or a hostname allowlist", async () => {
    const findings = await run(detector, {
      "app/api/preview/route.ts": `const ALLOWED = new Set(["api.example.com"]);
export async function POST(req: Request) {
  const { id, url } = await req.json();
  await fetch(\`https://api.example.com/items/\${encodeURIComponent(id)}\`);
  const u = new URL(url);
  if (!ALLOWED.has(u.hostname)) return new Response("no", { status: 400 });
  await fetch(u);
  return new Response("ok");
}`,
    });
    expect(findings).toHaveLength(0);
  });

  it("ignores fetch in comments and strings", async () => {
    const findings = await run(detector, {
      "app/api/preview/route.ts": `export async function POST(req: Request) {
  const { url } = await req.json();
  // await fetch(url);
  return Response.json({ example: "fetch(url)" });
}`,
    });
    expect(findings).toHaveLength(0);
  });

  it("does not run on client components", async () => {
    const findings = await run(detector, {
      "app/preview/page.tsx": `"use client";
export default function Preview() {
  const params = useSearchParams();
  useEffect(() => { fetch(params.get("u")!); }, []);
  return null;
}`,
    });
    expect(findings).toHaveLength(0);
  });

  it("produces stable ids across runs", async () => {
    const files = {
      "app/api/preview/route.ts": `export async function POST(req: Request) {
  const { url } = await req.json();
  return fetch(url);
}`,
    };
    const a = await run(detector, files);
    expect(a).toHaveLength(1);
    expect(a.map((f) => f.id)).toEqual((await run(detector, files)).map((f) => f.id));
  });
});
