import { describe, it, expect } from "vitest";
import { PathTraversalDetector } from "../../src/detectors/path-traversal-detector.js";
import { expectRubric } from "../helpers/rubric.js";
import { run } from "../helpers/injection.js";

const detector = new PathTraversalDetector();
const RULE = "injection/path-traversal";

describe("PathTraversalDetector", () => {
  it("flags readFile with path.join on a query parameter", async () => {
    const findings = await run(detector, {
      "app/api/files/route.ts": `import { readFile } from "fs/promises";
import path from "path";
export async function GET(req: Request) {
  const name = new URL(req.url).searchParams.get("name")!;
  const data = await readFile(path.join(process.cwd(), "uploads", name));
  return new Response(data);
}`,
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe(RULE);
    expect(findings[0]!.severity).toBe("high");
    expect(findings[0]!.line).toBe(5);
    expectRubric(findings);
  });

  it("flags res.sendFile and fs.unlink on route params in Express", async () => {
    const findings = await run(detector, {
      "server.js": `const express = require("express");
const fs = require("fs");
const app = express();
app.get("/download/:file", (req, res) => {
  res.sendFile(__dirname + "/files/" + req.params.file);
});
app.delete("/files/:file", (req, res) => {
  fs.unlinkSync("./uploads/" + req.params.file);
  res.end();
});`,
    });
    expect(findings.map((f) => f.line)).toEqual([5, 8]);
    expectRubric(findings);
  });

  it("does not flag basename, sendFile with root, or a startsWith(root) guard", async () => {
    const findings = await run(detector, {
      "server.js": `const express = require("express");
const fs = require("fs");
const path = require("path");
const app = express();
const ROOT = path.resolve("uploads");
app.get("/a/:file", (req, res) => {
  res.sendFile(req.params.file, { root: ROOT });
});
app.get("/b/:file", (req, res) => {
  res.send(fs.readFileSync(path.join(ROOT, path.basename(req.params.file))));
});
app.get("/c/:file", (req, res) => {
  const target = path.resolve(ROOT, req.params.file);
  if (!target.startsWith(ROOT + path.sep)) return res.status(400).end();
  res.send(fs.readFileSync(target));
});`,
    });
    expect(findings).toHaveLength(0);
  });

  it("ignores fs calls in comments and strings", async () => {
    const findings = await run(detector, {
      "app/api/files/route.ts": `import fs from "fs";
export async function GET(req: Request) {
  const name = new URL(req.url).searchParams.get("name");
  // fs.readFileSync("uploads/" + name);
  return Response.json({ usage: 'fs.readFileSync("uploads/" + name)' });
}`,
    });
    expect(findings).toHaveLength(0);
  });

  it("does not run on client components or .py files", async () => {
    const findings = await run(detector, {
      "app/files/page.tsx": `"use client";
import fs from "fs";
export default function Page() {
  const p = useSearchParams();
  fs.readFileSync("uploads/" + p.get("f"));
  return null;
}`,
      "app/files.py": `open("uploads/" + request.args["f"]).read()`,
    });
    expect(findings).toHaveLength(0);
  });

  it("produces stable ids across runs", async () => {
    const files = {
      "pages/api/file.ts": `import fs from "fs";
export default function handler(req, res) {
  res.send(fs.readFileSync("uploads/" + req.query.name));
}`,
    };
    const a = await run(detector, files);
    expect(a).toHaveLength(1);
    expect(a.map((f) => f.id)).toEqual((await run(detector, files)).map((f) => f.id));
  });
});
