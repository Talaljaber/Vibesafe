import { describe, it, expect } from "vitest";
import { CommandInjectionDetector } from "../../src/detectors/command-injection-detector.js";
import { expectRubric } from "../helpers/rubric.js";
import { run } from "../helpers/injection.js";

const detector = new CommandInjectionDetector();
const RULE = "injection/command-exec-interpolation";

describe("CommandInjectionDetector", () => {
  it("flags exec with a template literal built from the request body", async () => {
    const findings = await run(detector, {
      "app/api/convert/route.ts": `import { exec } from "child_process";
export async function POST(req: Request) {
  const { url } = await req.json();
  exec(\`curl -s \${url} -o /tmp/out\`, () => {});
  return Response.json({ ok: true });
}`,
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe(RULE);
    expect(findings[0]!.severity).toBe("critical");
    expect(findings[0]!.confidence).toBe("high");
    expect(findings[0]!.line).toBe(4);
    expectRubric(findings);
  });

  it("flags renamed/promisified exec and spawn with shell: true", async () => {
    const findings = await run(detector, {
      "server.js": `const express = require("express");
const cp = require("node:child_process");
const { spawn } = require("child_process");
const app = express();
app.post("/ping", (req, res) => {
  cp.execSync("ping -c 1 " + req.body.host);
  spawn("git", ["log", req.query.ref], { shell: true });
  res.send("ok");
});`,
    });
    expect(findings.map((f) => f.line)).toEqual([6, 7]);
    expect(findings.every((f) => f.ruleId === RULE)).toBe(true);
    expectRubric(findings);
  });

  it("caps command-line arguments in scripts at high", async () => {
    const findings = await run(detector, {
      "scripts/backup.mjs": `#!/usr/bin/env node
import { execSync } from "node:child_process";
const target = process.argv[2];
execSync(\`tar czf backup.tgz \${target}\`);`,
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("high");
    expectRubric(findings);
  });

  it("does not flag execFile/spawn with argument arrays, literal commands or a local helper named exec", async () => {
    const findings = await run(detector, {
      "app/api/convert/route.ts": `import { execFile, spawn, exec } from "child_process";
import { exec as run } from "@/lib/shell";
export async function POST(req: Request) {
  const { url } = await req.json();
  execFile("curl", ["-fsSL", url, "-o", "/tmp/out"]);
  spawn("git", ["log", url]);
  exec("ls -la /tmp");
  run(\`curl \${url}\`);
  return Response.json({ ok: true });
}`,
    });
    expect(findings).toHaveLength(0);
  });

  it("ignores exec calls in comments and strings", async () => {
    const findings = await run(detector, {
      "app/api/convert/route.ts": `import { exec } from "child_process";
export async function POST(req: Request) {
  const { url } = await req.json();
  // exec(\`curl \${url}\`);
  const help = "exec(\`curl \${url}\`)";
  return Response.json({ help });
}`,
    });
    expect(findings).toHaveLength(0);
  });

  it("does not run on client components or .py files", async () => {
    const findings = await run(detector, {
      "components/Runner.tsx": `"use client";
import { exec } from "child_process";
export function Runner() {
  const q = useSearchParams();
  exec(\`echo \${q.get("x")}\`);
  return null;
}`,
      "tools/run.py": `import subprocess\nsubprocess.run(f"curl {request.args['u']}", shell=True)`,
    });
    expect(findings).toHaveLength(0);
  });

  it("produces stable ids across runs", async () => {
    const files = {
      "app/api/convert/route.ts": `import { exec } from "child_process";
export async function POST(req: Request) {
  const { url } = await req.json();
  exec("curl " + url);
}`,
    };
    const a = await run(detector, files);
    const b = await run(detector, files);
    expect(a).toHaveLength(1);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });
});

describe("CommandInjectionDetector: generics and queue job payloads", () => {
  it("flags execSync with a TS type argument", async () => {
    const findings = await run(detector, {
      "server.ts": `import express from "express";
import { execSync } from "child_process";
const app = express();
app.get("/p", (req, res) => {
  const out = execSync<string>(\`ping \${req.query.host}\`);
  res.send(out);
});`,
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.line).toBe(5);
    expectRubric(findings);
  });

  it("flags exec built from job.data in a queue worker, capped at high", async () => {
    const findings = await run(
      detector,
      {
        "workers/thumb.ts": `import { Worker } from "bullmq";
import { exec } from "node:child_process";
new Worker("thumbs", async (job) => {
  exec(\`convert \${job.data.path} out.png\`);
});`,
      },
      { targetFiles: ["workers/thumb.ts"] },
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("high");
    expect(findings[0]!.title).toBe("Shell Command Built From Queue Job Data");
    expectRubric(findings);
  });

  it("flags Agenda and pg-boss payloads", async () => {
    const findings = await run(detector, {
      "jobs/a.ts": `import Agenda from "agenda";
import { exec } from "child_process";
const agenda = new Agenda();
agenda.define("run", async (job) => {
  exec("sh " + job.attrs.data.script);
});`,
      "jobs/b.ts": `import PgBoss from "pg-boss";
import { exec } from "child_process";
export async function start(boss: PgBoss) {
  await boss.work("run", async (job) => { exec(\`echo \${job.data.msg}\`); });
}`,
    });
    expect(findings.map((f) => f.file).sort()).toEqual(["jobs/a.ts", "jobs/b.ts"]);
  });

  it("is silent for execFile array args, numeric coercion and files without a queue import", async () => {
    const findings = await run(detector, {
      "workers/a.ts": `import { Worker } from "bullmq";
import { execFile, exec } from "node:child_process";
new Worker("thumbs", async (job) => {
  execFile("convert", [job.data.path, "out.png"]);
  exec(\`sleep \${Number(job.data.id)}\`);
});`,
      "workers/b.ts": `import { exec } from "node:child_process";
import { Worker } from "./own";
new Worker("thumbs", async (job) => {
  exec(\`convert \${job.data.path} out.png\`);
});`,
    });
    expect(findings).toHaveLength(0);
  });
});
