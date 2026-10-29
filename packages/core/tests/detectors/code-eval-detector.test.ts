import { describe, it, expect } from "vitest";
import { CodeEvalDetector } from "../../src/detectors/code-eval-detector.js";
import { expectRubric } from "../helpers/rubric.js";
import { run } from "../helpers/injection.js";

const detector = new CodeEvalDetector();
const RULE = "injection/dynamic-code-eval";

describe("CodeEvalDetector", () => {
  it("flags eval of the request body in an App Router handler", async () => {
    const findings = await run(detector, {
      "app/api/calc/route.ts": `export async function POST(req: Request) {
  const { expression } = await req.json();
  const result = eval(expression);
  return Response.json({ result });
}`,
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe(RULE);
    expect(findings[0]!.severity).toBe("critical");
    expect(findings[0]!.line).toBe(3);
    expectRubric(findings);
  });

  it("follows tainted values into callbacks and same-file helpers", async () => {
    const findings = await run(detector, {
      "app/api/rules/route.ts": `function compile(src: string) {
  return new Function("row", src);
}
export async function POST(req: Request) {
  const body = await req.json();
  const fns = Object.entries(body.rules).map(([name, expr]) => new Function("x", expr as string));
  const check = compile(body.filter);
  return Response.json({ n: fns.length, ok: check({}) });
}`,
    });
    const lines = findings.map((f) => f.line ?? 0).sort((a, b) => a - b);
    expect(lines).toEqual([2, 6]);
    expect(findings.every((f) => f.ruleId === RULE)).toBe(true);
    expectRubric(findings);
  });

  it("flags vm.runInNewContext on the query string in Express", async () => {
    const findings = await run(detector, {
      "server.ts": `import express from "express";
import vm from "node:vm";
const app = express();
app.get("/run", (req, res) => {
  res.json(vm.runInNewContext(String(req.query.code), {}));
});`,
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.line).toBe(5);
    expectRubric(findings);
  });

  it("does not flag literal code, function timers, JSON.parse, redis.eval or page.evaluate", async () => {
    const findings = await run(detector, {
      "app/api/calc/route.ts": `export async function POST(req: Request) {
  const body = await req.json();
  setTimeout(() => console.error(body.x), 10);
  eval("1 + 1");
  const data = JSON.parse(body.payload);
  await redis.eval(body.script, 0);
  await page.evaluate(body.selector);
  return Response.json(data);
}`,
    });
    expect(findings).toHaveLength(0);
  });

  it("ignores eval in comments and strings", async () => {
    const findings = await run(detector, {
      "app/api/calc/route.ts": `export async function POST(req: Request) {
  const { expression } = await req.json();
  // const result = eval(expression);
  return Response.json({ hint: "eval(expression)" });
}`,
    });
    expect(findings).toHaveLength(0);
  });

  it("does not run on client components (owned by the client stream)", async () => {
    const findings = await run(detector, {
      "app/calc/page.tsx": `"use client";
export default function Calc() {
  const params = useSearchParams();
  const v = eval(params.get("expr") ?? "0");
  return <div>{v}</div>;
}`,
    });
    expect(findings).toHaveLength(0);
  });

  it("produces stable ids across runs", async () => {
    const files = {
      "app/api/calc/route.ts": `export async function POST(req: Request) {
  const { expression } = await req.json();
  return Response.json(eval(expression));
}`,
    };
    const a = await run(detector, files);
    expect(a).toHaveLength(1);
    expect(a.map((f) => f.id)).toEqual((await run(detector, files)).map((f) => f.id));
  });
});
