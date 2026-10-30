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

describe("CodeEvalDetector: queue job payloads", () => {
  it("flags eval of job.data in a worker, capped at high", async () => {
    const findings = await run(
      detector,
      {
        "workers/rules.ts": `import { Worker } from "bullmq";
new Worker("rules", async (job) => {
  return eval(job.data.expression);
});`,
      },
      { targetFiles: ["workers/rules.ts"] },
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe(RULE);
    expect(findings[0]!.severity).toBe("high");
    expect(findings[0]!.title).toBe("Dynamic Code Built From Queue Job Data");
    expectRubric(findings);
  });

  it("is silent without a queue import and for literal code", async () => {
    const findings = await run(detector, {
      "workers/a.ts": `import { Worker } from "./own";
new Worker("rules", async (job) => eval(job.data.expression));`,
      "workers/b.ts": `import { Worker } from "bullmq";
new Worker("rules", async (job) => { console.log(job.data.expression); return eval("1 + 1"); });`,
    });
    expect(findings).toHaveLength(0);
  });
});

describe("CodeEvalDetector: injection/code-eval-from-parameter", () => {
  const PARAM = "injection/code-eval-from-parameter";

  it("flags vm code built from an exported function's parameter", async () => {
    const findings = await run(
      detector,
      {
        "lib/rules.ts": `import vm from "node:vm";
export function evaluateRule(rule: string, ctx: object) {
  return vm.runInNewContext(\`(\${rule})\`, ctx);
}
export const compile = (exprs: Record<string, string>) =>
  Object.entries(exprs).map(([name, expr]) => new Function("row", \`return \${expr}\`));
export default function run(source: string) {
  const script = new vm.Script(source);
  return script;
}
module.exports.legacy = function (code) { return eval(code); };`,
      },
      { targetFiles: ["lib/rules.ts"] },
    );
    expect(findings.every((f) => f.ruleId === PARAM)).toBe(true);
    expect(findings.map((f) => f.line)).toEqual([3, 6, 8, 11]);
    expect(findings[0]!.severity).toBe("high");
    expect(findings[0]!.confidence).toBe("medium");
    expectRubric(findings);
  });

  it("follows the parameter through for...of destructuring", async () => {
    const findings = await run(detector, {
      "lib/rules.js": `import vm from "vm";
export function compileAll(rules) {
  const out = [];
  for (const [name, body] of Object.entries(rules)) {
    out.push(vm.compileFunction(body, ["row"]));
  }
  return out;
}`,
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe(PARAM);
    expect(findings[0]!.line).toBe(5);
  });

  it("is skipped when dynamic-code-eval already fires on the call", async () => {
    const findings = await run(detector, {
      "app/api/calc/route.ts": `export async function POST(req: Request) {
  const { expression } = await req.json();
  return Response.json({ r: eval(expression) });
}
export function helper(code: string) { return eval(code); }`,
    });
    expect(findings.map((f) => f.ruleId).sort()).toEqual([PARAM, RULE]);
    expect(findings.find((f) => f.ruleId === RULE)!.line).toBe(3);
  });

  it("stays silent for sandbox-only parameters, constant code and non-exported helpers", async () => {
    const findings = await run(detector, {
      "lib/rules.ts": `import vm from "node:vm";
export function run(sandbox: object, ctx: object) {
  const g = new Function("return this")();
  vm.runInNewContext("total = a + b", sandbox);
  return vm.runInContext("a * 2", vm.createContext(ctx));
}
function internal(code: string) { return eval(code); }
export function delay(ms: number, cb: () => void) { setTimeout(cb, ms); return internal("1"); }
export function parse(text: string) { return JSON.parse(text); }`,
    });
    expect(findings).toHaveLength(0);
  });

  it("ignores client files and comments", async () => {
    const findings = await run(detector, {
      "components/Calc.tsx": `"use client";
export function calc(expr: string) { return eval(expr); }`,
      "lib/x.ts": `// export function f(code: string) { return eval(code); }
export const x = 1;`,
    });
    expect(findings.filter((f) => f.ruleId === PARAM)).toHaveLength(0);
  });
});
