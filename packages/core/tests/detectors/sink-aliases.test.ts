import { describe, it, expect } from "vitest";
import { CommandInjectionDetector } from "../../src/detectors/command-injection-detector.js";
import { CodeEvalDetector } from "../../src/detectors/code-eval-detector.js";
import { expectRubric } from "../helpers/rubric.js";
import { run } from "../helpers/injection.js";

const cmd = new CommandInjectionDetector();
const evalDet = new CodeEvalDetector();

const handler = (head: string, call: string): string => `${head}
import express from "express";
const app = express();
app.post("/x", async (req, res) => {
  const name = req.body.name;
  ${call}
  res.end();
});`;

describe("sink aliases: command", () => {
  const cases: [string, string, string][] = [
    [
      "renamed named import",
      `import { exec as sh } from "node:child_process";`,
      "sh(`ls ${name}`);",
    ],
    [
      "renamed destructured require",
      `const { exec: sh } = require("node:child_process");`,
      "sh(`ls ${name}`);",
    ],
    [
      "namespace import with util.promisify",
      `import * as cp from "child_process";\nimport * as util from "util";\nconst run = util.promisify(cp.exec);`,
      "await run(`ls ${name}`);",
    ],
    [
      "promisify of an inline require",
      `import { promisify } from "util";\nconst run = promisify(require("child_process").exec);`,
      "await run(`ls ${name}`);",
    ],
    [
      "promisify of an imported exec",
      `import { exec } from "child_process";\nimport { promisify } from "util";\nconst run = promisify(exec);`,
      "await run(`ls ${name}`);",
    ],
  ];
  for (const [label, head, call] of cases) {
    it(`flags ${label}`, async () => {
      const findings = await run(cmd, { "server.ts": handler(head, call) });
      expect(findings).toHaveLength(1);
      expect(findings[0]!.ruleId).toBe("injection/command-exec-interpolation");
      expectRubric(findings);
    });
  }

  it("does not treat a project helper named exec as child_process", async () => {
    const findings = await run(cmd, {
      "server.ts": handler(
        `import { exec } from "./lib/shell";\nimport { spawn } from "child_process";`,
        "exec(`ls ${name}`);",
      ),
    });
    expect(findings).toHaveLength(0);
  });

  it("does not flag an aliased exec with a constant command", async () => {
    const findings = await run(cmd, {
      "server.ts": handler(
        `import { exec as sh } from "node:child_process";`,
        'sh("ls -la /tmp");',
      ),
    });
    expect(findings).toHaveLength(0);
  });
});

describe("sink aliases: vm", () => {
  const cases: [string, string, string][] = [
    ["default import of node:vm", `import vm from "node:vm";`, "vm.runInNewContext(name, {});"],
    [
      "named import of runInNewContext",
      `import { runInNewContext } from "vm";`,
      "runInNewContext(name, {});",
    ],
    [
      "new Script from a destructured require",
      `const { Script } = require("vm");`,
      "new Script(name).runInThisContext();",
    ],
    ["namespace import", `import * as v from "vm";`, "v.runInThisContext(name);"],
  ];
  for (const [label, head, call] of cases) {
    it(`flags ${label}`, async () => {
      const findings = await run(evalDet, { "server.ts": handler(head, call) });
      expect(findings).toHaveLength(1);
      expect(findings[0]!.ruleId).toBe("injection/dynamic-code-eval");
      expectRubric(findings);
    });
  }

  it("does not flag vm with a constant script or a tainted sandbox only", async () => {
    const findings = await run(evalDet, {
      "server.ts": handler(
        `import vm from "node:vm";`,
        'vm.runInNewContext("1 + 1", { name });\n  vm.runInNewContext("x * 2", name);',
      ),
    });
    expect(findings).toHaveLength(0);
  });

  it("does not flag a project Script class", async () => {
    const findings = await run(evalDet, {
      "server.ts": handler(`import { Script } from "./script";`, "new Script(name);"),
    });
    expect(findings).toHaveLength(0);
  });
});
