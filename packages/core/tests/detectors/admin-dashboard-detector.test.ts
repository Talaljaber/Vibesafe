import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { AdminDashboardDetector } from "../../src/detectors/admin-dashboard-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const ctx = (files: Record<string, string>, only?: string): ScanContext => ({
  rootPath: "/fake",
  projectContext: {} as any,
  files: only ? [only] : Object.keys(files),
  config: {} as any,
  readFile: async (f) => files[f] ?? "",
});
const run = (files: Record<string, string>, only?: string) =>
  new AdminDashboardDetector().detect(ctx(files, only));
const RULE = "auth/unprotected-queue-dashboard";

describe("auth/unprotected-queue-dashboard", () => {
  it("flags a destructured Bull Board router mounted before auth", async () => {
    const files = {
      "src/index.ts": [
        "import express from 'express';",
        "import { createBullBoard } from 'bull-board';",
        "import { BullMQAdapter } from 'bull-board/bullMQAdapter';",
        "const app = express();",
        "app.use(requestLogger);",
        "const { router: boardRouter } = createBullBoard(queues.map((q) => new BullMQAdapter(q)));",
        "app.use('/admin/queues', boardRouter);",
        "app.use(internalAuth);",
        "app.use('/v1/jobs', jobsRouter);",
      ].join("\n"),
    };
    const f = await run(files);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ ruleId: RULE, severity: "high", confidence: "high", line: 7 });
    expectRubric(f);
    expect((await run(files)).map((x) => x.id)).toEqual(f.map((x) => x.id));
  });

  it("flags ExpressAdapter.getRouter() and Arena()", async () => {
    const f = await run({
      "server.js": [
        "const express = require('express');",
        "const { ExpressAdapter } = require('@bull-board/express');",
        "const { createBullBoard } = require('@bull-board/api');",
        "const Arena = require('bull-arena');",
        "const app = express();",
        "const serverAdapter = new ExpressAdapter();",
        "createBullBoard({ queues: [], serverAdapter });",
        "app.use('/queues', serverAdapter.getRouter());",
        "app.use('/arena', Arena({ queues: [] }, { disableListen: true }));",
      ].join("\n"),
    });
    expect(f.map((x) => x.line)).toEqual([8, 9]);
    expectRubric(f);
  });

  it("flags Agendash mounted on a router object", async () => {
    const f = await run({
      "src/admin.ts": [
        "import { Router } from 'express';",
        "import Agendash from 'agendash';",
        "const router = Router();",
        "const dash = Agendash(agenda);",
        "router.use('/jobs', dash);",
      ].join("\n"),
    });
    expect(f).toHaveLength(1);
    expect(f[0]!.line).toBe(5);
  });

  it("is silent when auth middleware is in the mount arguments", async () => {
    const f = await run({
      "src/index.ts": [
        "import express from 'express';",
        "import { createBullBoard } from 'bull-board';",
        "const app = express();",
        "const { router } = createBullBoard([]);",
        "app.use('/admin/queues', requireAdmin, router);",
        "app.use('/q', basicAuth({ users: { a: 'b' } }), router);",
      ].join("\n"),
    });
    expect(f).toHaveLength(0);
  });

  it("is silent when a global auth middleware is registered earlier", async () => {
    const f = await run({
      "src/index.ts": [
        "import express from 'express';",
        "import { createBullBoard } from 'bull-board';",
        "const app = express();",
        "app.use(passport.authenticate('jwt', { session: false }));",
        "const { router } = createBullBoard([]);",
        "app.use('/admin/queues', router);",
      ].join("\n"),
    });
    expect(f).toHaveLength(0);
  });

  it("is silent inside a non-production block and when never mounted", async () => {
    const f = await run({
      "src/dev.ts": [
        "import express from 'express';",
        "import { createBullBoard } from 'bull-board';",
        "const app = express();",
        "const { router } = createBullBoard([]);",
        "if (process.env.NODE_ENV !== 'production') {",
        "  app.use('/admin/queues', router);",
        "}",
      ].join("\n"),
      "src/unused.ts": [
        "import express from 'express';",
        "import { createBullBoard } from 'bull-board';",
        "const app = express();",
        "const { router } = createBullBoard([]);",
        "export const unused = router;",
        "app.use('/health', healthRouter);",
      ].join("\n"),
    });
    expect(f).toHaveLength(0);
  });

  it("is silent in non-Express files and for unrelated routers", async () => {
    const f = await run({
      "src/koa.ts": [
        "import Koa from 'koa';",
        "import { createBullBoard } from 'bull-board';",
        "const app = new Koa();",
        "const { router } = createBullBoard([]);",
        "app.use('/queues', router);",
      ].join("\n"),
      "src/api.ts": [
        "import express from 'express';",
        "const app = express();",
        "const router = express.Router();",
        "app.use('/api', router);",
      ].join("\n"),
    });
    expect(f).toHaveLength(0);
  });

  it("flags a Fastify plugin registration and honours targetFiles", async () => {
    const files = {
      "src/fast.ts": [
        "import Fastify from 'fastify';",
        "import { FastifyAdapter } from '@bull-board/fastify';",
        "import { createBullBoard } from '@bull-board/api';",
        "const app = Fastify();",
        "const serverAdapter = new FastifyAdapter();",
        "createBullBoard({ queues: [], serverAdapter });",
        "app.register(serverAdapter.registerPlugin(), { prefix: '/ui' });",
      ].join("\n"),
      "src/other.ts": "export const x = 1;",
    };
    expect(await run(files, "src/other.ts")).toHaveLength(0);
    const f = await run(files, "src/fast.ts");
    expect(f).toHaveLength(1);
    expect(f[0]!.line).toBe(7);
  });
});
