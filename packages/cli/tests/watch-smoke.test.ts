import { describe, it, expect } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { runWatch } from "../src/commands/watch.js";

type Ev = Record<string, unknown> & { type: string };

async function waitFor(events: Ev[], pred: (e: Ev) => boolean, ms = 20000): Promise<Ev> {
  const start = Date.now();
  while (Date.now() - start < ms) {
    const hit = events.find(pred);
    if (hit) return hit;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`timed out; events: ${JSON.stringify(events.map((e) => e.type))}`);
}

describe("runWatch smoke test (temp dir, --json events)", () => {
  it("emits ready, then a change with new and resolved findings, and stops on abort", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "vibesafe-watch-"));
    await fs.mkdir(path.join(dir, "src"));
    await fs.writeFile(path.join(dir, "src", "ok.ts"), "export const a = 1;\n");
    await fs.writeFile(path.join(dir, ".gitignore"), "ignored.ts\n");

    const events: Ev[] = [];
    const controller = new AbortController();
    const done = runWatch(dir, {
      json: true,
      debounceMs: 100,
      signal: controller.signal,
      write: (line) => events.push(JSON.parse(line) as Ev),
    });

    try {
      const ready = await waitFor(events, (e) => e.type === "ready");
      expect(ready.projectPath).toBe(dir);

      // Introduce a leaked secret.
      const secretFile = path.join(dir, "src", "leak.ts");
      await fs.writeFile(secretFile, 'export const k = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL";\n');
      const added = await waitFor(events, (e) => e.type === "change" && (e.added as unknown[]).length > 0);
      expect(added.files).toEqual(["src/leak.ts"]);
      expect(added.scoreChange as number).toBeLessThan(0);

      // A gitignored file must never surface findings. A scannable sentinel
      // written afterwards proves the watcher processed past ignored.ts.
      await fs.writeFile(
        path.join(dir, "ignored.ts"),
        'export const k = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL";\n',
      );
      await fs.writeFile(path.join(dir, "src", "sentinel.ts"), 'export const s = "sk-proj-zyxwvutsrqponmlkjihgfedcba9876543210ZYXWVUTSRQP";\n');
      await waitFor(events, (e) => e.type === "change" && (e.files as string[]).includes("src/sentinel.ts"));
      const mentionsIgnored = events
        .filter((e) => e.type === "change")
        .some((e) => (e.added as Array<{ file?: string }>).some((f) => f.file === "ignored.ts"));
      expect(mentionsIgnored).toBe(false);
      // Fix it: the finding is resolved and the score goes back up.
      await fs.writeFile(secretFile, "export const k = process.env.KEY;\n");
      const resolved = await waitFor(events, (e) => e.type === "change" && (e.resolved as unknown[]).length > 0);
      expect(resolved.scoreChange as number).toBeGreaterThan(0);
    } finally {
      controller.abort();
      await done;
      await fs.rm(dir, { recursive: true, force: true });
    }
  }, 60000);
});

describe("runWatch cross-file correctness (full rescan)", () => {
  it("does not report a protected route as new, catches a weakened middleware, and handles delete and package.json", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "vibesafe-watch-"));
    const route = path.join(dir, "src", "app", "api", "admin", "route.ts");
    const middleware = path.join(dir, "src", "middleware.ts");
    await fs.mkdir(path.dirname(route), { recursive: true });
    await fs.writeFile(route, "export async function POST() { return Response.json({ ok: true }); }\n");
    await fs.writeFile(middleware, 'export { default } from "next-auth/middleware";\n');
    await fs.writeFile(path.join(dir, "package.json"), '{ "name": "x" }\n');

    const events: Ev[] = [];
    const controller = new AbortController();
    const done = runWatch(dir, {
      json: true,
      debounceMs: 100,
      signal: controller.signal,
      write: (line) => events.push(JSON.parse(line) as Ev),
    });
    const changes = () => events.filter((e) => e.type === "change");

    try {
      await waitFor(events, (e) => e.type === "ready");
      const authFindings = (e: Ev) =>
        (e.added as Array<{ ruleId: string }>).filter((f) => f.ruleId === "auth/missing-route-auth");

      // 1. Editing the route while middleware protects it must not add a finding.
      await fs.writeFile(route, "export async function POST() { return Response.json({ ok: false }); }\n");
      const edit = await waitFor(events, (e) => e.type === "change" && (e.files as string[]).includes("src/app/api/admin/route.ts"));
      expect(authFindings(edit)).toHaveLength(0);

      // 2. Weakening the middleware must surface the now-unprotected route.
      await fs.writeFile(middleware, "export function middleware() {}\n");
      const weakened = await waitFor(events, (e) => e.type === "change" && authFindings(e).length > 0);
      expect(authFindings(weakened)[0]).toMatchObject({ file: "src/app/api/admin/route.ts" });

      // 3. Touching package.json triggers a rescan without breaking anything.
      const n = changes().length;
      await fs.writeFile(path.join(dir, "package.json"), '{ "name": "y" }\n');
      await waitFor(events, (e) => e.type === "change" && (e.files as string[]).includes("package.json"));
      expect(changes().length).toBeGreaterThan(n);

      // 4. Deleting the route resolves its finding.
      await fs.rm(route);
      await waitFor(
        events,
        (e) => e.type === "change" && (e.resolved as Array<{ file?: string }>).some((f) => f.file === "src/app/api/admin/route.ts"),
      );
    } finally {
      controller.abort();
      await done;
      await fs.rm(dir, { recursive: true, force: true });
    }
  }, 90000);
});
