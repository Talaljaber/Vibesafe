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

      // Gitignored file must not trigger a change event.
      const before = events.length;
      await fs.writeFile(
        path.join(dir, "ignored.ts"),
        'export const k = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL";\n',
      );
      await new Promise((r) => setTimeout(r, 1500));
      expect(events.slice(before).filter((e) => e.type === "change")).toHaveLength(0);

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
