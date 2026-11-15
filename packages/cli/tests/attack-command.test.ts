import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { AttackResult, ProbeGroup } from "@talaljaber/vibesafe-attack";
import { evidence, headline, parseRate } from "../src/commands/attack.js";

// Requires `pnpm build` (dist/bin.js).
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(__dirname, "../dist/bin.js");
const DEMO = path.resolve(__dirname, "../../../fixtures/attack-demo-app");

const group: ProbeGroup = {
  attackId: "ATK-df44c1e8a995",
  checkId: "idor",
  title: "One signed-in user can read another user's notes.",
  route: "/api/notes/[id]",
  method: "GET",
  requests: [
    { label: "R0", method: "GET", host: "target", path: "/api/notes/n_bob_1" },
    { label: "R1", method: "GET", host: "target", path: "/api/notes/n_alice_1", session: "alice" },
    { label: "R2", method: "GET", host: "target", path: "/api/notes/n_bob_1", session: "bob" },
    { label: "R3", method: "GET", host: "target", path: "/api/notes/n_bob_1", session: "alice" },
  ],
};
const result: AttackResult = {
  attackId: group.attackId,
  checkId: "idor",
  title: group.title,
  outcome: "CONFIRMED",
  severity: "high",
  route: group.route,
  method: "GET",
  reasoning: "A signed-in user received the same kind of record another user owns.",
  shapes: [
    { label: "R0", status: 401, keys: ["error"] },
    { label: "R2", status: 200, keys: ["id", "title", "user_id"] },
    { label: "R3", status: 200, keys: ["id", "title", "user_id"] },
  ],
  curl: [],
  fixGuidance: "",
  ownerOk: true,
};

describe("attack command output", () => {
  it("names who read whose record", () => {
    expect(headline(result, group)).toBe("Alice read Bob's note.");
    expect(headline({ ...result, severity: "critical" }, group)).toBe(
      "Anyone, logged out, read Bob's note.",
    );
    expect(evidence(result, group)).toEqual([
      "alice → bob's note: 200 (keys: id, title, user_id)",
      "bob → own note: 200 (keys: id, title, user_id)",
      "logged out: 401",
    ]);
  });

  it("does not trust odd session labels or key names", () => {
    const odd: ProbeGroup = {
      ...group,
      requests: group.requests.map((r) =>
        r.label === "R3" ? { ...r, session: "\u001b[31mevil" } : r,
      ),
    };
    expect(headline(result, odd)).toBe("One user read Bob's note.");
    const shapes = [{ label: "R3", status: 200, keys: ["\u001b]0;x\u0007ok"] }];
    // eslint-disable-next-line no-control-regex
    expect(evidence({ ...result, shapes }, group).join("")).not.toMatch(/\u001b/);
  });

  it("parses --rate", () => {
    expect(parseRate(undefined)).toBeUndefined();
    expect(parseRate("2")).toBe(2);
    expect(parseRate("")).toBeNaN();
    expect(parseRate("fast")).toBeNaN();
  });
});

describe("vibesafe attack (built binary)", () => {
  it("lists every flag in --help", () => {
    const res = spawnSync(process.execPath, [BIN, "attack", "--help"], { encoding: "utf-8" });
    expect(res.status).toBe(0);
    for (const flag of [
      "--target",
      "--sessions",
      "--retest",
      "--new-baseline",
      "--dry-run",
      "--replay",
      "--rate",
      "--open-report",
      "--json",
    ]) {
      expect(res.stdout, flag).toContain(flag);
    }
  }, 30000);

  it("exits 2 on conflicting flags and keeps --json stdout empty", () => {
    const res = spawnSync(
      process.execPath,
      [BIN, "attack", DEMO, "--retest", "--new-baseline", "--json"],
      { encoding: "utf-8" },
    );
    expect(res.status).toBe(2);
    expect(res.stdout).toBe("");
    expect(res.stderr).toContain("cannot be used together");
  }, 30000);

  it("exits 2 for a non-loopback target", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vs-attack-cli-"));
    try {
      fs.cpSync(DEMO, dir, { recursive: true });
      const res = spawnSync(
        process.execPath,
        [BIN, "attack", dir, "--target", "http://example.com", "--json"],
        { encoding: "utf-8" },
      );
      expect(res.status).toBe(2);
      expect(res.stdout).toBe("");
      expect(fs.existsSync(path.join(dir, ".vibesafe", "attack-baseline.json"))).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }, 60000);

  it("--dry-run --json prints pure JSON, sends nothing and writes nothing", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vs-attack-cli-"));
    try {
      fs.cpSync(DEMO, dir, { recursive: true });
      const res = spawnSync(process.execPath, [BIN, "attack", dir, "--dry-run", "--json"], {
        encoding: "utf-8",
        maxBuffer: 16 * 1024 * 1024,
      });
      expect(res.status).toBe(0);
      // eslint-disable-next-line no-control-regex
      expect(res.stdout).not.toMatch(/\u001b\[/);
      const run = JSON.parse(res.stdout) as { mode: string; groups: unknown[]; results: unknown[] };
      expect(run.mode).toBe("dry-run");
      expect(run.groups.length).toBeGreaterThanOrEqual(4);
      expect(run.results).toEqual([]);
      expect(fs.existsSync(path.join(dir, ".vibesafe", "attack-last.json"))).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }, 60000);
});
