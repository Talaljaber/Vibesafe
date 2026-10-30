import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  AttackPersistError,
  assertCanRun,
  atomicWrite,
  loadSavedRun,
  saveReport,
  saveRun,
} from "../src/persist.js";
import type { AttackRun } from "../src/types.js";

function makeRun(mode: AttackRun["mode"], tag = "a"): AttackRun {
  return {
    schemaVersion: 1,
    vibesafeVersion: "0.0.0",
    mode,
    startedAt: tag,
    finishedAt: tag,
    projectPath: ".",
    targetUrl: "x",
    groups: [],
    results: [],
    requestLog: [],
    ledger: { staticFlagged: 0, confirmed: 0, refuted: 0, untested: 0, errors: 0 },
  };
}

let dir: string;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "atk-persist-"));
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});
const vs = (f: string) => path.join(dir, ".vibesafe", f);

describe("persist", () => {
  it("writes .vibesafe/.gitignore with '*', and only if absent", () => {
    saveRun(dir, makeRun("baseline"));
    expect(fs.readFileSync(vs(".gitignore"), "utf8")).toBe("*\n");
    fs.writeFileSync(vs(".gitignore"), "custom\n");
    saveRun(dir, makeRun("retest"));
    expect(fs.readFileSync(vs(".gitignore"), "utf8")).toBe("custom\n");
  });

  it("creates the gitignore before any other file", () => {
    const seen: string[] = [];
    const origWrite = fs.writeFileSync;
    (fs as { writeFileSync: unknown }).writeFileSync = ((f: unknown, ...rest: unknown[]) => {
      seen.push(path.basename(String(f)));
      return (origWrite as (...a: unknown[]) => unknown)(f, ...rest);
    }) as never;
    try {
      saveRun(dir, makeRun("baseline"));
    } finally {
      (fs as { writeFileSync: unknown }).writeFileSync = origWrite;
    }
    expect(seen[0]).toMatch(/^\.gitignore/);
  });

  it("writes baseline and last for a baseline run, only last for a retest", () => {
    const r1 = saveRun(dir, makeRun("baseline", "1"));
    expect(r1.written.map((p) => path.basename(p))).toEqual([
      "attack-baseline.json",
      "attack-last.json",
    ]);
    saveRun(dir, makeRun("retest", "2"));
    expect(loadSavedRun(dir, "baseline")?.startedAt).toBe("1");
    expect(loadSavedRun(dir, "last")?.startedAt).toBe("2");
  });

  it("refuses a plain baseline run when a baseline exists (exit code 2) and writes nothing", () => {
    saveRun(dir, makeRun("baseline", "1"));
    expect(() => saveRun(dir, makeRun("baseline", "2"))).toThrow(AttackPersistError);
    expect(() => assertCanRun(dir, "baseline")).toThrow(
      expect.objectContaining({ exitCode: 2, message: expect.stringContaining("--new-baseline") }),
    );
    expect(loadSavedRun(dir, "baseline")?.startedAt).toBe("1");
    expect(loadSavedRun(dir, "last")?.startedAt).toBe("1");
  });

  it("--new-baseline archives the old baseline first", () => {
    saveRun(dir, makeRun("baseline", "1"));
    const res = saveRun(dir, makeRun("baseline", "2"), {
      newBaseline: true,
      now: new Date("2026-11-01T10:20:30.000Z"),
    });
    expect(path.basename(res.archived ?? "")).toBe("attack-baseline.2026-11-01T10-20-30.000Z.json");
    expect(JSON.parse(fs.readFileSync(res.archived ?? "", "utf8")).startedAt).toBe("1");
    expect(loadSavedRun(dir, "baseline")?.startedAt).toBe("2");
  });

  it("retest without a baseline is refused with exit code 2", () => {
    expect(() => assertCanRun(dir, "retest")).toThrow(/run `vibesafe attack` first/);
    expect(() => saveRun(dir, makeRun("retest"))).toThrow(AttackPersistError);
  });

  it("dry-run writes nothing, not even the directory", () => {
    expect(saveRun(dir, makeRun("dry-run")).written).toEqual([]);
    expect(fs.existsSync(path.join(dir, ".vibesafe"))).toBe(false);
  });

  it("atomic write leaves no temp file and cleans up when rename fails", () => {
    const file = path.join(dir, "f.json");
    atomicWrite(file, "one");
    atomicWrite(file, "two");
    expect(fs.readFileSync(file, "utf8")).toBe("two");
    expect(fs.readdirSync(dir)).toEqual(["f.json"]);
    // rename onto a directory fails: temp file must be cleaned up
    const target = path.join(dir, "sub");
    fs.mkdirSync(target);
    expect(() => atomicWrite(target, "x")).toThrow();
    expect(fs.readdirSync(dir).sort()).toEqual(["f.json", "sub"]);
  });

  it("redacts sensitive request header values but keeps names", () => {
    const run = makeRun("baseline");
    run.groups = [
      {
        attackId: "a",
        checkId: "idor",
        title: "t",
        requests: [
          {
            label: "R3",
            method: "GET",
            host: "target",
            path: "/x",
            headers: { Cookie: "sess=secret1", apikey: "k1", Accept: "json" },
          },
        ],
      },
    ];
    saveRun(dir, run);
    const text = fs.readFileSync(vs("attack-baseline.json"), "utf8");
    expect(text).not.toContain("secret1");
    expect(text).not.toContain("k1");
    expect(text).toContain("Cookie");
    expect(text).toContain("json");
  });

  it("rejects a saved baseline with an unsafe request", () => {
    fs.mkdirSync(path.join(dir, ".vibesafe"));
    const bad = makeRun("baseline");
    bad.groups = [
      {
        attackId: "a",
        checkId: "idor",
        title: "t",
        requests: [{ label: "R0", method: "GET", host: "target", path: "//evil.com" }],
      },
    ];
    fs.writeFileSync(vs("attack-baseline.json"), JSON.stringify(bad));
    expect(() => loadSavedRun(dir, "baseline")).toThrow(AttackPersistError);
  });

  it("wraps filesystem failures in AttackPersistError", () => {
    fs.writeFileSync(path.join(dir, ".vibesafe"), "i am a file");
    expect(() => saveRun(dir, makeRun("baseline"))).toThrow(AttackPersistError);
  });

  it("writes reports atomically into .vibesafe", () => {
    const p = saveReport(dir, "md", "# hi");
    expect(path.basename(p)).toBe("attack-report.md");
    expect(fs.readFileSync(p, "utf8")).toBe("# hi");
    expect(path.basename(saveReport(dir, "html", "<p>"))).toBe("attack-report.html");
    expect(fs.readdirSync(path.join(dir, ".vibesafe")).some((f) => f.endsWith(".tmp"))).toBe(false);
  });

  it("loadSavedRun returns undefined when absent and throws on bad content", () => {
    expect(loadSavedRun(dir)).toBeUndefined();
    fs.mkdirSync(path.join(dir, ".vibesafe"));
    fs.writeFileSync(vs("attack-last.json"), "{nope");
    expect(() => loadSavedRun(dir)).toThrow(/not valid JSON/);
    fs.writeFileSync(vs("attack-last.json"), JSON.stringify({ schemaVersion: 2 }));
    expect(() => loadSavedRun(dir)).toThrow(/schemaVersion/);
  });
});
