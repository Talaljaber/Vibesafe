import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";

const pkgRoot = path.resolve(import.meta.dirname, "..");

const FORBIDDEN_MODULES = [
  "http",
  "https",
  "http2",
  "net",
  "tls",
  "dgram",
  "dns",
  "child_process",
  "undici",
  "axios",
  "got",
  "node-fetch",
  "ws",
];
const names = FORBIDDEN_MODULES.flatMap((m) => [m, `node:${m}`]).join("|");
const moduleRe = new RegExp(
  `(?:from\\s*|import\\s*\\(\\s*|require\\s*\\(\\s*|import\\s+)["'](?:${names})(?:/[^"']*)?["']`,
);
const fetchRe = /(?<![\w.$])fetch\s*\(|globalThis\s*\.\s*fetch|\b(?:WebSocket|XMLHttpRequest)\b/;

function walk(dir: string, skipDir: string, out: string[] = []): string[] {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (path.resolve(full) !== path.resolve(skipDir)) walk(full, skipDir, out);
    } else if (/\.(ts|mts|cts|js|mjs|cjs)$/.test(entry.name)) {
      out.push(full);
    }
  }
  return out;
}

/** Returns "<file>: <what>" for every network use found outside `<root>/http`. */
function findViolations(root: string): string[] {
  const violations: string[] = [];
  for (const file of walk(root, path.join(root, "http"))) {
    const text = fs.readFileSync(file, "utf8");
    if (moduleRe.test(text)) violations.push(`${file}: network module`);
    if (fetchRe.test(text)) violations.push(`${file}: fetch or socket global`);
  }
  return violations;
}

describe("network chokepoint", () => {
  it("src has no network use outside src/http", () => {
    expect(fs.existsSync(path.join(pkgRoot, "src"))).toBe(true);
    expect(findViolations(path.join(pkgRoot, "src"))).toEqual([]);
  });

  it("dist has no network use outside dist/http (when built)", () => {
    expect(findViolations(path.join(pkgRoot, "dist"))).toEqual([]);
  });

  it("proves itself: a planted violation is detected, http/ is exempt", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vibesafe-chokepoint-"));
    try {
      fs.mkdirSync(path.join(tmp, "http"));
      fs.writeFileSync(path.join(tmp, "http", "ok.ts"), 'import http from "node:http";\n');
      expect(findViolations(tmp)).toEqual([]);

      const planted: Record<string, string> = {
        "a.ts": 'import https from "node:https";\n',
        "b.ts": 'import { request } from "http";\n',
        "c.ts": 'const r = await fetch("http://127.0.0.1");\n',
        "d.ts": "const r = await globalThis.fetch(u);\n",
        "e.js": 'const n = require("net");\n',
        "f.ts": 'const u = await import("undici");\n',
      };
      for (const [name, body] of Object.entries(planted)) {
        fs.writeFileSync(path.join(tmp, name), body);
      }
      const found = findViolations(tmp);
      for (const name of Object.keys(planted)) {
        expect(
          found.some(
            (v) =>
              v.endsWith(`${path.sep}${name}: network module`) ||
              v.includes(`${path.sep}${name}: fetch`),
          ),
          name,
        ).toBe(true);
      }
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
