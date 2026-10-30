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
  "module",
  "worker_threads",
  "vm",
  "inspector",
  "cluster",
];
const names = FORBIDDEN_MODULES.flatMap((m) => [m, `node:${m}`]).join("|");
const moduleRe = new RegExp(`["'\u0060](?:${names})(?:/[^"'\u0060]*)?["'\u0060]`);
const onlineRe =
  /\bOsvDetector\b|\bPackageExistenceDetector\b|\bonline\s*:\s*(?:true\b|[^\s,}]*(?:\bonline\b|Online))/;
const fetchRe =
  /(?<![\w$])fetch\s*\(|\bfetch\s*:|["'\u0060]fetch["'\u0060]|(?:globalThis|global|self|window)\s*\.\s*fetch|\b(?:WebSocket|XMLHttpRequest|createRequire|getBuiltinModule)\b|process\s*\.\s*binding/;

function walk(dir: string, skipDir: string, out: string[] = []): string[] {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (path.resolve(full) !== path.resolve(skipDir)) walk(full, skipDir, out);
    } else if (/\.(ts|tsx|mts|cts|js|mjs|cjs)$/.test(entry.name)) {
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
    if (onlineRe.test(text)) violations.push(`${file}: online core scan`);
  }
  return violations;
}

describe("network chokepoint", () => {
  it("src has no network use outside src/http", () => {
    expect(fs.existsSync(path.join(pkgRoot, "src"))).toBe(true);
    expect(findViolations(path.join(pkgRoot, "src"))).toEqual([]);
  });

  it.skipIf(!fs.existsSync(path.join(pkgRoot, "dist")))(
    "dist has no network use outside dist/http",
    () => {
      expect(findViolations(path.join(pkgRoot, "dist"))).toEqual([]);
    },
  );

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
        "g.ts": "const r = await global.fetch(u);\n",
        "h.ts": "const { fetch: f } = globalThis;\n",
        "i.ts": 'import { createRequire } from "node:module";\n',
        "j.ts": 'const m = process.getBuiltinModule("node:tls");\n',
        "k.ts": "const u = await import(`node:http`);\n",
        "l.tsx": 'const r = await globalThis["fetch"](u);\n',
        "m.ts": 'import inspector from "node:inspector";\n',
        "n.ts": 'import cluster from "cluster";\n',
        "o.ts": "const d = new OsvDetector();\n",
        "p.ts": "const d = new PackageExistenceDetector();\n",
        "q.ts": "await scan({ projectPath, online: true });\n",
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
              v.includes(`${path.sep}${name}: fetch`) ||
              v.endsWith(`${path.sep}${name}: online core scan`),
          ),
          name,
        ).toBe(true);
      }
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe("package manifest allowlist", () => {
  it("dependencies and peerDependencies stay within core and shared", () => {
    const manifest = JSON.parse(
      fs.readFileSync(path.join(pkgRoot, "package.json"), "utf8"),
    ) as Record<string, Record<string, string> | undefined>;
    const allowed = new Set(["@talaljaber/vibesafe-core", "@talaljaber/vibesafe-shared"]);
    for (const field of ["dependencies", "peerDependencies", "optionalDependencies"]) {
      const extra = Object.keys(manifest[field] ?? {}).filter((d) => !allowed.has(d));
      expect(extra, field).toEqual([]);
    }
  });
});

describe("online scans are never started from attack", () => {
  it("online-core patterns trip the structural check", () => {
    expect(onlineRe.test("new OsvDetector()")).toBe(true);
    expect(onlineRe.test("scan({ online: true })")).toBe(true);
    expect(onlineRe.test("online: opts.online")).toBe(true);
    expect(onlineRe.test("online: false")).toBe(false);
  });
});
