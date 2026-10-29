import { describe, it, expect, vi, afterEach } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { OsvDetector, OSV_QUERYBATCH_URL } from "../../src/detectors/osv-detector.js";
import { expectRubric } from "../helpers/rubric.js";

interface Call {
  url: string;
  body: { queries: { package: { name: string; ecosystem: string }; version: string }[] };
  signal: AbortSignal;
}

function createContext(
  files: Record<string, string>,
  online: boolean | undefined,
  warnings: string[] = [],
): ScanContext {
  return {
    rootPath: "/fake/path",
    projectContext: {} as ScanContext["projectContext"],
    files: Object.keys(files),
    config: { rootPath: "/fake/path", ...(online !== undefined ? { online } : {}) },
    readFile: async (file) => files[file] ?? "",
    addWarning: (m) => warnings.push(m),
  };
}

const manifest = JSON.stringify(
  {
    name: "app",
    dependencies: { express: "4.21.0", react: "^18.2.0", lodash: "4.17.15", local: "file:../x" },
  },
  null,
  2,
);
const lock = JSON.stringify(
  {
    lockfileVersion: 3,
    packages: {
      "": {},
      "node_modules/express": { version: "4.21.0" },
      "node_modules/react": { version: "18.2.0" },
      "node_modules/lodash": { version: "4.17.15" },
      "node_modules/body-parser": { version: "1.20.1" },
    },
  },
  null,
  2,
);

function mockFetch(respond: (call: Call) => unknown, status = 200) {
  const calls: Call[] = [];
  const fn = vi.fn(async (url: string, init: { body: string; signal: AbortSignal }) => {
    const call = { url, body: JSON.parse(init.body), signal: init.signal } as Call;
    calls.push(call);
    return { ok: status === 200, status, json: async () => respond(call) };
  });
  return { fn, calls };
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("OsvDetector", () => {
  it("does nothing (and makes no request) unless config.online is exactly true", async () => {
    const { fn } = mockFetch(() => ({ results: [] }));
    const detector = new OsvDetector(fn);
    for (const online of [undefined, false]) {
      expect(await detector.detect(createContext({ "package.json": manifest }, online))).toEqual(
        [],
      );
    }
    expect(fn).not.toHaveBeenCalled();
  });

  it("sends only npm package names and versions, and reports vulnerable ones", async () => {
    const { fn, calls } = mockFetch((call) => ({
      results: call.body.queries.map((q) =>
        q.package.name === "express"
          ? { vulns: [{ id: "GHSA-qw6h-vgh9-j6wx", modified: "x" }, { id: "GHSA-rv95-896h-c2vc" }] }
          : q.package.name === "body-parser"
            ? { vulns: [{ id: "GHSA-qwcr-r2fm-qrc7" }] }
            : {},
      ),
    }));
    const warnings: string[] = [];
    const findings = await new OsvDetector(fn).detect(
      createContext({ "package.json": manifest, "package-lock.json": lock }, true, warnings),
    );
    expectRubric(findings);

    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe(OSV_QUERYBATCH_URL);
    const queries = calls[0]!.body.queries;
    // Exactly { package: { name, ecosystem }, version } per query: no paths, no file contents.
    for (const q of queries) {
      expect(Object.keys(q).sort()).toEqual(["package", "version"]);
      expect(Object.keys(q.package).sort()).toEqual(["ecosystem", "name"]);
      expect(q.package.ecosystem).toBe("npm");
    }
    const sent = queries.map((q) => `${q.package.name}@${q.version}`).sort();
    // lodash 4.17.15 is already reported by the offline list, `local` is not a registry version.
    expect(sent).toEqual(["body-parser@1.20.1", "express@4.21.0", "react@18.2.0"]);

    const express = findings.find((f) => f.title.startsWith("express"))!;
    expect(express.ruleId).toBe("dependency/osv-advisory");
    expect(express.file).toBe("package.json");
    expect(express.line).toBe(4);
    expect(express.severity).toBe("medium");
    expect(express.evidence).toContain("GHSA-qw6h-vgh9-j6wx");
    const bodyParser = findings.find((f) => f.title.startsWith("body-parser"))!;
    expect(bodyParser.file).toBe("package-lock.json");
    expect(bodyParser.severity).toBe("low");
    expect(findings).toHaveLength(2);
    expect(warnings.join("\n")).toContain("sent 3 package name/version pair(s)");
  });

  it("queries nested copies of a direct dependency, but not its own resolved version twice", async () => {
    const nestedLock = JSON.stringify(
      {
        lockfileVersion: 3,
        packages: {
          "": {},
          "node_modules/react": { version: "18.2.0" },
          "node_modules/old-lib/node_modules/react": { version: "16.4.0" },
          "node_modules/old-lib": { version: "1.0.0" },
        },
      },
      null,
      2,
    );
    const { fn, calls } = mockFetch((call) => ({
      results: call.body.queries.map((q) =>
        q.package.name === "react" && q.version === "16.4.0"
          ? { vulns: [{ id: "GHSA-mvjj-gqq2-p4hw" }] }
          : {},
      ),
    }));
    const findings = await new OsvDetector(fn).detect(
      createContext(
        {
          "package.json": JSON.stringify({ dependencies: { react: "^18.2.0" } }, null, 2),
          "package-lock.json": nestedLock,
        },
        true,
      ),
    );
    expectRubric(findings);
    const sent = calls[0]!.body.queries.map((q) => `${q.package.name}@${q.version}`).sort();
    expect(sent).toEqual(["old-lib@1.0.0", "react@16.4.0", "react@18.2.0"]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.file).toBe("package-lock.json");
    expect(findings[0]!.title).toContain("react 16.4.0");
    expect(findings[0]!.severity).toBe("low");
  });

  it("turns HTTP errors, bad JSON shapes and network failures into a warning", async () => {
    const cases = [
      mockFetch(() => ({ results: [] }), 503).fn,
      mockFetch(() => ({ nope: true })).fn,
      vi.fn(async () => {
        throw new Error("getaddrinfo ENOTFOUND api.osv.dev");
      }),
    ];
    for (const fn of cases) {
      const warnings: string[] = [];
      const findings = await new OsvDetector(fn).detect(
        createContext({ "package.json": manifest }, true, warnings),
      );
      expect(findings).toEqual([]);
      expect(warnings.some((w) => w.includes("Online advisory lookup (OSV) failed"))).toBe(true);
    }
  });

  it("aborts after 5 seconds and reports a timeout", async () => {
    vi.useFakeTimers();
    const fn = vi.fn(
      (_url: string, init: { signal: AbortSignal }) =>
        new Promise<never>((_resolve, reject) => {
          init.signal.addEventListener("abort", () => reject(new Error("aborted")));
        }),
    );
    const warnings: string[] = [];
    const pending = new OsvDetector(fn).detect(
      createContext({ "package.json": manifest }, true, warnings),
    );
    // Let the detector read its files and start the request before the clock moves.
    for (let i = 0; i < 100 && fn.mock.calls.length === 0; i++) await Promise.resolve();
    expect(fn).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(4_999);
    expect(fn.mock.calls[0]![1].signal.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(await pending).toEqual([]);
    expect(warnings.join("\n")).toContain("timed out after 5s");
  });

  it("ignores malformed advisory ids from the response", async () => {
    const { fn } = mockFetch((call) => ({
      results: call.body.queries.map(() => ({ vulns: [{ id: "\u001b[31mevil" }, { id: 42 }] })),
    }));
    const findings = await new OsvDetector(fn).detect(
      createContext({ "package.json": manifest }, true),
    );
    expect(findings).toEqual([]);
  });

  it("uses the global fetch when none is injected", async () => {
    const { fn, calls } = mockFetch((call) => ({ results: call.body.queries.map(() => ({})) }));
    vi.stubGlobal("fetch", fn);
    await new OsvDetector().detect(createContext({ "package.json": manifest }, true));
    expect(calls).toHaveLength(1);
  });

  it("makes no request when there is nothing with a concrete version", async () => {
    const { fn } = mockFetch(() => ({ results: [] }));
    const findings = await new OsvDetector(fn).detect(
      createContext({ "package.json": JSON.stringify({ dependencies: { a: "^1.0.0" } }) }, true),
    );
    expect(findings).toEqual([]);
    expect(fn).not.toHaveBeenCalled();
  });
});
