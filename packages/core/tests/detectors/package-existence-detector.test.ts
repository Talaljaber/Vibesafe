import { describe, it, expect, vi, afterEach } from "vitest";
import type { Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import {
  PackageExistenceDetector,
  BULK_DOWNLOADS,
  CONCURRENCY,
  OVERALL_DEADLINE_MS,
  REQUEST_TIMEOUT_MS,
} from "../../src/detectors/package-existence-detector.js";
import type { FetchLike } from "../../src/detectors/utils/package-registry.js";
import { KNOWN_TYPOSQUATS } from "../../src/detectors/patterns/npm-typosquats.js";
import { depsPrecedence } from "../../src/detectors/groups/deps.js";
import { applyPrecedence } from "../../src/scanner/precedence.js";
import { expectRubric } from "../helpers/rubric.js";

const NOW = Date.parse("2026-10-30T00:00:00Z");
const DAY = 86_400_000;
const iso = (daysAgo: number): string => new Date(NOW - daysAgo * DAY).toISOString();

type Route = { status: number; body?: unknown } | "hang";

function context(
  files: Record<string, string>,
  online: boolean | "unset" = true,
  warnings: string[] = [],
  targetFiles?: string[],
): ScanContext {
  return {
    rootPath: "/fake/path",
    projectContext: {} as ScanContext["projectContext"],
    files: targetFiles ?? Object.keys(files),
    config: { rootPath: "/fake/path", ...(online !== "unset" ? { online } : {}) },
    readFile: async (file) => files[file] ?? "",
    addWarning: (m) => warnings.push(m),
  };
}

function mockFetch(route: (url: string) => Route | undefined) {
  const calls: string[] = [];
  let inFlight = 0;
  let peak = 0;
  const inits: { method: string; headers: Record<string, string>; body?: unknown }[] = [];
  const fn: FetchLike = async (url, init) => {
    calls.push(url);
    inits.push(init as never);
    inFlight++;
    peak = Math.max(peak, inFlight);
    try {
      const r = route(url) ?? { status: 404 };
      if (r === "hang") {
        await new Promise<never>(() => undefined);
      }
      const res = r as { status: number; body?: unknown };
      await Promise.resolve();
      return {
        ok: res.status >= 200 && res.status < 300,
        status: res.status,
        json: async () => res.body,
      };
    } finally {
      inFlight--;
    }
  };
  return { fn, calls, inits, peak: () => peak };
}

const pkg = (deps: Record<string, string>, extra: Record<string, unknown> = {}): string =>
  JSON.stringify({ name: "app", dependencies: deps, ...extra }, null, 2);

const DL = "https://api.npmjs.org/downloads/point/last-week/";
const REG = "https://registry.npmjs.org/";

/** Route helper: downloads and packuments from small tables. */
function npmRoutes(opts: {
  downloads?: Record<string, number | null>;
  packuments?: Record<string, Route>;
  latest?: Record<string, Route>;
}): (url: string) => Route | undefined {
  return (url) => {
    if (url.startsWith(DL)) {
      const names = decodeURIComponent(url.slice(DL.length)).split(",");
      if (names.length === 1 && names[0]!.startsWith("@")) {
        const d = opts.downloads?.[names[0]!];
        return d == null
          ? { status: 404, body: { error: "not found" } }
          : { status: 200, body: { downloads: d } };
      }
      if (names.length === 1) {
        const d = opts.downloads?.[names[0]!];
        return d == null
          ? { status: 404, body: { error: "not found" } }
          : { status: 200, body: { downloads: d } };
      }
      const body: Record<string, unknown> = {};
      for (const n of names) {
        const d = opts.downloads?.[n];
        body[n] = d == null ? null : { downloads: d, package: n };
      }
      return { status: 200, body };
    }
    if (url.endsWith("/latest")) {
      return (
        opts.latest?.[decodeURIComponent(url.slice(REG.length, -"/latest".length))] ?? {
          status: 200,
          body: { version: "1.0.0" },
        }
      );
    }
    if (url.startsWith(REG))
      return opts.packuments?.[decodeURIComponent(url.slice(REG.length))] ?? { status: 404 };
    return undefined;
  };
}

const detect = async (
  files: Record<string, string>,
  route: (url: string) => Route | undefined,
  warnings: string[] = [],
) => {
  const m = mockFetch(route);
  const findings = await new PackageExistenceDetector(m.fn, () => NOW).detect(
    context(files, true, warnings),
  );
  return { findings, ...m };
};

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("PackageExistenceDetector: npm positives", () => {
  it("reports an unknown unscoped package as not-found high/high at its line", async () => {
    const files = { "package.json": pkg({ "leftpadx-ai-helper": "^1.0.0", react: "^18.0.0" }) };
    const { findings, calls } = await detect(files, npmRoutes({ downloads: {} }));
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.ruleId).toBe("dependency/package-not-found");
    expect(f.severity).toBe("high");
    expect(f.confidence).toBe("high");
    expect(f.title).toContain("does not exist on npm");
    expect(f.file).toBe("package.json");
    expect(f.line).toBe(4);
    expect(f.evidence).toContain("leftpadx-ai-helper");
    expect(f.autoFixAvailable).toBe(false);
    expectRubric(findings);
    expect(calls.some((u) => u.includes("react"))).toBe(false);
  });

  it("reports a scoped unknown package using the single downloads endpoint and the %2f packument", async () => {
    const files = { "package.json": pkg({ "@acme-ai/magic": "1.0.0" }) };
    const { findings, calls } = await detect(files, npmRoutes({}));
    expect(findings.map((f) => f.ruleId)).toEqual(["dependency/package-not-found"]);
    expect(calls).toContain(`${DL}@acme-ai/magic`);
    expect(calls).toContain(`${REG}@acme-ai%2fmagic`);
  });

  it("titles a 404 for a lockfile package as removed from npm", async () => {
    const files = {
      "package.json": pkg({ "leftpadx-ai-helper": "^1.0.0" }),
      "package-lock.json": JSON.stringify({
        lockfileVersion: 3,
        packages: { "": {}, "node_modules/leftpadx-ai-helper": { version: "1.0.3" } },
      }),
    };
    const { findings } = await detect(files, npmRoutes({}));
    expect(findings[0]!.title).toContain("was removed from npm");
    expect(findings[0]!.plainEnglishProblem).toContain("malware");
  });

  it("treats an unpublished package as removed", async () => {
    const files = { "package.json": pkg({ "leftpadx-ai-helper": "^1.0.0" }) };
    const { findings } = await detect(
      files,
      npmRoutes({
        downloads: { "leftpadx-ai-helper": 3 },
        packuments: {
          "leftpadx-ai-helper": {
            status: 200,
            body: { time: { created: iso(900), unpublished: { time: iso(2) } } },
          },
        },
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe("dependency/package-not-found");
    expect(findings[0]!.title).toContain("was removed from npm");
  });

  it("reports a 5 day old package with 12 downloads as very-new medium/medium", async () => {
    const files = { "package.json": pkg({ "leftpadx-ai-helper": "^1.0.0" }) };
    const { findings } = await detect(
      files,
      npmRoutes({
        downloads: { "leftpadx-ai-helper": 12 },
        packuments: { "leftpadx-ai-helper": { status: 200, body: { time: { created: iso(5) } } } },
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "dependency/package-very-new",
      severity: "medium",
      confidence: "medium",
    });
    expect(findings[0]!.plainEnglishProblem).toContain("5 days ago");
    expect(findings[0]!.plainEnglishProblem).toContain("12 weekly downloads");
  });

  it("counts unknown downloads as zero for very-new", async () => {
    const files = { "package.json": pkg({ "leftpadx-ai-helper": "^1.0.0" }) };
    const { findings } = await detect(
      files,
      npmRoutes({
        downloads: {},
        packuments: { "leftpadx-ai-helper": { status: 200, body: { time: { created: iso(5) } } } },
      }),
    );
    expect(findings.map((f) => f.ruleId)).toEqual(["dependency/package-very-new"]);
  });

  it("reports a security placeholder with few downloads as removed, even outside the lockfile", async () => {
    const files = { "package.json": pkg({ "leftpadx-ai-helper": "^1.0.0" }) };
    const { findings } = await detect(
      files,
      npmRoutes({
        downloads: { "leftpadx-ai-helper": 3 },
        packuments: {
          "leftpadx-ai-helper": {
            status: 200,
            body: {
              "dist-tags": { latest: "0.0.1-security" },
              description: "security holding package",
              time: { created: iso(2000) },
            },
          },
        },
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "dependency/package-not-found",
      severity: "high",
      confidence: "high",
    });
    expect(findings[0]!.title).toContain("was removed from npm");
  });

  it("checks /latest (not the packument) for a security placeholder that kept its traffic", async () => {
    const files = { "package.json": pkg({ "leftpadx-ai-helper": "^1.0.0" }) };
    const { findings, calls } = await detect(
      files,
      npmRoutes({
        downloads: { "leftpadx-ai-helper": 40000 },
        latest: { "leftpadx-ai-helper": { status: 200, body: { version: "0.0.1-security" } } },
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.title).toContain("was removed from npm");
    expect(calls).toContain(`${REG}leftpadx-ai-helper/latest`);
    expect(calls).not.toContain(`${REG}leftpadx-ai-helper`);
  });

  it("queries the target of an npm: alias and anchors at the alias line", async () => {
    const files = { "package.json": pkg({ "ui-kit": "npm:leftpadx-ai-helper@^1.0.0" }) };
    const { findings, calls } = await detect(files, npmRoutes({}));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.title).toContain("leftpadx-ai-helper");
    expect(findings[0]!.line).toBe(4);
    expect(findings[0]!.evidence).toContain("ui-kit");
    expect(calls.some((u) => u.includes("ui-kit"))).toBe(false);
  });
});

describe("PackageExistenceDetector: npm silent cases", () => {
  it("does nothing, and never calls fetch, unless online is exactly true", async () => {
    const m = mockFetch(() => ({ status: 404 }));
    const globalFetch = vi.fn();
    vi.stubGlobal("fetch", globalFetch);
    const files = {
      "package.json": pkg({ "leftpadx-ai-helper": "^1.0.0" }),
      "requirements.txt": "fastapi-auth-magic==0.1.0\n",
    };
    for (const online of ["unset", false] as const) {
      expect(
        await new PackageExistenceDetector(m.fn, () => NOW).detect(context(files, online)),
      ).toEqual([]);
      expect(await new PackageExistenceDetector().detect(context(files, online))).toEqual([]);
    }
    expect(m.calls).toEqual([]);
    expect(globalFetch).not.toHaveBeenCalled();
  });

  it("skips workspace:, file:, link:, git, github and url specs", async () => {
    const files = {
      "package.json": pkg({
        "@acme/ui": "workspace:*",
        "acme-x": "file:../x",
        "acme-y": "link:../y",
        "acme-z": "github:acme/z",
        "acme-w": "https://example.com/w.tgz",
        "acme-v": "catalog:",
      }),
    };
    const { findings, calls } = await detect(files, npmRoutes({}));
    expect(findings).toEqual([]);
    expect(calls).toEqual([]);
  });

  it("does not query names declared by a scanned package.json (workspaces without the protocol)", async () => {
    const files = {
      "package.json": pkg({ "@acme/ui": "^1.0.0" }),
      "packages/ui/package.json": JSON.stringify({ name: "@acme/ui", version: "1.0.0" }),
    };
    const { findings, calls } = await detect(files, npmRoutes({}));
    expect(findings).toEqual([]);
    expect(calls).toEqual([]);
  });

  it("skips private scopes from .npmrc and skips whole manifests under a private default registry", async () => {
    const scoped = {
      "package.json": pkg({ "@acme/ui": "^1.0.0" }),
      ".npmrc": "@acme:registry=https://npm.acme.dev/\n",
    };
    const r1 = await detect(scoped, npmRoutes({}));
    expect(r1.findings).toEqual([]);
    expect(r1.calls).toEqual([]);

    const warnings: string[] = [];
    const priv = {
      "package.json": pkg({ "leftpadx-ai-helper": "^1.0.0" }),
      ".npmrc": "registry=https://npm.acme.dev/\n",
    };
    const r2 = await detect(priv, npmRoutes({}), warnings);
    expect(r2.findings).toEqual([]);
    expect(r2.calls).toEqual([]);
    expect(
      warnings.some((w) => w.includes("skipped `package.json`") && w.includes("private registry")),
    ).toBe(true);
  });

  it("stays silent for a scoped 404 when the lockfile resolves it from the default registry (private org package)", async () => {
    const files = {
      "package.json": pkg({ "@acmeprobe-co/design-tokens": "^1.0.0" }),
      "package-lock.json": JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": {},
          "node_modules/@acmeprobe-co/design-tokens": {
            version: "1.2.0",
            resolved: "https://registry.npmjs.org/@acmeprobe-co/design-tokens/-/dt-1.2.0.tgz",
          },
        },
      }),
    };
    const { findings } = await detect(files, npmRoutes({}));
    expect(findings).toEqual([]);
  });

  it("still reports an unscoped lockfile package that got a 404, and a scoped one with no lockfile at medium confidence", async () => {
    const unscoped = await detect(
      {
        "package.json": pkg({ "leftpadx-ai-helper": "^1.0.0" }),
        "package-lock.json": JSON.stringify({
          lockfileVersion: 3,
          packages: { "": {}, "node_modules/leftpadx-ai-helper": { version: "1.0.3" } },
        }),
      },
      npmRoutes({}),
    );
    expect(unscoped.findings).toHaveLength(1);
    const scoped = await detect(
      { "package.json": pkg({ "@acme-ai/magic": "1.0.0" }) },
      npmRoutes({}),
    );
    expect(scoped.findings).toHaveLength(1);
    expect(scoped.findings[0]!.confidence).toBe("medium");
    expect(scoped.findings[0]!.plainEnglishProblem).toContain("private package");
  });

  it("skips scopes and defaults whose registry is an unresolved env placeholder", async () => {
    const npmrc = await detect(
      {
        "package.json": pkg({ "@acmeprobe/ui-kit": "^1.0.0" }),
        ".npmrc": "@acmeprobe:registry=${ACME_REGISTRY_URL}\n",
      },
      npmRoutes({}),
    );
    expect(npmrc.findings).toEqual([]);
    expect(npmrc.calls).toEqual([]);
    const yarnrc = await detect(
      {
        "package.json": pkg({ "@acmeprobe/ui-kit": "^1.0.0" }),
        ".yarnrc.yml": "npmScopes:\n  acmeprobe:\n    npmRegistryServer: ${ACME_REGISTRY_URL}\n",
      },
      npmRoutes({}),
    );
    expect(yarnrc.findings).toEqual([]);
    expect(yarnrc.calls).toEqual([]);
  });

  it("reads .yarnrc.yml from a parent directory", async () => {
    const files = {
      "apps/web/package.json": pkg({ "@acme/ui": "^1.0.0" }),
      ".yarnrc.yml": 'npmScopes:\n  acme:\n    npmRegistryServer: "https://npm.acme.dev"\n',
    };
    const { findings, calls } = await detect(files, npmRoutes({}));
    expect(findings).toEqual([]);
    expect(calls).toEqual([]);
  });

  it("skips packages the lockfile resolves from a non-default registry", async () => {
    const files = {
      "package.json": pkg({ "internal-lib": "^1.0.0" }),
      "package-lock.json": JSON.stringify(
        {
          packages: {
            "node_modules/internal-lib": {
              version: "1.0.0",
              resolved: "https://npm.pkg.github.com/download/internal-lib-1.0.0.tgz",
            },
          },
        },
        null,
        2,
      ),
    };
    const { findings, calls } = await detect(files, npmRoutes({}));
    expect(findings).toEqual([]);
    expect(calls).toEqual([]);
  });

  it("never queries popular packages, known typosquats or near-misses of popular names", async () => {
    const [typosquat] = Object.keys(KNOWN_TYPOSQUATS);
    const files = {
      "package.json": pkg({
        react: "^18.0.0",
        next: "14.0.0",
        express: "^4.18.0",
        [typosquat!]: "1.0.0",
        expresss: "^1.0.0",
        lodahs: "^1.0.0",
        axioos: "^1.0.0",
      }),
    };
    const { findings, calls } = await detect(files, npmRoutes({}));
    expect(findings).toEqual([]);
    expect(calls).toEqual([]);
  });

  it("stays silent for an old low-traffic package and a new but busy one", async () => {
    const files = { "package.json": pkg({ "acme-old-lib": "^1.0.0", "acme-new-busy": "^1.0.0" }) };
    const { findings, calls } = await detect(
      files,
      npmRoutes({
        downloads: { "acme-old-lib": 40, "acme-new-busy": 50000 },
        packuments: { "acme-old-lib": { status: 200, body: { time: { created: iso(1100) } } } },
      }),
    );
    expect(findings).toEqual([]);
    expect(calls).not.toContain(`${REG}acme-new-busy`);
  });

  it("stays silent for a busy package whose description merely mentions security", async () => {
    const files = { "package.json": pkg({ "acme-sec-headers": "^1.0.0" }) };
    const { findings } = await detect(
      files,
      npmRoutes({
        downloads: { "acme-sec-headers": 9000 },
        latest: {
          "acme-sec-headers": {
            status: 200,
            body: { version: "2.0.0", description: "Security headers for Express" },
          },
        },
      }),
    );
    expect(findings).toEqual([]);
  });

  it("never reports from a downloads 404 alone", async () => {
    const files = { "package.json": pkg({ "acme-old-lib": "^1.0.0" }) };
    const { findings } = await detect(
      files,
      npmRoutes({
        packuments: { "acme-old-lib": { status: 200, body: { time: { created: iso(1100) } } } },
      }),
    );
    expect(findings).toEqual([]);
  });

  it.each([
    ["HTTP 500", { status: 500 }],
    ["HTTP 429", { status: 429 }],
    ["malformed JSON", { status: 200, body: "not json at all" }],
  ] as [string, Route][])("degrades to one warning on %s", async (_name, bad) => {
    const warnings: string[] = [];
    const files = {
      "package.json": pkg({ "leftpadx-ai-helper": "^1.0.0", "acme-two-lib": "^1.0.0" }),
    };
    const { findings } = await detect(files, () => bad, warnings);
    expect(findings).toEqual([]);
    expect(warnings.filter((w) => w.includes("(npm) failed"))).toHaveLength(1);
  });

  it("degrades on a thrown network error without throwing", async () => {
    const warnings: string[] = [];
    const fn: FetchLike = async () => {
      throw new Error("getaddrinfo ENOTFOUND");
    };
    const files = {
      "package.json": pkg({ "leftpadx-ai-helper": "^1.0.0" }),
      "requirements.txt": "fastapi-auth-magic==0.1.0\n",
    };
    const findings = await new PackageExistenceDetector(fn, () => NOW).detect(
      context(files, true, warnings),
    );
    expect(findings).toEqual([]);
    expect(warnings.some((w) => w.includes("failed"))).toBe(true);
  });

  it("never throws when readFile rejects", async () => {
    const ctx = context({ "package.json": "" });
    ctx.readFile = async () => {
      throw new Error("boom");
    };
    expect(await new PackageExistenceDetector(mockFetch(() => undefined).fn).detect(ctx)).toEqual(
      [],
    );
  });

  it("scans only the requested manifests when targetFiles narrows the context to a single file", async () => {
    const files = {
      "package.json": pkg({ "leftpadx-ai-helper": "^1.0.0" }),
      "other/package.json": pkg({ "acme-other-missing": "^1.0.0" }),
    };
    const m = mockFetch(npmRoutes({}));
    const findings = await new PackageExistenceDetector(m.fn, () => NOW).detect(
      context(files, true, [], ["package.json"]),
    );
    expect(findings.map((f) => f.file)).toEqual(["package.json"]);
    expect(m.calls.some((u) => u.includes("acme-other-missing"))).toBe(false);
  });
});

describe("PackageExistenceDetector: PyPI", () => {
  const pypi =
    (routes: Record<string, Route>) =>
    (url: string): Route | undefined =>
      url.startsWith("https://pypi.org/pypi/") ? (routes[url] ?? { status: 404 }) : undefined;

  it("reports a missing PyPI package at its requirements line", async () => {
    const { findings } = await detect(
      { "requirements.txt": "flask==3.0.0\nfastapi-auth-magic==0.1.0\n" },
      pypi({
        "https://pypi.org/pypi/flask/json": {
          status: 200,
          body: { releases: { "3.0.0": [{ upload_time_iso_8601: iso(900) }] } },
        },
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "dependency/package-not-found",
      line: 2,
      severity: "high",
      confidence: "high",
    });
    expect(findings[0]!.title).toContain("does not exist on PyPI");
    expectRubric(findings);
  });

  it("reports a week-old single-release package as very-new medium/low", async () => {
    const { findings } = await detect(
      { "requirements.txt": "fastapi-auth-magic==0.1.0\n" },
      pypi({
        "https://pypi.org/pypi/fastapi-auth-magic/json": {
          status: 200,
          body: { releases: { "0.1.0": [{ upload_time_iso_8601: iso(7) }] } },
        },
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "dependency/package-very-new",
      severity: "medium",
      confidence: "low",
    });
  });

  it("reports a package with no release files as not-found", async () => {
    const { findings } = await detect(
      { "requirements.txt": "fastapi-auth-magic==0.1.0\n" },
      pypi({
        "https://pypi.org/pypi/fastapi-auth-magic/json": {
          status: 200,
          body: { releases: { "0.1.0": [] } },
        },
      }),
    );
    expect(findings.map((f) => f.ruleId)).toEqual(["dependency/package-not-found"]);
  });

  it("normalises names, dedupes across files and keeps the first file", async () => {
    const files = {
      "requirements.txt": "Fastapi_Auth.Magic==0.1.0\n",
      "pyproject.toml": '[project]\ndependencies = [\n  "fastapi-auth-magic>=0.1",\n]\n',
    };
    const { findings, calls } = await detect(files, pypi({}));
    expect(calls).toEqual(["https://pypi.org/pypi/fastapi-auth-magic/json"]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.file).toBe("requirements.txt");
    expect(findings[0]!.title).toContain("Fastapi_Auth.Magic");
  });

  it("uses the minimum upload time across every file and release", async () => {
    const url = "https://pypi.org/pypi/fastapi-auth-magic/json";
    const old = await detect(
      { "requirements.txt": "fastapi-auth-magic==0.2.0\n" },
      pypi({
        [url]: {
          status: 200,
          body: {
            releases: {
              "0.1.0": [{ upload_time_iso_8601: iso(400) }],
              "0.2.0": [{ upload_time_iso_8601: iso(5) }],
            },
          },
        },
      }),
    );
    expect(old.findings).toEqual([]);
    const fresh = await detect(
      { "requirements.txt": "fastapi-auth-magic==0.2.0\n" },
      pypi({
        [url]: {
          status: 200,
          body: { releases: { "0.1.0": [], "0.2.0": [{ upload_time_iso_8601: iso(5) }] } },
        },
      }),
    );
    expect(fresh.findings.map((f) => f.ruleId)).toEqual(["dependency/package-very-new"]);
  });

  it("skips a requirements file with a custom index, and URL or editable requirements", async () => {
    const warnings: string[] = [];
    const files = {
      "requirements.txt": "--index-url https://pypi.acme.dev/simple\nfastapi-auth-magic==0.1.0\n",
      "requirements-dev.txt":
        "-e git+https://example.com/x.git#egg=x\nacme-lib @ https://example.com/acme-lib.tar.gz\n",
    };
    const { findings, calls } = await detect(files, pypi({}), warnings);
    expect(findings).toEqual([]);
    expect(calls).toEqual([]);
    expect(warnings.some((w) => w.includes("custom package index"))).toBe(true);
  });

  it("skips pyproject sources and Pipfile sources that are not public PyPI", async () => {
    const files = {
      "pyproject.toml":
        '[tool.poetry.dependencies]\nacme-private = "^1.0"\n\n[[tool.poetry.source]]\nname = "acme"\nurl = "https://pypi.acme.dev/simple"\n',
      Pipfile:
        '[[source]]\nurl = "https://pypi.acme.dev/simple"\nname = "acme"\n\n[packages]\nacme-private = "*"\n',
    };
    const { findings, calls } = await detect(files, pypi({}));
    expect(findings).toEqual([]);
    expect(calls).toEqual([]);
    const pub = await detect(
      {
        Pipfile:
          '[[source]]\nurl = "https://pypi.org/simple"\nname = "pypi"\n\n[packages]\nacme-private = "*"\n',
      },
      pypi({}),
    );
    expect(pub.findings).toHaveLength(1);
  });

  it("never sends PEP 735 include-group names to PyPI, but still checks real packages", async () => {
    const files = {
      "pyproject.toml":
        '[project]\nname = "app"\n\n[dependency-groups]\ntest = ["acme-testkit"]\ndev = [{ include-group = "test" }, "acme-lintkit"]\nci = [\n  { include-group = "lint" },\n  "acme-covkit",\n]\n',
    };
    const { calls } = await detect(files, pypi({}));
    expect(calls).toContain("https://pypi.org/pypi/acme-lintkit/json");
    expect(calls).toContain("https://pypi.org/pypi/acme-testkit/json");
    expect(calls).toContain("https://pypi.org/pypi/acme-covkit/json");
    expect(calls).not.toContain("https://pypi.org/pypi/test/json");
    expect(calls).not.toContain("https://pypi.org/pypi/lint/json");
  });

  it("skips offline and local-wheel installs and legacy uv index keys", async () => {
    const cases: Record<string, string>[] = [
      { "requirements.txt": "--no-index\nacme-internal==1.0\n" },
      { "requirements.txt": "-f ./wheels\nacme-internal==1.0\n" },
      { "requirements.txt": "--find-links=./wheels\nacme-internal==1.0\n" },
      {
        "pyproject.toml":
          '[project]\nname = "x"\ndependencies = ["acme-internal"]\n\n[tool.uv]\nextra-index-url = ["https://pypi.acme.dev/simple"]\n',
      },
      {
        "pyproject.toml":
          '[project]\nname = "x"\ndependencies = ["acme-internal"]\n\n[tool.uv.pip]\nno-index = true\n',
      },
    ];
    for (const files of cases) {
      const { findings, calls } = await detect(files, pypi({}));
      expect(findings).toEqual([]);
      expect(calls).toEqual([]);
    }
  });

  it("still checks pyproject dependencies when [tool.uv] has no index keys", async () => {
    const { calls } = await detect(
      {
        "pyproject.toml":
          '[project]\nname = "x"\ndependencies = ["made-up-lib"]\n\n[tool.uv]\ndev-dependencies = ["pytest"]\n',
      },
      pypi({}),
    );
    expect(calls).toContain("https://pypi.org/pypi/made-up-lib/json");
  });

  it("treats a scoped 404 as private when .npmrc has a registry.npmjs.org auth token", async () => {
    const files = {
      "package.json": pkg({ "@acme/internal": "^1.0.0" }),
      ".npmrc": "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n",
    };
    const { findings } = await detect(files, npmRoutes({ downloads: {} }));
    expect(findings).toEqual([]);
    const bare = await detect(
      { "package.json": files["package.json"] },
      npmRoutes({ downloads: {} }),
    );
    expect(bare.findings).toHaveLength(1);
    const unscoped = await detect(
      { "package.json": pkg({ "made-up-thing-lib": "^1.0.0" }), ".npmrc": files[".npmrc"] },
      npmRoutes({ downloads: {} }),
    );
    expect(unscoped.findings).toHaveLength(1);
  });
  it("never sends a pyproject's own name (self-referencing extras) to PyPI", async () => {
    const files = {
      "pyproject.toml":
        '[project]\nname = "My_Internal.Lib"\ndependencies = ["requests>=2"]\n\n[project.optional-dependencies]\ntest = ["pytest"]\nall = ["my-internal-lib[test]"]\n',
    };
    const { findings, calls } = await detect(files, pypi({}));
    expect(calls.some((u) => u.includes("my-internal-lib"))).toBe(false);
    expect(findings.some((f) => f.title.includes("my-internal-lib"))).toBe(false);
  });

  it("never sends the [tool.poetry] name to PyPI", async () => {
    const files = {
      "pyproject.toml":
        '[tool.poetry]\nname = "acme-core"\n\n[tool.poetry.dependencies]\nacme-core = "^1.0"\n',
    };
    const { calls } = await detect(files, pypi({}));
    expect(calls).toEqual([]);
  });

  it("never sends [tool.uv.sources] workspace, path and git members to PyPI", async () => {
    const files = {
      "pyproject.toml":
        '[project]\nname = "root"\ndependencies = ["member-a", "local-path-pkg", "gitdep", "tbl-member", "fastapi-auth-magic"]\n\n[tool.uv.sources]\nmember-a = { workspace = true }\nlocal-path-pkg = { path = "../local" }\n"gitdep" = { git = "https://example.com/x.git" }\n\n[tool.uv.sources.tbl-member]\nworkspace = true\n',
    };
    const { calls } = await detect(files, pypi({}));
    expect(calls).toEqual(["https://pypi.org/pypi/fastapi-auth-magic/json"]);
  });

  it("skips poetry path and git entries without a version but still checks versioned ones", async () => {
    const files = {
      "pyproject.toml":
        '[tool.poetry.dependencies]\nlocal-lib = { path = "../lib" }\ngit-lib = { git = "https://example.com/x.git" }\nmade-up-lib = "^1.0"\n',
    };
    const { calls } = await detect(files, pypi({}));
    expect(calls).toEqual(["https://pypi.org/pypi/made-up-lib/json"]);
  });

  it("degrades on a malformed PyPI body", async () => {
    const warnings: string[] = [];
    const { findings } = await detect(
      { "requirements.txt": "fastapi-auth-magic==0.1.0\n" },
      pypi({
        "https://pypi.org/pypi/fastapi-auth-magic/json": { status: 200, body: { nope: true } },
      }),
      warnings,
    );
    expect(findings).toEqual([]);
    expect(warnings.some((w) => w.includes("failed"))).toBe(true);
  });

  it("stays silent for comment-only mentions", async () => {
    const { findings, calls } = await detect(
      { "requirements.txt": "# fastapi-auth-magic==0.1.0\n" },
      pypi({}),
    );
    expect(findings).toEqual([]);
    expect(calls).toEqual([]);
  });
});

describe("PackageExistenceDetector: network behaviour", () => {
  it("sends GET with an accept header, no body, one request per name and bulk chunks of 128", async () => {
    const names: Record<string, string> = {};
    for (let i = 0; i < 130; i++)
      names[`acme-lib-${String.fromCharCode(97 + (i % 26))}${i}`] = "^1.0.0";
    const files = {
      "package.json": pkg(names),
      "apps/web/package.json": pkg({ "acme-lib-a0": "^1.0.0" }),
    };
    const downloads: Record<string, number> = {};
    for (const n of Object.keys(names)) downloads[n] = 9999;
    const { calls, inits } = await detect(files, npmRoutes({ downloads }));
    const bulk = calls.filter((u) => u.startsWith(DL));
    expect(bulk).toHaveLength(2);
    expect(decodeURIComponent(bulk[0]!.slice(DL.length)).split(",")).toHaveLength(BULK_DOWNLOADS);
    expect(new Set(calls).size).toBe(calls.length);
    for (const init of inits) {
      expect(init.method).toBe("GET");
      expect(init.headers).toEqual({ accept: "application/json" });
      expect(init.body).toBeUndefined();
    }
  });

  it("never has more than 6 requests in flight", async () => {
    const names: Record<string, string> = {};
    for (let i = 0; i < 30; i++) names[`acme-pkg-${i}`] = "^1.0.0";
    const m = mockFetch(npmRoutes({ downloads: {} }));
    let active = 0;
    let peak = 0;
    const slow: FetchLike = async (url, init) => {
      active++;
      peak = Math.max(peak, active);
      await new Promise((r) => setTimeout(r, 3));
      active--;
      return m.fn(url, init);
    };
    await new PackageExistenceDetector(slow, () => NOW).detect(
      context({ "package.json": pkg(names) }),
    );
    expect(peak).toBeLessThanOrEqual(CONCURRENCY);
    expect(peak).toBeGreaterThan(1);
  });

  it("adds a privacy warning with counts only, and no file contents", async () => {
    const warnings: string[] = [];
    await detect(
      {
        "package.json": pkg({ "leftpadx-ai-helper": "^1.0.0" }),
        "requirements.txt": "fastapi-auth-magic==0.1.0\n",
      },
      npmRoutes({}),
      warnings,
    );
    const privacy = warnings.find((w) => w.startsWith("Online package check: looked up"));
    expect(privacy).toContain("1 npm and 1 PyPI package name(s)");
    expect(privacy).not.toContain("leftpadx");
    expect(privacy).not.toContain("fastapi-auth-magic");
  });

  it("keeps partial results when one lookup times out", async () => {
    vi.useFakeTimers();
    const warnings: string[] = [];
    const files = { "requirements.txt": "fastapi-auth-magic==0.1.0\nacme-hangs==1.0\n" };
    const m = mockFetch((url) => (url.includes("acme-hangs") ? "hang" : { status: 404 }));
    const p = new PackageExistenceDetector(m.fn, () => NOW).detect(context(files, true, warnings));
    await vi.advanceTimersByTimeAsync(REQUEST_TIMEOUT_MS + 10);
    const findings = await p;
    expect(findings.map((f) => f.title)).toEqual(["`fastapi-auth-magic` does not exist on PyPI"]);
    expect(warnings.some((w) => w.includes("1 lookup(s) failed"))).toBe(true);
  });

  it("stops after the overall deadline and says how many packages were not checked", async () => {
    vi.useFakeTimers();
    const warnings: string[] = [];
    const reqs = Array.from({ length: 40 }, (_, i) => `acme-pkg-${i}==1.0`).join("\n");
    const m = mockFetch(() => "hang");
    const p = new PackageExistenceDetector(m.fn, () => NOW).detect(
      context({ "requirements.txt": reqs }, true, warnings),
    );
    await vi.advanceTimersByTimeAsync(OVERALL_DEADLINE_MS + 100);
    expect(await p).toEqual([]);
    expect(
      warnings.some((w) => /stopped after 10s; \d+ package\(s\) were not checked/.test(w)),
    ).toBe(true);
    expect(m.calls.length).toBeLessThan(40);
  });

  it("checks npm and PyPI concurrently so a slow npm phase cannot starve PyPI", async () => {
    const files = {
      "package.json": pkg({ "leftpadx-ai-helper": "^1.0.0" }),
      "requirements.txt": "fastapi-auth-magic==0.1.0\n",
    };
    const order: string[] = [];
    const m = mockFetch((url) => {
      order.push(url.startsWith("https://pypi.org") ? "pypi" : "npm");
      return undefined;
    });
    await new PackageExistenceDetector(m.fn, () => NOW).detect(context(files));
    expect(order[0]).toBe("npm");
    expect(order.indexOf("pypi")).toBeLessThan(order.length - 1);
  });

  it("warns and returns nothing when fetch is unavailable", async () => {
    vi.stubGlobal("fetch", undefined);
    const warnings: string[] = [];
    const findings = await new PackageExistenceDetector(undefined, () => NOW).detect(
      context({ "package.json": pkg({ "leftpadx-ai-helper": "^1.0.0" }) }, true, warnings),
    );
    expect(findings).toEqual([]);
    expect(warnings.some((w) => w.includes("fetch is not available"))).toBe(true);
  });

  it("gives stable ids across two runs", async () => {
    const files = { "package.json": pkg({ "leftpadx-ai-helper": "^1.0.0" }) };
    const a = await detect(files, npmRoutes({}));
    const b = await detect(files, npmRoutes({}));
    expect(a.findings.map((f) => f.id)).toEqual(b.findings.map((f) => f.id));
  });
});

describe("depsPrecedence for existence findings", () => {
  const f = (ruleId: string, line: number): Finding =>
    ({
      id: `DEP-${ruleId}-${line}`,
      ruleId,
      title: ruleId,
      severity: "medium",
      category: "dependency",
      deployBlocking: false,
      confidence: "low",
      file: "package.json",
      line,
      plainEnglishProblem: "p",
      whyItMatters: "w",
      fixSteps: ["s"],
      autoFixAvailable: false,
    }) as Finding;

  it.each(["dependency/package-not-found", "dependency/package-very-new"])(
    "keeps only the typosquat finding on the same line for %s",
    (loser) => {
      const same = applyPrecedence(
        [f("dependency/typosquat-package", 4), f(loser, 4)],
        depsPrecedence,
      );
      expect(same.findings.map((x) => x.ruleId)).toEqual(["dependency/typosquat-package"]);
      const other = applyPrecedence(
        [f("dependency/typosquat-package", 4), f(loser, 5)],
        depsPrecedence,
      );
      expect(other.findings).toHaveLength(2);
    },
  );
});
