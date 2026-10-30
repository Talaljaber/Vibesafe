import { describe, it, expect } from "vitest";
import {
  mapLimit,
  mergeRegistryConfig,
  nonDefaultRegistryNames,
  normalizePypiName,
  npmDownloadsUrl,
  npmLatestUrl,
  npmPackumentUrl,
  parseDownloads,
  parseLatest,
  parseNpmrc,
  parsePackument,
  parsePypi,
  parseYarnrc,
  pypiUrl,
} from "../../src/detectors/utils/package-registry.js";

describe("urls", () => {
  it("encodes scoped names in the packument url only", () => {
    expect(npmPackumentUrl("@acme/ui")).toBe("https://registry.npmjs.org/@acme%2fui");
    expect(npmPackumentUrl("left-pad")).toBe("https://registry.npmjs.org/left-pad");
    expect(npmLatestUrl("left-pad")).toBe("https://registry.npmjs.org/left-pad/latest");
    expect(npmDownloadsUrl(["a", "b"])).toBe("https://api.npmjs.org/downloads/point/last-week/a,b");
    expect(pypiUrl("fastapi-auth-magic")).toBe("https://pypi.org/pypi/fastapi-auth-magic/json");
  });
  it("normalises PyPI names per PEP 503", () => {
    expect(normalizePypiName("Fastapi_Auth.Magic")).toBe("fastapi-auth-magic");
    expect(normalizePypiName("a--b__c")).toBe("a-b-c");
  });
});

describe("registry config", () => {
  it("reads .npmrc scopes and the default registry", () => {
    const c = parseNpmrc(
      "# comment\n@acme:registry=https://npm.acme.dev/\n@pub:registry=https://registry.npmjs.org/\n//npm.acme.dev/:_authToken=x\n",
    );
    expect([...c.privateScopes]).toEqual(["@acme"]);
    expect(c.defaultIsPrivate).toBe(false);
    expect(parseNpmrc("registry=https://npm.acme.dev/\n").defaultIsPrivate).toBe(true);
    expect(parseNpmrc("registry=https://registry.npmjs.org/\n").defaultIsPrivate).toBe(false);
  });
  it("reads .yarnrc.yml scopes and the default registry", () => {
    const c = parseYarnrc(
      'npmRegistryServer: "https://npm.acme.dev"\nnpmScopes:\n  acme:\n    npmRegistryServer: "https://npm.acme.dev"\n  other:\n    npmAlwaysAuth: true\n',
    );
    expect(c.defaultIsPrivate).toBe(true);
    expect([...c.privateScopes]).toEqual(["@acme"]);
    const merged = mergeRegistryConfig(c, parseNpmrc("@x:registry=https://x.dev/"));
    expect([...merged.privateScopes].sort()).toEqual(["@acme", "@x"]);
  });
  it("never throws on junk", () => {
    expect(parseNpmrc(undefined as unknown as string).defaultIsPrivate).toBe(false);
    expect(parseYarnrc("::: {{").privateScopes.size).toBe(0);
  });
});

describe("nonDefaultRegistryNames", () => {
  it("reads package-lock resolved hosts", () => {
    const lock = JSON.stringify(
      {
        packages: {
          "node_modules/internal-lib": {
            version: "1.0.0",
            resolved: "https://npm.pkg.github.com/download/internal-lib-1.0.0.tgz",
          },
          "node_modules/react": {
            version: "18.0.0",
            resolved: "https://registry.npmjs.org/react/-/react-18.0.0.tgz",
          },
          "node_modules/@acme/ui": {
            version: "1.0.0",
            resolved: "https://npm.acme.dev/@acme/ui/-/ui-1.0.0.tgz",
          },
        },
      },
      null,
      2,
    );
    expect([...nonDefaultRegistryNames("package-lock.json", lock)].sort()).toEqual([
      "@acme/ui",
      "internal-lib",
    ]);
  });
  it("reads pnpm tarball hosts and yarn resolved hosts", () => {
    const pnpm =
      "packages:\n\n  internal-lib@1.0.0:\n    resolution: {tarball: https://npm.acme.dev/internal-lib/-/internal-lib-1.0.0.tgz}\n\n  react@18.0.0:\n    resolution: {integrity: sha512-x}\n";
    expect([...nonDefaultRegistryNames("pnpm-lock.yaml", pnpm)]).toEqual(["internal-lib"]);
    const yarn =
      'internal-lib@^1.0.0:\n  version "1.0.0"\n  resolved "https://npm.acme.dev/internal-lib/-/internal-lib-1.0.0.tgz#abc"\n\n"react@^18.0.0":\n  version "18.0.0"\n  resolved "https://registry.yarnpkg.com/react/-/react-18.0.0.tgz#abc"\n';
    expect([...nonDefaultRegistryNames("yarn.lock", yarn)]).toEqual(["internal-lib"]);
    expect(nonDefaultRegistryNames("other.lock", "x").size).toBe(0);
  });
});

describe("mapLimit", () => {
  it("never exceeds the limit and returns results in order", async () => {
    let inFlight = 0;
    let peak = 0;
    const out = await mapLimit(
      [1, 2, 3, 4, 5, 6, 7, 8],
      3,
      new AbortController().signal,
      async (n) => {
        inFlight++;
        peak = Math.max(peak, inFlight);
        await new Promise((r) => setTimeout(r, 2));
        inFlight--;
        return n * 2;
      },
    );
    expect(out).toEqual([2, 4, 6, 8, 10, 12, 14, 16]);
    expect(peak).toBeLessThanOrEqual(3);
  });
  it("stops starting work after abort", async () => {
    const c = new AbortController();
    const out = await mapLimit([1, 2, 3, 4], 1, c.signal, async (n) => {
      if (n === 2) c.abort();
      return n;
    });
    expect(out).toEqual([1, 2, undefined, undefined]);
  });
});

describe("parsers", () => {
  it("parseDownloads handles bulk, single and unknown names", () => {
    const bulk = parseDownloads(["a", "b"], { a: { downloads: 5, package: "a" }, b: null });
    expect(bulk.get("a")).toBe(5);
    expect(bulk.get("b")).toBeNull();
    expect(parseDownloads(["a"], { downloads: 9, package: "a" }).get("a")).toBe(9);
    expect(parseDownloads(["a"], "junk").get("a")).toBeNull();
  });
  it("parsePackument reads created, unpublished and security holders", () => {
    const created = "2024-01-02T00:00:00.000Z";
    expect(parsePackument({ time: { created } }).created).toBe(Date.parse(created));
    expect(parsePackument({ time: { created, unpublished: { time: created } } }).unpublished).toBe(
      true,
    );
    expect(parsePackument({ "dist-tags": { latest: "0.0.1-security" } }).securityHolder).toBe(true);
    expect(parsePackument({ description: "security holding package" }).securityHolder).toBe(true);
    expect(parsePackument({ description: "Security headers for Express" }).securityHolder).toBe(
      false,
    );
    expect(parsePackument(null)).toEqual({
      created: undefined,
      unpublished: false,
      securityHolder: false,
    });
  });
  it("parseLatest detects only the placeholder", () => {
    expect(parseLatest({ version: "0.0.1-security" }).securityHolder).toBe(true);
    expect(
      parseLatest({ version: "2.1.0", description: "Security headers for Express" }).securityHolder,
    ).toBe(false);
    expect(parseLatest([]).securityHolder).toBe(false);
  });
  it("parsePypi takes the minimum upload time over all files and counts releases with files", () => {
    const old = "2020-01-01T00:00:00Z";
    const recent = "2026-10-01T00:00:00Z";
    const r = parsePypi({
      releases: {
        "0.1.0": [{ upload_time_iso_8601: old }],
        "0.2.0": [{ upload_time_iso_8601: recent }],
        "0.3.0": [],
      },
    });
    expect(r).toEqual({ created: Date.parse(old), releases: 2 });
    expect(parsePypi({ releases: {} })).toEqual({ created: undefined, releases: 0 });
    expect(parsePypi({})).toBeUndefined();
    expect(parsePypi("x")).toBeUndefined();
  });
});
