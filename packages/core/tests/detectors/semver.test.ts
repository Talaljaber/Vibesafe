import { describe, it, expect } from "vitest";
import {
  classifySpec,
  compareVersions,
  formatVersion,
  minVersion,
  parseRange,
  parseVersion,
  resolvedVersions,
  satisfies,
} from "../../src/detectors/utils/semver.js";

describe("parseVersion / compareVersions", () => {
  it("parses releases, prereleases, build metadata and a leading v or =", () => {
    expect(parseVersion("1.2.3")).toEqual({ major: 1, minor: 2, patch: 3, prerelease: [] });
    expect(parseVersion("v1.2.3-rc.1+build.5")).toEqual({
      major: 1,
      minor: 2,
      patch: 3,
      prerelease: ["rc", 1],
    });
    expect(parseVersion("=0.0.1")?.patch).toBe(1);
    expect(parseVersion("1.2")).toBeNull();
    expect(parseVersion("latest")).toBeNull();
    expect(parseVersion("^1.2.3")).toBeNull();
  });

  it("orders versions with semver prerelease rules", () => {
    const sorted = [
      "1.0.0",
      "1.0.0-rc.1",
      "1.0.0-beta.11",
      "1.0.0-beta.2",
      "1.0.0-beta",
      "1.0.0-alpha.beta",
      "1.0.0-alpha.1",
      "1.0.0-alpha",
      "0.9.9",
      "1.0.1",
    ].sort((a, b) => compareVersions(a, b));
    expect(sorted).toEqual([
      "0.9.9",
      "1.0.0-alpha",
      "1.0.0-alpha.1",
      "1.0.0-alpha.beta",
      "1.0.0-beta",
      "1.0.0-beta.2",
      "1.0.0-beta.11",
      "1.0.0-rc.1",
      "1.0.0",
      "1.0.1",
    ]);
    expect(compareVersions("2.0.0", "10.0.0")).toBe(-1);
    expect(compareVersions("1.2.3", "1.2.3")).toBe(0);
  });

  it("formats parsed versions", () => {
    expect(formatVersion(parseVersion("v1.2.3-rc.1")!)).toBe("1.2.3-rc.1");
  });
});

describe("parseRange / satisfies", () => {
  const cases: [string, string[], string[]][] = [
    ["^1.2.3", ["1.2.3", "1.9.0"], ["1.2.2", "2.0.0", "2.0.0-rc.1"]],
    ["^0.2.3", ["0.2.3", "0.2.9"], ["0.3.0", "0.2.2"]],
    ["^0.0.3", ["0.0.3"], ["0.0.4"]],
    ["^1.2", ["1.2.0", "1.99.0"], ["2.0.0", "1.1.9"]],
    ["~1.2.3", ["1.2.3", "1.2.9"], ["1.3.0"]],
    ["~1", ["1.0.0", "1.9.9"], ["2.0.0"]],
    ["1.x", ["1.0.0", "1.5.5"], ["2.0.0", "0.9.0"]],
    ["1.2.*", ["1.2.0", "1.2.7"], ["1.3.0"]],
    ["*", ["0.0.1", "99.0.0"], []],
    ["", ["1.0.0"], []],
    ["1.2.3", ["1.2.3"], ["1.2.4"]],
    [">=1.2.3 <2", ["1.2.3", "1.9.9"], ["2.0.0", "1.2.2"]],
    [">= 1.2.3 < 2.0.0", ["1.5.0"], ["2.0.0"]],
    [">1.2", ["1.3.0"], ["1.2.9"]],
    ["<=1.2", ["1.2.9"], ["1.3.0"]],
    ["1.2.3 - 2.3", ["1.2.3", "2.3.9"], ["2.4.0", "1.2.2"]],
    ["1.2.3 - 2.3.4", ["2.3.4"], ["2.3.5"]],
    ["<0.2.4 || >=1.0.0 <1.2.6", ["0.2.3", "1.2.5"], ["0.2.4", "1.2.6", "0.9.0"]],
    [
      ">=11.1.4 <12.3.5 || >=13.0.0 <13.5.9 || >=14.0.0 <14.2.25 || >=15.0.0 <15.2.3",
      ["11.1.4", "13.4.0", "14.2.24", "15.2.2", "12.3.4"],
      ["11.1.3", "12.3.5", "13.5.9", "14.2.25", "15.2.3", "16.0.0"],
    ],
    [">=8.0.0-alpha.0 <8.0.0-alpha.4", ["8.0.0-alpha.3"], ["8.0.0-alpha.4", "8.0.0"]],
  ];

  for (const [range, inside, outside] of cases) {
    it(`"${range}"`, () => {
      expect(parseRange(range), range).not.toBeNull();
      for (const v of inside) expect(satisfies(v, range), `${v} in ${range}`).toBe(true);
      for (const v of outside) expect(satisfies(v, range), `${v} not in ${range}`).toBe(false);
    });
  }

  it("rejects things that are not ranges", () => {
    expect(parseRange("latest")).toBeNull();
    expect(parseRange("github:user/repo")).toBeNull();
    expect(parseRange("^not.a.version")).toBeNull();
    expect(satisfies("garbage", "^1.0.0")).toBe(false);
    expect(satisfies("1.0.0", "latest")).toBe(false);
  });
});

describe("minVersion", () => {
  it("returns the lowest admitted version", () => {
    expect(formatVersion(minVersion("^13.4.0")!)).toBe("13.4.0");
    expect(formatVersion(minVersion("~1.2")!)).toBe("1.2.0");
    expect(formatVersion(minVersion(">1.2.3")!)).toBe("1.2.4");
    expect(formatVersion(minVersion("<2.0.0")!)).toBe("0.0.0");
    expect(formatVersion(minVersion("^2.0.0 || ^1.5.0")!)).toBe("1.5.0");
    expect(formatVersion(minVersion("*")!)).toBe("0.0.0");
  });

  it("returns null for an empty or invalid range", () => {
    expect(minVersion(">2.0.0 <1.0.0")).toBeNull();
    expect(minVersion("latest")).toBeNull();
  });
});

describe("classifySpec", () => {
  it.each([
    ["1.2.3", "exact"],
    ["=1.2.3", "exact"],
    ["v1.2.3", "exact"],
    ["^1.2.3", "range"],
    ["~1.2.3", "range"],
    ["1.x", "range"],
    [">=1 <2", "range"],
    ["*", "range"],
    ["latest", "tag"],
    ["next", "tag"],
    ["npm:other@^1.0.0", "alias"],
    ["workspace:*", "workspace"],
    ["file:../lib", "file"],
    ["link:../lib", "file"],
    ["./local", "file"],
    ["git+https://github.com/u/r.git", "git"],
    ["github:u/r", "git"],
    ["u/r#main", "git"],
    ["https://example.com/pkg.tgz", "url"],
    ["^^bad", "invalid"],
  ])("%s -> %s", (spec, kind) => {
    expect(classifySpec(spec)).toBe(kind);
  });
});

describe("resolvedVersions", () => {
  it("reads package-lock v2/v3 packages, including nested and scoped entries, with lines", () => {
    const lock = JSON.stringify(
      {
        name: "app",
        lockfileVersion: 3,
        packages: {
          "": { name: "app", dependencies: { next: "^13.4.0" } },
          "node_modules/next": { version: "13.5.11" },
          "node_modules/@babel/traverse": { version: "7.22.0" },
          "node_modules/foo/node_modules/minimist": { version: "1.2.5" },
          "node_modules/minimist": { version: "1.2.8" },
          "node_modules/linked": { link: true, resolved: "packages/linked" },
        },
      },
      null,
      2,
    );
    const map = resolvedVersions("package-lock.json", lock);
    expect(map.get("next")).toEqual([{ version: "13.5.11", line: 11 }]);
    expect(map.get("@babel/traverse")?.[0]?.version).toBe("7.22.0");
    expect(map.get("minimist")?.map((e) => e.version)).toEqual(["1.2.5", "1.2.8"]);
    expect(map.has("linked")).toBe(false);
  });

  it("reads package-lock v1 nested dependencies", () => {
    const lock = JSON.stringify({
      lockfileVersion: 1,
      dependencies: {
        lodash: { version: "4.17.15" },
        a: { version: "1.0.0", dependencies: { qs: { version: "6.5.2" } } },
      },
    });
    const map = resolvedVersions("package-lock.json", lock);
    expect(map.get("lodash")?.[0]?.version).toBe("4.17.15");
    expect(map.get("qs")?.[0]?.version).toBe("6.5.2");
  });

  it("reads pnpm-lock v5, v6 and v9 keys", () => {
    const v5 = [
      "lockfileVersion: 5.4",
      "",
      "packages:",
      "",
      "  /lodash/4.17.15:",
      "    resolution: {integrity: sha512-x}",
      "  /@babel/traverse/7.22.0_react@18.2.0:",
      "    resolution: {integrity: sha512-y}",
    ].join("\n");
    const v6 = [
      "lockfileVersion: '6.0'",
      "packages:",
      "  /next@13.4.0(react-dom@18.2.0)(react@18.2.0):",
      "    resolution: {integrity: sha512-z}",
    ].join("\n");
    const v9 = [
      "lockfileVersion: '9.0'",
      "importers:",
      "  .:",
      "    dependencies:",
      "      axios:",
      "        specifier: ^0.21.0",
      "        version: 0.21.1",
      "packages:",
      "  axios@0.21.1:",
      "    resolution: {integrity: sha512-a}",
      "  '@scope/pkg@1.0.0-rc.1':",
      "    resolution: {integrity: sha512-b}",
      "snapshots:",
      "  axios@0.21.1:",
      "    dependencies: {}",
    ].join("\n");
    expect(resolvedVersions("pnpm-lock.yaml", v5).get("lodash")).toEqual([
      { version: "4.17.15", line: 5 },
    ]);
    expect(resolvedVersions("pnpm-lock.yaml", v5).get("@babel/traverse")?.[0]?.version).toBe(
      "7.22.0",
    );
    expect(resolvedVersions("pnpm-lock.yaml", v6).get("next")?.[0]?.version).toBe("13.4.0");
    const m9 = resolvedVersions("pnpm-lock.yaml", v9);
    expect(m9.get("axios")).toEqual([{ version: "0.21.1", line: 9 }]);
    expect(m9.get("@scope/pkg")?.[0]?.version).toBe("1.0.0-rc.1");
  });

  it("reads yarn classic and berry lockfiles", () => {
    const classic = [
      "# yarn lockfile v1",
      "",
      "lodash@^4.17.15, lodash@^4.17.20:",
      '  version "4.17.21"',
      '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"',
      "",
      '"@babel/traverse@^7.0.0":',
      '  version "7.22.0"',
    ].join("\n");
    const berry = [
      "__metadata:",
      "  version: 6",
      "",
      '"json5@npm:^2.1.0, json5@npm:^2.2.0":',
      "  version: 2.2.1",
      '  resolution: "json5@npm:2.2.1"',
      "",
      '"app@workspace:.":',
      "  version: 0.0.0-use.local",
    ].join("\n");
    const c = resolvedVersions("yarn.lock", classic);
    expect(c.get("lodash")).toEqual([{ version: "4.17.21", line: 3 }]);
    expect(c.get("@babel/traverse")?.[0]?.version).toBe("7.22.0");
    const b = resolvedVersions("yarn.lock", berry);
    expect(b.get("json5")?.[0]?.version).toBe("2.2.1");
    expect(b.has("app")).toBe(false);
  });

  it("returns an empty map for unknown names or garbage, never throwing", () => {
    expect(resolvedVersions("package-lock.json", "{not json").size).toBe(0);
    expect(resolvedVersions("Cargo.lock", "x").size).toBe(0);
    expect(resolvedVersions("pnpm-lock.yaml", "").size).toBe(0);
  });
});
