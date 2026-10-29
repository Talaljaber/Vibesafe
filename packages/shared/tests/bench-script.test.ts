import { describe, it, expect } from "vitest";

interface KeyItem {
  id: string;
  file: string;
  line: number;
  category: string;
  isDecoy: boolean;
}
interface F {
  ruleId: string;
  category: string;
  file?: string;
  line?: number;
}
interface Row {
  id: string;
  status: string;
  ruleIds: string[];
}
interface Match {
  rows: Row[];
  total: number;
  strict: number;
  lenient: number;
  decoysFlagged: Row[];
  unmatched: string[];
  unmatchedByRule: Record<string, number>;
}

const bench = (await import("../../../scripts/bench.mjs")) as {
  assertNotHoldout: (...paths: (string | undefined)[]) => void;
  normalizePath: (file: string | undefined, root?: string) => string;
  isCompatible: (keyCategory: string, findingCategory: string) => boolean;
  isLocated: (item: KeyItem, f: F, window?: number, root?: string) => boolean;
  matchFindings: (
    key: KeyItem[],
    findings: F[],
    opts?: { window?: number; appRoot?: string },
  ) => Match;
  compareMatches: (
    base: Match,
    current: Match,
  ) => {
    newlyCaught: string[];
    newlyStrict: string[];
    lost: string[];
    newDecoys: string[];
    newUnmatched: string[];
  };
  parseScanOutput: (text: string) => { findings: F[] };
  findingsOf: (json: unknown) => F[];
};

const KEY: KeyItem[] = [
  { id: "K-1", file: "lib/a.ts", line: 10, category: "secret", isDecoy: false },
  { id: "K-2", file: "app/api/x/route.ts", line: 20, category: "injection", isDecoy: false },
  { id: "K-3", file: "Dockerfile", line: 3, category: "security_config", isDecoy: false },
  { id: "K-4", file: "lib/b.ts", line: 5, category: "other", isDecoy: false },
  { id: "D-1", file: "lib/safe.ts", line: 7, category: "xss", isDecoy: true },
  { id: "D-2", file: ".env.local", line: 2, category: "secret", isDecoy: true },
];

describe("bench script", () => {
  it("refuses holdout paths in any position and separator", () => {
    expect(() => bench.assertNotHoldout("C:\\bench\\holdout\\app")).toThrow(/holdout/);
    expect(() => bench.assertNotHoldout("/x/y", "/bench/HoldOut/key.json")).toThrow();
    expect(() => bench.assertNotHoldout("/bench/holdouts/app", undefined)).not.toThrow();
    expect(() => bench.assertNotHoldout("/bench/shop-holdout-free")).not.toThrow();
  });

  it("normalizes separators, the app root, ./ and the git-history prefix", () => {
    expect(bench.normalizePath("C:\\bench\\app\\lib\\a.ts", "C:\\bench\\app")).toBe("lib/a.ts");
    expect(bench.normalizePath("./lib/a.ts")).toBe("lib/a.ts");
    expect(bench.normalizePath("(git history) scripts/x.sh")).toBe("scripts/x.sh");
    expect(bench.normalizePath(undefined)).toBe("");
  });

  it("locates findings within the window and in the same file only", () => {
    const item = KEY[0]!;
    expect(
      bench.isLocated(item, { ruleId: "r", category: "secret", file: "lib/a.ts", line: 13 }),
    ).toBe(true);
    expect(
      bench.isLocated(item, { ruleId: "r", category: "secret", file: "lib/a.ts", line: 14 }),
    ).toBe(false);
    expect(
      bench.isLocated(item, { ruleId: "r", category: "secret", file: "lib/a.ts", line: 14 }, 4),
    ).toBe(true);
    expect(
      bench.isLocated(item, { ruleId: "r", category: "secret", file: "lib/a.tsx", line: 10 }),
    ).toBe(false);
    expect(bench.isLocated(item, { ruleId: "r", category: "secret", file: "lib/a.ts" })).toBe(true);
  });

  it("maps compatible categories", () => {
    expect(bench.isCompatible("secret", "frontend_exposure")).toBe(true);
    expect(bench.isCompatible("ssrf", "injection")).toBe(true);
    expect(bench.isCompatible("injection", "validation")).toBe(false);
    expect(bench.isCompatible("other", "structure")).toBe(true);
    expect(bench.isCompatible("unknown_cat", "unknown_cat")).toBe(true);
  });

  const BASE: F[] = [
    { ruleId: "secret/x", category: "secret", file: "lib/a.ts", line: 10 },
    {
      ruleId: "validation/missing-body-validation",
      category: "validation",
      file: "app/api/x/route.ts",
      line: 18,
    },
    { ruleId: "secret/env-not-ignored", category: "secret", file: ".env.local" },
    { ruleId: "code_quality/console-log", category: "code_quality", file: "lib/z.ts", line: 1 },
  ];

  it("computes statuses, recall, decoys and unmatched findings", () => {
    const m = bench.matchFindings(KEY, BASE);
    const status = Object.fromEntries(m.rows.map((r) => [r.id, r.status]));
    expect(status).toEqual({
      "K-1": "caught",
      "K-2": "located",
      "K-3": "missed",
      "K-4": "missed",
      "D-1": "decoy-clean",
      // A file-level finding makes no claim about the decoy's line.
      "D-2": "decoy-clean",
    });
    expect(m.total).toBe(4);
    expect(m.strict).toBe(1);
    expect(m.lenient).toBe(2);
    expect(m.unmatched).toEqual(["code_quality/console-log|lib/z.ts|1"]);
    expect(m.unmatchedByRule).toEqual({ "code_quality/console-log": 1 });
    expect(m.rows.find((r) => r.id === "K-2")!.ruleIds).toEqual([
      "validation/missing-body-validation",
    ]);
  });

  it("reports newly caught, lost, new decoys and new unmatched findings against a baseline", () => {
    const current: F[] = [
      // K-1 lost (moved out of the window), K-2 now strict, K-3 newly caught
      { ruleId: "secret/x", category: "secret", file: "lib/a.ts", line: 30 },
      { ruleId: "injection/sql", category: "injection", file: "app/api/x/route.ts", line: 20 },
      {
        ruleId: "security_config/docker-root",
        category: "security_config",
        file: "Dockerfile",
        line: 3,
      },
      { ruleId: "xss/y", category: "xss", file: "lib/safe.ts", line: 8 },
      { ruleId: "code_quality/console-log", category: "code_quality", file: "lib/z.ts", line: 1 },
    ];
    const d = bench.compareMatches(
      bench.matchFindings(KEY, BASE),
      bench.matchFindings(KEY, current),
    );
    expect(d.newlyCaught).toEqual(["K-3"]);
    expect(d.newlyStrict).toEqual(["K-2", "K-3"]);
    expect(d.lost).toEqual(["K-1"]);
    expect(d.newDecoys).toEqual(["D-1"]);
    expect(d.newUnmatched).toEqual(["secret/x|lib/a.ts|30"]);
  });

  it("parses scan output with a BOM or leading noise and accepts reports as baselines", () => {
    const scan = bench.parseScanOutput(
      '\uFEFFwarn: x\n{"findings":[{"ruleId":"a/b","category":"a"}]}',
    );
    expect(scan.findings).toHaveLength(1);
    expect(bench.findingsOf(scan)).toHaveLength(1);
    expect(bench.findingsOf({ scan })).toHaveLength(1);
    expect(() => bench.findingsOf({})).toThrow();
    expect(() => bench.parseScanOutput("nothing")).toThrow();
  });
});
