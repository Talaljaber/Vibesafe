import { describe, it, expect, beforeAll } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  ALL_CATEGORIES,
  isMoreSevere,
  type Detector,
  type Finding,
  type ScanContext,
} from "@talaljaber/vibesafe-shared";
import { createDefaultRegistry } from "../../src/scanner/detector-registry.js";
import { ProjectContextBuilder } from "../../src/scanner/project-context.js";
import {
  matchesRulePattern,
  validatePrecedenceRules,
  type PrecedenceRule,
} from "../../src/scanner/precedence.js";
import { assertFindingRubric } from "../../src/detectors/utils/finding.js";
import * as infra from "../../src/detectors/groups/infra.js";
import * as injection from "../../src/detectors/groups/injection.js";
import * as client from "../../src/detectors/groups/client.js";
import * as authz from "../../src/detectors/groups/authz.js";
import * as crypto from "../../src/detectors/groups/crypto.js";
import * as supabase from "../../src/detectors/groups/supabase.js";
import * as deps from "../../src/detectors/groups/deps.js";
import * as tooling from "../../src/detectors/groups/tooling.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const coreRoot = path.resolve(here, "../..");
const detectorsDir = path.join(coreRoot, "src/detectors");
const corpusDir = path.join(coreRoot, "tests/registry-corpus");
const fixtureApp = path.resolve(coreRoot, "../../fixtures/nextjs-vibecoded-bad-app");

const GROUPS: Record<string, Record<string, unknown>> = {
  infra,
  injection,
  client,
  authz,
  crypto,
  supabase,
  deps,
  tooling,
};

/**
 * Pre-rubric ruleIds that can break assertFindingRubric today (found by this test and
 * by reading the legacy detectors on day one). Legacy detectors are never migrated;
 * new rules must not be added here.
 */
const LEGACY_RUBRIC_ALLOW = new Set([
  // critical at medium confidence
  "auth/missing-route-auth",
  "auth/missing-express-auth",
  "frontend_exposure/service-role-key", // when the key is reached through an import
  "secret/sec-aws-secret-key",
  "secret/sec-supabase-service-key",
  "secret/git-history-sec-aws-secret-key",
  "secret/git-history-sec-supabase-service-key",
  // high at low confidence (view with an unresolved base class)
  "auth/django-view-missing-auth",
]);

/**
 * Legacy detectors that compose ruleIds at runtime (`secret/${pattern.id}`,
 * `secret/git-history-${id}`, `security_config/cors-${rule}`), so the emitted ruleId
 * is not a single string literal in the detector file. New detectors must not be added.
 */
const LEGACY_COMPOSED_RULE_IDS = new Set([
  "secret-detector",
  "git-history-detector",
  "cors-detector",
]);

/**
 * One category per detector, with one documented legacy exception: the Django
 * settings detector (security_config) also reports a hardcoded SECRET_KEY as
 * `secret/django-secret-key*`.
 */
function categoryException(detector: Detector, f: Finding): boolean {
  return (
    detector.id === "django-settings-detector" && f.ruleId.startsWith("secret/django-secret-key")
  );
}

function listFiles(root: string): string[] {
  const out: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === "node_modules" || entry.name === ".git") continue;
      const abs = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(abs);
      else if (entry.isFile()) out.push(path.relative(root, abs).replace(/\\/g, "/"));
    }
  };
  walk(root);
  return out.sort();
}

async function contextFor(root: string): Promise<ScanContext> {
  return {
    rootPath: root,
    projectContext: await new ProjectContextBuilder(root).build(),
    files: listFiles(root),
    config: { rootPath: root },
    readFile: async (rel) => {
      try {
        return fs.readFileSync(path.join(root, rel), "utf8");
      } catch {
        return "";
      }
    },
  };
}

/** Maps each detector to the top-level `detectors/*.ts` file that declares its class. */
function sourceFileOf(detector: Detector): string {
  const name = detector.constructor.name;
  const files = fs
    .readdirSync(detectorsDir)
    .filter((f) => f.endsWith(".ts"))
    .map((f) => path.join(detectorsDir, f));
  const hit = files.find((f) =>
    new RegExp(`\\bclass\\s+${name}\\b`).test(fs.readFileSync(f, "utf8")),
  );
  if (!hit) throw new Error(`No detectors/*.ts declares class ${name}`);
  return hit;
}

const hasLiteral = (source: string, value: string): boolean =>
  source.includes(`"${value}"`) || source.includes(`'${value}'`) || source.includes(`\`${value}\``);

interface Run {
  project: string;
  detector: Detector;
  findings: Finding[];
}

const registry = createDefaultRegistry();
const detectors = registry.getDetectors();
let runs: Run[] = [];

beforeAll(async () => {
  const projects = [
    fixtureApp,
    ...fs
      .readdirSync(corpusDir, { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .map((e) => path.join(corpusDir, e.name)),
  ];
  runs = [];
  for (const project of projects) {
    const context = await contextFor(project);
    for (const detector of detectors) {
      const first = await detector.detect(context);
      const second = await detector.detect(context);
      expect(
        second.map((f) => f.id),
        `${detector.id} ids are stable`,
      ).toEqual(first.map((f) => f.id));
      runs.push({ project: path.basename(project), detector, findings: first });
    }
  }
}, 120_000);

describe("detector registry integrity", () => {
  it("detector ids are unique, well formed and declared as literals", () => {
    const ids = detectors.map((d) => d.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const d of detectors) {
      expect(d.id).toMatch(/^[a-z0-9]+(?:-[a-z0-9]+)*-detector$/);
      const source = fs.readFileSync(sourceFileOf(d), "utf8");
      expect(source, d.id).toMatch(new RegExp(`\\bid\\s*=\\s*"${d.id}"`));
      expect(ALL_CATEGORIES, d.id).toContain(d.category);
      expect(d.name.trim(), d.id).not.toBe("");
      expect(d.description.trim(), d.id).not.toBe("");
    }
  });

  it("the corpus exercises most detectors", () => {
    const fired = new Set(runs.filter((r) => r.findings.length > 0).map((r) => r.detector.id));
    expect(fired.size).toBeGreaterThanOrEqual(15);
  });

  it("every emitted ruleId is a full string literal in its detector file", () => {
    for (const { detector, findings } of runs) {
      if (LEGACY_COMPOSED_RULE_IDS.has(detector.id)) continue;
      const source = fs.readFileSync(sourceFileOf(detector), "utf8");
      for (const f of findings) {
        expect(hasLiteral(source, f.ruleId), `${detector.id} emits ${f.ruleId}`).toBe(true);
      }
    }
  });

  it("findings follow the severity rubric (legacy allowlist aside)", () => {
    const violations = new Set<string>();
    for (const { findings } of runs) {
      for (const f of findings) {
        try {
          assertFindingRubric(f, LEGACY_RUBRIC_ALLOW);
        } catch (error) {
          violations.add((error as Error).message);
        }
      }
    }
    expect([...violations]).toEqual([]);
  });

  it("each detector reports one category, matching its ruleIds and id prefixes", () => {
    for (const { detector, findings } of runs) {
      for (const f of findings) {
        expect(f.ruleId.startsWith(`${f.category}/`), f.ruleId).toBe(true);
        expect(f.id, f.ruleId).toMatch(/^[A-Z]+-[0-9a-f]{10}$/);
        if (categoryException(detector, f)) continue;
        expect(f.category, `${detector.id} emits ${f.ruleId}`).toBe(detector.category);
      }
    }
  });

  it("finding ids are unique within a project", () => {
    const byProject = new Map<string, string[]>();
    for (const { project, findings } of runs) {
      byProject.set(project, [...(byProject.get(project) ?? []), ...findings.map((f) => f.id)]);
    }
    for (const [project, ids] of byProject) {
      const dupes = ids.filter((id, i) => ids.indexOf(id) !== i);
      expect(dupes, project).toEqual([]);
    }
  });
});

describe("detector groups", () => {
  it("export only *Detector classes, <group>Detectors, <group>Precedence and <group>NonJsExempt", () => {
    for (const [group, mod] of Object.entries(GROUPS)) {
      for (const [name, value] of Object.entries(mod)) {
        const allowed =
          name === `${group}Detectors` ||
          name === `${group}Precedence` ||
          name === `${group}NonJsExempt` ||
          (/Detector$/.test(name) && typeof value === "function");
        expect(allowed, `${group} exports ${name}`).toBe(true);
      }
      expect(typeof mod[`${group}Detectors`]).toBe("function");
      expect(Array.isArray(mod[`${group}Precedence`])).toBe(true);
      expect(typeof mod[`${group}NonJsExempt`]).toBe("object");
    }
  });

  it("registers every group detector, after the built-in ones, and re-exports its class", () => {
    const groupDetectors = Object.entries(GROUPS).flatMap(([group, mod]) =>
      (mod[`${group}Detectors`] as () => Detector[])().map((d) => ({ group, mod, d })),
    );
    const ids = detectors.map((d) => d.id);
    const firstGroupIndex =
      groupDetectors.length === 0 ? ids.length : ids.indexOf(groupDetectors[0]!.d.id);
    expect(firstGroupIndex).toBeGreaterThanOrEqual(20);
    for (const { group, mod, d } of groupDetectors) {
      expect(ids, d.id).toContain(d.id);
      expect(Object.values(mod), `${group} re-exports ${d.constructor.name}`).toContain(
        d.constructor,
      );
    }
  });

  it("NonJsExempt entries name registered detectors of the same group", () => {
    const ids = new Set(detectors.map((d) => d.id));
    for (const [group, mod] of Object.entries(GROUPS)) {
      const own = new Set((mod[`${group}Detectors`] as () => Detector[])().map((d) => d.id));
      for (const id of Object.keys(mod[`${group}NonJsExempt`] as object)) {
        expect(ids.has(id), `${group}NonJsExempt: ${id}`).toBe(true);
        expect(own.has(id), `${group}NonJsExempt: ${id} belongs to ${group}`).toBe(true);
      }
    }
  });

  it("imports scanner/precedence only with `import type` from detectors and groups", () => {
    const files: string[] = [];
    const walk = (dir: string): void => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const abs = path.join(dir, e.name);
        if (e.isDirectory()) walk(abs);
        else if (e.name.endsWith(".ts")) files.push(abs);
      }
    };
    walk(detectorsDir);
    const re =
      /\b(import|export)\s+([^;]*?)\s*from\s*["']([^"']*scanner\/precedence(?:\.js)?)["']/g;
    for (const file of files) {
      const text = fs.readFileSync(file, "utf8");
      for (const m of text.matchAll(re)) {
        expect(m[2]!.startsWith("type "), `${path.relative(coreRoot, file)}: ${m[0]}`).toBe(true);
      }
    }
  });
});

describe("precedence integrity", () => {
  const rules: readonly PrecedenceRule[] = registry.getPrecedence();

  it("registers each group's precedence list", () => {
    const declared = Object.entries(GROUPS).flatMap(
      ([group, mod]) => mod[`${group}Precedence`] as readonly PrecedenceRule[],
    );
    expect([...rules]).toEqual(declared);
  });

  it("has no malformed patterns, self-overlaps or chains", () => {
    expect(validatePrecedenceRules(rules)).toEqual([]);
  });

  it("every exact winner/loser ruleId is a literal in a detectors/*.ts file (not groups/)", () => {
    const sources = fs
      .readdirSync(detectorsDir)
      .filter((f) => f.endsWith(".ts"))
      .map((f) => fs.readFileSync(path.join(detectorsDir, f), "utf8"));
    for (const rule of rules) {
      for (const pattern of [rule.winner, ...rule.losers]) {
        if (pattern.endsWith("/*")) continue;
        expect(
          sources.some((s) => hasLiteral(s, pattern)),
          `${pattern} is emitted by some detector`,
        ).toBe(true);
      }
    }
  });

  it("winners are at least as severe as the losers they hide on the corpus", () => {
    const all = runs.flatMap((r) => r.findings);
    for (const rule of rules) {
      const winners = all.filter((f) => matchesRulePattern(f.ruleId, rule.winner));
      const losers = all.filter((f) => rule.losers.some((l) => matchesRulePattern(f.ruleId, l)));
      for (const w of winners) {
        for (const l of losers) {
          if (w.file !== l.file || w.line === undefined || l.line === undefined) continue;
          const inScope =
            rule.scope === "line"
              ? w.line === l.line
              : l.endLine !== undefined && w.line >= l.line && w.line <= l.endLine;
          if (inScope)
            expect(isMoreSevere(l.severity, w.severity), `${w.ruleId} > ${l.ruleId}`).toBe(false);
        }
      }
    }
  });
});
