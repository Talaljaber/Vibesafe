// ─────────────────────────────────────────────────────────────────────────────
// npm Advisory Detector (offline)
//
// Matches package.json dependencies and lockfile-resolved versions against the
// curated advisory list in patterns/npm-advisories.ts. No network.
//
// Confidence: a lockfile-resolved version or an exact pin is `high`. A range with no
// lockfile entry is `medium` when its lowest admitted version is affected (a fresh
// install may or may not pick a fixed release), and `low` when a lockfile exists but
// could not be read. A range that the lockfile resolves to a fixed version is never
// reported. devDependencies are one severity lower unless the package is build
// tooling; packages only present in the lockfile (transitive) are one lower as well.
// ─────────────────────────────────────────────────────────────────────────────

import type {
  Confidence,
  Detector,
  Finding,
  ScanContext,
  Severity,
} from "@talaljaber/vibesafe-shared";
import { makeFinding } from "./utils/finding.js";
import {
  compareVersions,
  formatVersion,
  minVersion,
  parseRange,
  parseVersion,
  satisfies,
  classifySpec,
} from "./utils/semver.js";
import {
  DirectClaims,
  findLockfile,
  manifestFiles,
  parseManifest,
  type LockfileInfo,
  type ManifestDependency,
} from "./utils/deps-manifest.js";
import { NPM_ADVISORIES, DATASET_DATE, type NpmAdvisory } from "./patterns/npm-advisories.js";

const LOWER: Record<Severity, Severity> = {
  critical: "high",
  high: "medium",
  medium: "low",
  low: "low",
};
const RANK: Record<Severity, number> = { critical: 3, high: 2, medium: 1, low: 0 };

function capFor(confidence: Confidence, severity: Severity): Severity {
  if (confidence === "low" && RANK[severity] > RANK.medium) return "medium";
  if (confidence !== "high" && severity === "critical") return "high";
  return severity;
}

const AI_FIX_PROMPT =
  "One of my npm dependencies resolves to a version with a published security advisory. " +
  "Upgrade that package to the first fixed release on the same major version (or to the latest " +
  "supported release if that major line is end-of-life), reinstall so the lockfile records the " +
  "fixed version, and adapt any code broken by the upgrade. If the package is only a transitive " +
  "dependency, upgrade the direct dependency that pulls it in, or add an npm `overrides`, " +
  "`pnpm.overrides` or yarn `resolutions` entry that forces the fixed version. Do not remove the " +
  "package or suppress the warning, and run the tests afterwards.";

const ADVISORIES_BY_NAME = (() => {
  const map = new Map<string, NpmAdvisory[]>();
  for (const a of NPM_ADVISORIES) map.set(a.name, [...(map.get(a.name) ?? []), a]);
  return map;
})();

/** The first fixed release above `version`, preferring its own major line. */
function fixedHint(advisory: NpmAdvisory, version: string | undefined): string {
  const v = version ? parseVersion(version) : null;
  const above = advisory.fixed.filter((f) => !v || compareVersions(f, v) > 0);
  const sameMajor = v ? above.find((f) => parseVersion(f)?.major === v.major) : undefined;
  return sameMajor ?? above[0] ?? advisory.fixed[advisory.fixed.length - 1] ?? "the latest release";
}

interface Match {
  advisory: NpmAdvisory;
  /** Concrete affected version (resolved, pinned or the range minimum). */
  version: string;
  confidence: Confidence;
  how: "lockfile" | "pinned" | "range";
}

export class NpmAdvisoryDetector implements Detector {
  id = "npm-advisory-detector";
  name = "Known Vulnerable npm Versions";
  category = "dependency" as const;
  description = `Flags npm dependencies whose pinned or lockfile-resolved version is affected by a known advisory (offline list reviewed ${DATASET_DATE}).`;

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    try {
      const lockCache = new Map<string, LockfileInfo>();
      const claims = new DirectClaims();
      let warnedEmpty = false;

      for (const file of manifestFiles(context)) {
        const manifest = parseManifest(file, await context.readFile(file));
        if (!manifest) continue;
        const lock = await findLockfile(context, file, lockCache);
        if (lock.file) {
          for (const d of manifest.deps)
            claims.claim(lock.file, d, lock.versions.get(d.name) ?? []);
        }
        if (lock.state === "empty" && !warnedEmpty) {
          warnedEmpty = true;
          context.addWarning?.(
            `Could not read ${lock.file} (too large or unreadable); dependency versions were judged from package.json ranges only, at low confidence.`,
          );
        }
        for (const dep of manifest.deps) {
          const advisories = ADVISORIES_BY_NAME.get(dep.name);
          if (!advisories) continue;
          for (const advisory of advisories) {
            const match = this.matchDirect(dep, advisory, lock);
            if (match) findings.push(this.directFinding(file, dep, match));
          }
        }
      }

      // Transitive: lockfile versions no manifest accounts for directly, including
      // nested copies of a package that is also a direct dependency.
      for (const [lockFile, info] of lockCache) {
        if (info.state !== "ok") continue;
        for (const [name, advisories] of ADVISORIES_BY_NAME) {
          const entries = claims.unclaimed(lockFile, name, info.versions.get(name) ?? []);
          if (entries.length === 0) continue;
          for (const advisory of advisories) {
            const hits = entries.filter((e) => satisfies(e.version, advisory.affected));
            const first = hits[0];
            if (!first) continue;
            findings.push(
              this.transitiveFinding(
                lockFile,
                advisory,
                hits.map((h) => h.version),
                first.line,
              ),
            );
          }
        }
      }
    } catch {
      // Never throw from a detector.
    }
    return findings;
  }

  private matchDirect(
    dep: ManifestDependency,
    advisory: NpmAdvisory,
    lock: LockfileInfo,
  ): Match | null {
    const kind = classifySpec(dep.spec);
    if (kind !== "exact" && kind !== "range") return null;
    const range = parseRange(dep.spec);
    if (!range) return null;

    // 1. The lockfile's resolution wins when it has one that fits the spec.
    const resolved = (lock.versions.get(dep.name) ?? []).filter((e) => satisfies(e.version, range));
    if (resolved.length > 0) {
      const hit = resolved.find((e) => satisfies(e.version, advisory.affected));
      return hit ? { advisory, version: hit.version, confidence: "high", how: "lockfile" } : null;
    }

    // 2. An exact pin is what gets installed.
    if (kind === "exact") {
      const pinned = parseVersion(dep.spec);
      if (!pinned || !satisfies(pinned, advisory.affected)) return null;
      return { advisory, version: formatVersion(pinned), confidence: "high", how: "pinned" };
    }

    // 3. An open range: report only when its lowest admitted version is affected.
    const min = minVersion(range);
    if (!min || !satisfies(min, advisory.affected)) return null;
    return {
      advisory,
      version: formatVersion(min),
      confidence: lock.state === "empty" ? "low" : "medium",
      how: "range",
    };
  }

  private directFinding(file: string, dep: ManifestDependency, m: Match): Finding {
    const { advisory } = m;
    let severity = advisory.severity;
    if (dep.section === "devDependencies" && !advisory.buildTool) severity = LOWER[severity];
    severity = capFor(m.confidence, severity);
    const fix = fixedHint(advisory, m.version);
    const which =
      m.how === "lockfile"
        ? `resolves to ${advisory.name} ${m.version} (per the lockfile)`
        : m.how === "pinned"
          ? `pins ${advisory.name} to ${m.version}`
          : `allows ${advisory.name} versions as old as ${m.version}`;
    return makeFinding({
      category: "dependency",
      ruleId: "dependency/known-vulnerable-version",
      title: `${advisory.name} ${m.version} is affected by ${advisory.cve}`,
      severity,
      confidence: m.confidence,
      file,
      line: dep.line,
      evidence: dep.text ?? `"${advisory.name}": "${m.version}"`,
      discriminator: `${dep.section}:${advisory.name}:${advisory.cve}`,
      plainEnglishProblem: `Your package.json ${which}, which is affected by ${advisory.cve}: ${advisory.summary}.${
        m.how === "range"
          ? " The range also admits fixed releases, so check what your install actually resolved."
          : ""
      }`,
      whyItMatters:
        dep.section === "devDependencies" && !advisory.buildTool
          ? "It is a devDependency, so production exposure is lower, but it still runs on developer machines and in CI, and published advisories are what attackers scan for first."
          : "Known, published vulnerabilities are the first thing automated scanners and attackers look for. A fix exists, so staying on the affected version leaves an easy door open.",
      fixSteps: [
        `Upgrade ${advisory.name} to ${fix} or later (the first fixed release on your major line).`,
        "Reinstall so the lockfile records the fixed version, then commit package.json and the lockfile together.",
        "Run your tests and re-run vibesafe scan to confirm the advisory no longer matches.",
      ],
      aiFixPrompt: AI_FIX_PROMPT,
    });
  }

  private transitiveFinding(
    lockFile: string,
    advisory: NpmAdvisory,
    versions: string[],
    line: number | undefined,
  ): Finding {
    const list = versions.slice(0, 5).join(", ");
    return makeFinding({
      category: "dependency",
      ruleId: "dependency/known-vulnerable-version",
      title: `Lockfile resolves ${advisory.name} ${versions[0]} (${advisory.cve})`,
      severity: LOWER[advisory.severity],
      confidence: "high",
      file: lockFile,
      line,
      evidence: `${advisory.name}@${list}`,
      discriminator: `transitive:${advisory.name}:${advisory.cve}`,
      plainEnglishProblem: `Your lockfile installs ${advisory.name} ${list} as an indirect dependency, which is affected by ${advisory.cve}: ${advisory.summary}.`,
      whyItMatters:
        "Indirect dependencies run with the same privileges as your own code. Whether this flaw is reachable depends on how the parent package uses it, so it is reported one level lower than for a direct dependency.",
      fixSteps: [
        `Run \`npm ls ${advisory.name}\` (or \`pnpm why ${advisory.name}\` / \`yarn why ${advisory.name}\`) to find which dependency pulls it in, and upgrade that one.`,
        `If no fixed parent release exists, force ${advisory.name} ${fixedHint(advisory, versions[0])} or later with npm \`overrides\`, \`pnpm.overrides\` or yarn \`resolutions\`.`,
        "Reinstall, commit the updated lockfile, and re-run vibesafe scan.",
      ],
      aiFixPrompt: AI_FIX_PROMPT,
    });
  }
}
