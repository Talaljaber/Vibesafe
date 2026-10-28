// ─────────────────────────────────────────────────────────────────────────────
// Dependency Detector
//
// Scans package.json for risky patterns: suspicious install scripts,
// and abnormally high dependency counts in the root package.json.
// (No typosquatting detection is implemented.)
// ─────────────────────────────────────────────────────────────────────────────

import type { Detector, Finding, ScanContext } from "@vibesafe/shared";
import { CATEGORY_PREFIX, createFindingId } from "@vibesafe/shared";
import { sanitizeEvidence } from "./utils/sanitize-evidence.js";

/** Scripts that run automatically during npm install — a common supply-chain attack vector. */
const RISKY_SCRIPT_KEYS = ["preinstall", "postinstall", "install"];

/** Threshold for direct dependency count before flagging. */
const MAX_DIRECT_DEPS = 80;

export class DependencyDetector implements Detector {
  id = "dependency-detector";
  name = "Risky Dependency Detection";
  category = "dependency" as const;
  description =
    "Detects dangerous install scripts, excessive dependency counts, and suspicious patterns in package.json.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Only the root package.json: nested ones (fixtures, workspaces) must not be picked up
    const packageJsonPath = context.files.find((f) => f.replace(/\\/g, "/") === "package.json");
    if (!packageJsonPath) return findings;

    let pkg: Record<string, unknown>;
    try {
      const raw = await context.readFile(packageJsonPath);
      pkg = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      return findings; // unparseable package.json — skip
    }

    const scripts = (pkg.scripts as Record<string, string> | undefined) ?? {};
    const deps = (pkg.dependencies as Record<string, string> | undefined) ?? {};

    // Install scripts of a private (never published) package only affect the project's own
    // contributors, so they are lower risk than in a published package.
    const isPrivate = pkg.private === true;

    // 1. Detect risky lifecycle scripts
    for (const scriptKey of RISKY_SCRIPT_KEYS) {
      if (scriptKey in scripts) {
        const scriptValue = scripts[scriptKey];
        findings.push({
          id: createFindingId(CATEGORY_PREFIX.dependency, "dependency/risky-install-script", packageJsonPath, undefined, scriptKey),
          ruleId: "dependency/risky-install-script",
          title: `Risky lifecycle script: "${scriptKey}"`,
          severity: isPrivate ? "low" : "high",
          category: "dependency",
          deployBlocking: false,
          confidence: "medium",
          file: packageJsonPath,
          evidence: sanitizeEvidence(`"${scriptKey}": "${scriptValue}"`),
          plainEnglishProblem: `Your package.json has a "${scriptKey}" script that runs automatically when someone installs your project.`,
          whyItMatters:
            "Malicious packages sometimes use install scripts to run harmful code on developer machines. Having your own install scripts also increases the attack surface.",
          fixSteps: [
            `Review the "${scriptKey}" script and confirm it is necessary.`,
            "If it's a build step, consider moving it to a separate manual command.",
          ],
          autoFixAvailable: false,
        });
      }
    }

    // 2. Flag excessive direct dependency count
    const directDepCount = Object.keys(deps).length;
    if (directDepCount > MAX_DIRECT_DEPS) {
      findings.push({
        id: createFindingId(CATEGORY_PREFIX.dependency, "dependency/excessive-dependencies", packageJsonPath),
        ruleId: "dependency/excessive-dependencies",
        title: `High dependency count: ${directDepCount} direct dependencies`,
        severity: "low",
        category: "dependency",
        deployBlocking: false,
        confidence: "high",
        file: packageJsonPath,
        evidence: `${directDepCount} direct dependencies`,
        plainEnglishProblem: `Your project has ${directDepCount} direct dependencies, which is unusually high.`,
        whyItMatters:
          "More dependencies means a larger attack surface. Each package you install could potentially be compromised in a supply-chain attack.",
        fixSteps: [
          "Review your dependencies and remove any you no longer use.",
          "Run `npx depcheck` to find unused dependencies.",
        ],
        autoFixAvailable: false,
      });
    }

    return findings;
  }
}
