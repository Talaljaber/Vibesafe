// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Dependency Detector
//
// Scans package.json for risky patterns: suspicious install scripts,
// and abnormally high dependency counts in the root package.json.
// Known-vulnerable versions and typosquats are handled by npm-advisory-detector and
// typosquat-detector.
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { CATEGORY_PREFIX, createFindingId } from "@talaljaber/vibesafe-shared";
import { sanitizeEvidence } from "./utils/sanitize-evidence.js";

/** Scripts that run automatically during npm install â€” a common supply-chain attack vector. */
const RISKY_SCRIPT_KEYS = ["preinstall", "postinstall", "install"];

/** `curl|wget ... | [sudo] sh|bash|zsh|node|python` (single pipe). */
const DOWNLOAD_PIPE_RE =
  /\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:(?:ba|z|da|k)?sh|node|python3?)\b/;
/** `sh -c "$(curl ...)"`, `node -e "$(curl ...)"`, `eval "$(wget ...)"`, `bash <(curl ...)`. */
const DOWNLOAD_SUBST_RE =
  /\b(?:(?:ba|z|da|k)?sh|node|python3?|eval)\b[^;&|]*?(?:\$\(|<\()\s*(?:curl|wget)\b/;
/** `npx -y https://...`: runs a remote package tarball or script. */
const NPX_URL_RE = /\bnpx\s+(?:-\S+\s+)*["']?https?:\/\//;

/** True when an install script downloads remote code and executes it. */
function downloadsAndRuns(script: string): boolean {
  if (script.length > 5000 || !/curl|wget|npx/.test(script)) return false;
  return DOWNLOAD_PIPE_RE.test(script) || DOWNLOAD_SUBST_RE.test(script) || NPX_URL_RE.test(script);
}

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
      return findings; // unparseable package.json â€” skip
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
        const remoteExec = typeof scriptValue === "string" && downloadsAndRuns(scriptValue);
        findings.push({
          id: createFindingId(
            CATEGORY_PREFIX.dependency,
            "dependency/risky-install-script",
            packageJsonPath,
            undefined,
            scriptKey,
          ),
          ruleId: "dependency/risky-install-script",
          title: remoteExec
            ? `Install script downloads and runs a remote script: "${scriptKey}"`
            : `Risky lifecycle script: "${scriptKey}"`,
          severity: remoteExec ? "critical" : isPrivate ? "low" : "high",
          category: "dependency",
          deployBlocking: remoteExec,
          confidence: remoteExec ? "high" : "medium",
          file: packageJsonPath,
          evidence: sanitizeEvidence(`"${scriptKey}": "${scriptValue}"`),
          plainEnglishProblem: remoteExec
            ? `Your "${scriptKey}" script downloads code from the network and executes it every time someone installs the project (developers and CI runners alike).`
            : `Your package.json has a "${scriptKey}" script that runs automatically when someone installs your project.`,
          whyItMatters:
            "Malicious packages sometimes use install scripts to run harmful code on developer machines. Having your own install scripts also increases the attack surface.",
          fixSteps: remoteExec
            ? [
                `Remove the download-and-execute step from "${scriptKey}".`,
                "Install the tool from a package manager or a pinned, checksum-verified release instead.",
              ]
            : [
                `Review the "${scriptKey}" script and confirm it is necessary.`,
                "If it's a build step, consider moving it to a separate manual command.",
              ],
          autoFixAvailable: false,
          aiFixPrompt: remoteExec
            ? `My package.json "${scriptKey}" script downloads a remote script and executes it. Remove that step and install the tool from a package manager or a pinned release whose checksum is verified.`
            : `Review my package.json "${scriptKey}" script, tell me whether it is necessary, and if it is only a build step move it to an explicit manual command.`,
        });
      }
    }

    // 2. Flag excessive direct dependency count
    const directDepCount = Object.keys(deps).length;
    if (directDepCount > MAX_DIRECT_DEPS) {
      findings.push({
        id: createFindingId(
          CATEGORY_PREFIX.dependency,
          "dependency/excessive-dependencies",
          packageJsonPath,
        ),
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
