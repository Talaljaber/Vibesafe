import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { classifyPath, isTestOrFixturePath } from "./utils/file-kind.js";
import { makeFinding } from "./utils/finding.js";
import {
  parseWorkflow,
  type ActionRef,
  type Workflow,
  type WorkflowJob,
  type WorkflowStep,
} from "./utils/yaml-lines.js";

/** Triggers that run in the base repository's context (secrets, write token) for fork PRs. */
const PRIVILEGED_PR_TRIGGERS = new Set(["pull_request_target", "workflow_run"]);

/** References to the pull request's (untrusted) head code. */
const PR_HEAD_RE =
  /github\.event\.pull_request\.head\.(?:sha|ref)\b|github\.head_ref\b|github\.event\.pull_request\.merge_commit_sha\b|github\.event\.workflow_run\.head_(?:sha|branch)\b|github\.event\.workflow_run\.head_repository\.full_name\b|github\.event\.pull_request\.head\.repo\.full_name\b|refs\/pull\/|github\.event\.(?:pull_request\.)?number\b/;
/** Shell commands that fetch or check out PR code. */
const RUN_CHECKOUT_RE =
  /\bgh\s+pr\s+checkout\b|\bgit\s+(?:fetch|checkout|switch|pull)\b[^\n]*(?:pull\/|\$\{\{)/;
/** Job conditions that keep fork PRs out. */
const SAME_REPO_GUARD_RE =
  /head\.repo\.full_name\s*==\s*github\.repository|github\.repository\s*==\s*github\.event\.pull_request\.head\.repo\.full_name|head\.repo\.fork\s*(?:==\s*false|!=\s*true)|!\s*github\.event\.pull_request\.head\.repo\.fork|author_association\s*==\s*['"](?:OWNER|MEMBER|COLLABORATOR)/;
/** Approval gates by label: they help but stay racy (the PR can change after labelling). */
const LABEL_GATE_RE = /github\.event\.label\.name|pull_request\.labels/;

/** Organisations whose actions are maintained by GitHub. */
const FIRST_PARTY_OWNERS = new Set(["actions", "github"]);

function isCheckoutAction(uses: ActionRef | undefined): boolean {
  return (
    uses !== undefined &&
    uses.owner.toLowerCase() === "actions" &&
    uses.repo.toLowerCase() === "checkout"
  );
}

/**
 * GitHub Actions workflow rules: `pull_request_target` / `workflow_run` workflows that
 * check out and run the pull request's code, actions referenced by a branch or with
 * no ref, and `permissions: write-all`. Script injection through `${{ }}` in `run:`
 * is reported by the gha-script-injection detector.
 */
export class GithubWorkflowDetector implements Detector {
  id = "github-workflow-detector";
  name = "GitHub Actions Workflow Security";
  category = "security_config" as const;
  description =
    "Detects pull_request_target/workflow_run jobs that run PR code with secrets, actions pinned to a branch, and write-all permissions.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of context.files) {
      const kind = classifyPath(file);
      if (kind !== "workflow" && kind !== "gh-action") continue;
      if (isTestOrFixturePath(file) && context.config.includeTests !== true) continue;
      try {
        const text = await context.readFile(file);
        if (text.trim() === "") continue;
        const lines = text.split(/\r?\n/);
        const wf = parseWorkflow(text);
        if (kind === "workflow") {
          findings.push(...this.prTargetRule(file, wf, lines));
          findings.push(...this.permissionsRule(file, wf, lines));
        }
        findings.push(...this.unpinnedRule(file, wf, lines));
      } catch {
        // Never throw from a detector.
      }
    }
    return findings;
  }

  private prTargetRule(file: string, wf: Workflow, lines: string[]): Finding[] {
    const trigger = wf.triggers.find((t) => PRIVILEGED_PR_TRIGGERS.has(t.value));
    if (!trigger) return [];
    const out: Finding[] = [];
    for (const job of wf.jobs) {
      if (job.if && SAME_REPO_GUARD_RE.test(job.if.value)) continue;
      const checkoutIdx = job.steps.findIndex((s) => this.checksOutPrHead(s));
      if (checkoutIdx === -1) continue;
      const checkout = job.steps[checkoutIdx]!;
      if (checkout.if && SAME_REPO_GUARD_RE.test(checkout.if.value)) continue;
      const later = job.steps.slice(checkoutIdx + (checkout.run ? 0 : 1));
      const runsCode = later.some((s) => s.run !== undefined || s.uses?.refKind === "local");
      const labelGated = LABEL_GATE_RE.test(job.if?.value ?? "");
      const severe = runsCode && !labelGated;
      out.push(
        makeFinding({
          category: "security_config",
          ruleId: "security_config/gha-pull-request-target-checkout",
          title: `${trigger.value} workflow checks out and runs untrusted pull request code`,
          severity: severe ? "critical" : "high",
          confidence: severe ? "high" : "medium",
          file,
          line: trigger.line,
          endLine: job.endLine,
          evidence: lines[trigger.line - 1] ?? trigger.value,
          discriminator: job.id,
          plainEnglishProblem: `This workflow runs on ${trigger.value}, which executes in the context of the base repository with access to its secrets and a write-capable GITHUB_TOKEN, and job "${job.id}" checks out the pull request's head code (line ${checkout.uses?.line ?? checkout.line})${runsCode ? " and then runs commands on it" : ""}. A pull request from any fork can change build scripts, package.json or config files to run its own code with those privileges.`,
          whyItMatters:
            "This is the classic 'pwn request': an outsider opens a pull request and the workflow runs their code with your secrets, which lets them steal deploy keys and API tokens, push to the repository or publish releases.",
          fixSteps: [
            "Use the `pull_request` trigger for building and testing PR code; it runs fork PRs without secrets and with a read-only token.",
            "If you need privileges (commenting, labelling), split the workflow: an unprivileged `pull_request` job builds and uploads artifacts, and a separate `workflow_run` job with privileges only consumes the artifacts as data, never executing them.",
            "If a privileged job must check out PR code, never run it (no installs, builds, tests or scripts), set `permissions:` to the minimum, and do not expose secrets to that job.",
          ],
          aiFixPrompt:
            "My GitHub Actions workflow uses pull_request_target (or workflow_run) and checks out the pull request's head code, then runs commands with access to repository secrets. Restructure it so untrusted PR code only runs in a `pull_request` workflow without secrets, move any step that needs secrets or write permissions into a separate workflow that never executes PR code, and set minimal `permissions:` on every job.",
        }),
      );
    }
    return out;
  }

  private checksOutPrHead(step: WorkflowStep): boolean {
    if (isCheckoutAction(step.uses)) {
      const ref = step.with["ref"]?.text ?? "";
      const repo = step.with["repository"]?.text ?? "";
      return PR_HEAD_RE.test(ref) || PR_HEAD_RE.test(repo);
    }
    if (step.run) {
      return step.run.lines.some(
        (l) =>
          RUN_CHECKOUT_RE.test(l.value) &&
          (/\bgh\s+pr\s+checkout\b/.test(l.value) || PR_HEAD_RE.test(l.value)),
      );
    }
    return false;
  }

  private permissionsRule(file: string, wf: Workflow, lines: string[]): Finding[] {
    const out: Finding[] = [];
    const scopes: { where: string; line: number; job: WorkflowJob | undefined }[] = [];
    if (wf.permissions?.value?.toLowerCase() === "write-all") {
      scopes.push({ where: "the whole workflow", line: wf.permissions.line, job: undefined });
    }
    for (const job of wf.jobs) {
      if (job.permissions?.value?.toLowerCase() === "write-all") {
        scopes.push({ where: `job "${job.id}"`, line: job.permissions.line, job });
      }
    }
    for (const s of scopes) {
      out.push(
        makeFinding({
          category: "security_config",
          ruleId: "security_config/gha-write-all-permissions",
          title: "Workflow grants write-all permissions to GITHUB_TOKEN",
          severity: "medium",
          confidence: "high",
          file,
          line: s.line,
          evidence: lines[s.line - 1] ?? "permissions: write-all",
          plainEnglishProblem: `\`permissions: write-all\` gives the GITHUB_TOKEN of ${s.where} write access to every scope: code, releases, packages, issues, pull requests and workflow settings.`,
          whyItMatters:
            "If any step is compromised (a malicious action update, a script injection, a poisoned dependency), the attacker can push code, tamper with releases or approve their own changes using this token.",
          fixSteps: [
            "Set `permissions: contents: read` at the top of the workflow.",
            "Grant additional scopes only on the jobs that need them, e.g. `pull-requests: write` for a commenting job.",
          ],
          aiFixPrompt:
            "My GitHub Actions workflow uses `permissions: write-all`. Replace it with least-privilege permissions: `contents: read` at the workflow level, and only the specific write scopes each job actually needs, based on what its steps do.",
        }),
      );
    }
    return out;
  }

  private unpinnedRule(file: string, wf: Workflow, lines: string[]): Finding[] {
    const out: Finding[] = [];
    const refs: ActionRef[] = [];
    for (const job of wf.jobs) {
      if (job.uses) refs.push(job.uses);
      for (const step of job.steps) if (step.uses) refs.push(step.uses);
    }
    for (const ref of refs) {
      if (ref.refKind !== "branch" && ref.refKind !== "none") continue;
      if (ref.owner === "" || ref.repo === "") continue;
      const firstParty = FIRST_PARTY_OWNERS.has(ref.owner.toLowerCase());
      out.push(
        makeFinding({
          category: "security_config",
          ruleId: "security_config/gha-unpinned-action",
          title:
            ref.refKind === "none"
              ? "Action referenced without a version"
              : `Action pinned to the mutable branch @${ref.ref ?? ""}`,
          severity: firstParty ? "low" : "medium",
          confidence: "high",
          file,
          line: ref.line,
          evidence: lines[ref.line - 1] ?? ref.raw,
          discriminator: ref.raw,
          plainEnglishProblem:
            ref.refKind === "none"
              ? "This step uses an action without any version, so it runs whatever the action's default branch contains at the time of each run."
              : "This step uses an action pinned to a branch. Whoever controls that branch decides what code runs in your CI on the next run, with access to the job's secrets and token.",
          whyItMatters:
            "Compromised or hijacked actions have been used to dump CI secrets from thousands of repositories. A branch reference picks up such a change immediately, without any review on your side.",
          fixSteps: [
            "Pin the action to a full 40-character commit SHA, with the version in a comment: `uses: owner/action@<sha> # v1.2.3`.",
            "Let Dependabot or Renovate propose SHA updates so you review each change.",
          ],
          aiFixPrompt:
            "My GitHub Actions workflow references an action by a branch (such as @master or @main) or without a version. Replace it with the full commit SHA of the action's latest release tag, keep the tag in a trailing comment, and add a Dependabot config for the github-actions ecosystem so the pins get updated.",
        }),
      );
    }
    return out;
  }
}
