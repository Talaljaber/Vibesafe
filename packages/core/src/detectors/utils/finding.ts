import {
  CATEGORY_PREFIX,
  createFindingId,
  type Confidence,
  type Finding,
  type FindingCategory,
  type Severity,
} from "@talaljaber/vibesafe-shared";
import { sanitizeEvidence } from "./sanitize-evidence.js";

/** Everything a detector supplies to build a Finding; see {@link makeFinding}. */
export interface FindingInput {
  category: FindingCategory;
  /** `<category>/<kebab-slug>`; must start with `${category}/`. */
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  file?: string | undefined;
  line?: number | undefined;
  endLine?: number | undefined;
  column?: number | undefined;
  /** Raw source text; always passed through sanitizeEvidence (secrets redacted). */
  evidence?: string | undefined;
  /** Distinguishes several findings of one rule on one line; defaults to the evidence. */
  discriminator?: string | undefined;
  plainEnglishProblem: string;
  whyItMatters: string;
  fixSteps: string[];
  /** Static copy-paste prompt for this rule. Never include repo-derived text. */
  aiFixPrompt: string;
  learnMoreUrl?: string | undefined;
  /** Defaults to `severity === "critical" && confidence === "high"`. */
  deployBlocking?: boolean | undefined;
  /** Defaults to false. */
  autoFixAvailable?: boolean | undefined;
}

/**
 * Builds a Finding with a deterministic id
 * (`createFindingId(prefix, ruleId, file, line, discriminator ?? evidence)`, evidence
 * as sanitized). Throws when `ruleId` does not start with `${category}/` — a
 * programming error caught by the detector's own tests.
 *
 * New detectors must use this. Legacy detectors are never migrated: their ids would
 * change and users' baselines and inline ignores by id would break.
 */
export function makeFinding(input: FindingInput): Finding {
  const prefix = `${input.category}/`;
  if (!input.ruleId.startsWith(prefix) || input.ruleId.length === prefix.length) {
    throw new Error(`ruleId "${input.ruleId}" must start with "${prefix}" and name a rule.`);
  }
  const evidence = input.evidence === undefined ? undefined : sanitizeEvidence(input.evidence);
  const finding: Finding = {
    id: createFindingId(
      CATEGORY_PREFIX[input.category],
      input.ruleId,
      input.file,
      input.line,
      input.discriminator ?? evidence,
    ),
    ruleId: input.ruleId,
    title: input.title,
    severity: input.severity,
    category: input.category,
    deployBlocking:
      input.deployBlocking ?? (input.severity === "critical" && input.confidence === "high"),
    confidence: input.confidence,
    plainEnglishProblem: input.plainEnglishProblem,
    whyItMatters: input.whyItMatters,
    fixSteps: input.fixSteps,
    autoFixAvailable: input.autoFixAvailable ?? false,
    aiFixPrompt: input.aiFixPrompt,
  };
  if (input.file !== undefined) finding.file = input.file;
  if (input.line !== undefined) finding.line = input.line;
  if (input.endLine !== undefined) finding.endLine = input.endLine;
  if (input.column !== undefined) finding.column = input.column;
  if (evidence !== undefined) finding.evidence = evidence;
  if (input.learnMoreUrl !== undefined) finding.learnMoreUrl = input.learnMoreUrl;
  return finding;
}

/**
 * Throws when a finding breaks the severity rubric: `critical` requires
 * `confidence: "high"`, and `confidence: "low"` caps severity at `medium`.
 * Findings whose ruleId is in `legacyAllow` are skipped (pre-rubric detectors).
 */
export function assertFindingRubric(f: Finding, legacyAllow?: ReadonlySet<string>): void {
  if (legacyAllow?.has(f.ruleId)) return;
  if (f.severity === "critical" && f.confidence !== "high") {
    throw new Error(`${f.ruleId}: critical findings need confidence "high" (got ${f.confidence}).`);
  }
  if (f.confidence === "low" && (f.severity === "critical" || f.severity === "high")) {
    throw new Error(
      `${f.ruleId}: low-confidence findings are capped at medium (got ${f.severity}).`,
    );
  }
}
