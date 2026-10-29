import type { DeployStatus, Finding } from "@talaljaber/vibesafe-shared";

export interface ResultDelta {
  added: Finding[];
  resolved: Finding[];
  scoreBefore: number;
  scoreAfter: number;
  scoreChange: number;
  statusAfter: DeployStatus;
}

export interface Snapshot {
  findings: Finding[];
  score: number;
  deployStatus: DeployStatus;
}

/**
 * Identity of a finding across rescans. The finding id embeds the line number,
 * so it changes when unrelated edits shift code; the delta instead keys on
 * rule + file + evidence (falling back to title), with an occurrence index so
 * duplicates are counted individually.
 *
 * Limitation: evidence is already redacted by sanitizeEvidence, so replacing one
 * secret with another that redacts to the same string is reported as unchanged.
 */
function identityKeys(findings: Finding[]): Map<string, Finding> {
  const seen = new Map<string, number>();
  const out = new Map<string, Finding>();
  for (const f of findings) {
    const base = [f.ruleId, f.file ?? "", f.evidence ?? f.title].join("\0");
    const n = seen.get(base) ?? 0;
    seen.set(base, n + 1);
    out.set(`${base}\0${n}`, f);
  }
  return out;
}

/** Computes new/resolved findings and the score change between two snapshots. */
export function computeDelta(before: Snapshot, after: Snapshot): ResultDelta {
  const a = identityKeys(before.findings);
  const b = identityKeys(after.findings);
  const added: Finding[] = [];
  const resolved: Finding[] = [];
  for (const [key, f] of b) if (!a.has(key)) added.push(f);
  for (const [key, f] of a) if (!b.has(key)) resolved.push(f);
  return {
    added,
    resolved,
    scoreBefore: before.score,
    scoreAfter: after.score,
    scoreChange: after.score - before.score,
    statusAfter: after.deployStatus,
  };
}
