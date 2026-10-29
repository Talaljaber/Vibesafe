import { ALL_CATEGORIES, type Finding } from "@talaljaber/vibesafe-shared";

/**
 * Declares that a specific finding hides a generic one at the same place.
 *
 * Patterns are an exact ruleId (`"validation/missing-body-validation"`) or a whole
 * category (`"injection/*"`). Detectors and group files import this type with
 * `import type` only (a test enforces it) so the scanner never forms an import cycle.
 */
export interface PrecedenceRule {
  /** Pattern of the specific finding that wins. */
  winner: string;
  /** Patterns of the generic findings it hides. */
  losers: readonly string[];
  /**
   * `line`: winner and loser share `file` and `line`.
   * `enclosing`: same `file`, the loser has `line` AND `endLine`, and the winner's line
   * lies within `[loser.line, loser.endLine]` (e.g. a sink inside a flagged handler).
   * A loser without `endLine` is never hidden under `enclosing`.
   */
  scope: "line" | "enclosing";
  /** One sentence explaining why the winner makes the loser redundant. */
  reason: string;
}

const PATTERN_RE = /^([a-z_]+)\/(\*|[a-z0-9][a-z0-9-]*)$/;

/** True when `ruleId` matches an exact-ruleId or `category/*` pattern. */
export function matchesRulePattern(ruleId: string, pattern: string): boolean {
  if (pattern.endsWith("/*")) return ruleId.startsWith(pattern.slice(0, -1));
  return ruleId === pattern;
}

/** True when some ruleId could match both patterns. */
export function patternsOverlap(a: string, b: string): boolean {
  const wa = a.endsWith("/*");
  const wb = b.endsWith("/*");
  if (wa && wb) return a === b;
  if (wa) return matchesRulePattern(b, a);
  if (wb) return matchesRulePattern(a, b);
  return a === b;
}

/**
 * Structural problems with a precedence rule set (empty when valid): malformed
 * patterns, unknown categories, a winner overlapping its own losers, and chains
 * (a winner pattern that overlaps any rule's loser pattern, so a hidden finding
 * could hide another).
 */
export function validatePrecedenceRules(rules: readonly PrecedenceRule[]): string[] {
  const problems: string[] = [];
  const categories: readonly string[] = ALL_CATEGORIES;
  const checkPattern = (p: string, where: string): void => {
    const m = PATTERN_RE.exec(p);
    if (!m) problems.push(`${where}: "${p}" is not "category/slug" or "category/*".`);
    else if (!categories.includes(m[1]!)) problems.push(`${where}: unknown category in "${p}".`);
  };
  rules.forEach((rule, i) => {
    const where = `rule ${i} (${rule.winner})`;
    checkPattern(rule.winner, where);
    if (rule.losers.length === 0) problems.push(`${where}: no losers.`);
    if (rule.reason.trim() === "") problems.push(`${where}: empty reason.`);
    for (const loser of rule.losers) {
      checkPattern(loser, where);
      if (patternsOverlap(rule.winner, loser)) {
        problems.push(`${where}: winner overlaps its own loser "${loser}".`);
      }
    }
  });
  rules.forEach((rule, i) => {
    rules.forEach((other, j) => {
      for (const loser of other.losers) {
        if (i !== j && patternsOverlap(rule.winner, loser)) {
          problems.push(
            `chain: winner "${rule.winner}" (rule ${i}) can be hidden by rule ${j} via "${loser}".`,
          );
        }
      }
    });
  });
  return problems;
}

function inScope(winner: Finding, loser: Finding, scope: PrecedenceRule["scope"]): boolean {
  if (winner === loser || winner.file === undefined || winner.file !== loser.file) return false;
  if (winner.line === undefined || loser.line === undefined) return false;
  if (scope === "line") return winner.line === loser.line;
  if (loser.endLine === undefined) return false;
  return winner.line >= loser.line && winner.line <= loser.endLine;
}

/**
 * Collapses findings with an identical `id` (keeping the first) and hides generic
 * findings that a declared, more specific finding already covers.
 *
 * Runs after inline ignores and rule overrides, so only surviving winners hide losers:
 * a winner turned "off" by the user lets its losers back. Severity and deployBlocking
 * are never inherited (the winner keeps its own, so user overrides stay intact). As a
 * defensive measure a finding that could itself be hidden by some rule never acts as
 * a winner, so the result does not depend on rule or finding order even if a chain
 * slipped past validatePrecedenceRules.
 *
 * `suppressed` counts only precedence-hidden findings, not collapsed duplicates.
 */
export function applyPrecedence(
  findings: Finding[],
  rules: readonly PrecedenceRule[],
): { findings: Finding[]; suppressed: number } {
  const seen = new Set<string>();
  const unique: Finding[] = [];
  for (const f of findings) {
    if (seen.has(f.id)) continue;
    seen.add(f.id);
    unique.push(f);
  }
  if (rules.length === 0) return { findings: unique, suppressed: 0 };

  const isLoserAnywhere = (f: Finding): boolean =>
    rules.some((r) => r.losers.some((l) => matchesRulePattern(f.ruleId, l)));

  const hidden = new Set<Finding>();
  for (const rule of rules) {
    const winners = unique.filter(
      (f) => matchesRulePattern(f.ruleId, rule.winner) && !isLoserAnywhere(f),
    );
    if (winners.length === 0) continue;
    for (const f of unique) {
      if (hidden.has(f)) continue;
      if (!rule.losers.some((l) => matchesRulePattern(f.ruleId, l))) continue;
      if (winners.some((w) => inScope(w, f, rule.scope))) hidden.add(f);
    }
  }
  return { findings: unique.filter((f) => !hidden.has(f)), suppressed: hidden.size };
}
