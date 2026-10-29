import type { Finding, Severity } from "@talaljaber/vibesafe-shared";

type Override = "off" | Severity;

/**
 * Linear-time `*` wildcard match (no regex, so no catastrophic backtracking
 * on user-controlled keys). `*` matches any run of characters.
 */
function globMatch(glob: string, text: string): boolean {
  let g = 0;
  let t = 0;
  let star = -1;
  let mark = 0;
  while (t < text.length) {
    if (g < glob.length && glob[g] === "*") {
      star = g++;
      mark = t;
    } else if (g < glob.length && glob[g] === text[t]) {
      g++;
      t++;
    } else if (star !== -1) {
      g = star + 1;
      t = ++mark;
    } else {
      return false;
    }
  }
  while (g < glob.length && glob[g] === "*") g++;
  return g === glob.length;
}

/**
 * Resolves the override for a ruleId. An exact key wins; otherwise the most
 * specific (longest) matching `*` glob wins.
 */
export function resolveOverride(
  ruleId: string,
  overrides: Record<string, Override>,
): Override | undefined {
  if (Object.prototype.hasOwnProperty.call(overrides, ruleId)) return overrides[ruleId];
  let best: string | undefined;
  for (const key of Object.keys(overrides)) {
    if (!key.includes("*")) continue;
    if (globMatch(key, ruleId) && (best === undefined || key.length > best.length)) {
      best = key;
    }
  }
  return best === undefined ? undefined : overrides[best];
}

export interface RuleOverrideResult {
  findings: Finding[];
  /** Findings dropped because their rule is set to "off". */
  suppressed: number;
  /** Findings whose severity was replaced. */
  reclassified: number;
}

/** Like applyRuleOverrides, but also reports how many findings were affected. */
export function applyRuleOverridesWithStats(
  findings: Finding[],
  overrides: Record<string, Override> | undefined,
): RuleOverrideResult {
  if (!overrides || Object.keys(overrides).length === 0) {
    return { findings, suppressed: 0, reclassified: 0 };
  }
  const out: Finding[] = [];
  let suppressed = 0;
  let reclassified = 0;
  for (const f of findings) {
    const o = resolveOverride(f.ruleId, overrides);
    if (o === undefined) out.push(f);
    else if (o === "off") suppressed++;
    else {
      reclassified++;
      // An explicit severity wins over a detector's own deployBlocking flag.
      out.push({ ...f, severity: o, deployBlocking: o === "critical" });
    }
  }
  return { findings: out, suppressed, reclassified };
}

/** Drops "off" findings and applies severity overrides. Callers re-sort/score. */
export function applyRuleOverrides(
  findings: Finding[],
  overrides: Record<string, Override> | undefined,
): Finding[] {
  return applyRuleOverridesWithStats(findings, overrides).findings;
}
