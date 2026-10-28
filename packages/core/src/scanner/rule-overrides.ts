import type { Finding, Severity } from "@vibesafe/shared";

type Override = "off" | Severity;

function globToRegExp(glob: string): RegExp {
  const escaped = glob.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`);
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
    if (globToRegExp(key).test(ruleId) && (best === undefined || key.length > best.length)) {
      best = key;
    }
  }
  return best === undefined ? undefined : overrides[best];
}

/** Drops "off" findings and applies severity overrides. Callers re-sort/score. */
export function applyRuleOverrides(
  findings: Finding[],
  overrides: Record<string, Override> | undefined,
): Finding[] {
  if (!overrides || Object.keys(overrides).length === 0) return findings;
  const out: Finding[] = [];
  for (const f of findings) {
    const o = resolveOverride(f.ruleId, overrides);
    if (o === undefined) out.push(f);
    else if (o === "off") continue;
    else {
      // An explicit severity wins over a detector's own deployBlocking flag.
      out.push({ ...f, severity: o, deployBlocking: o === "critical" });
    }
  }
  return out;
}
