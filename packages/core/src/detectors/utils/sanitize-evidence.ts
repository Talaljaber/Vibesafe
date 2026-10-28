import { redactSecret } from "@vibesafe/shared";
import { SECRET_PATTERNS } from "../patterns/secret-patterns.js";

/** Default maximum length of an `evidence` string. */
export const MAX_EVIDENCE_LENGTH = 200;

const URL_CREDENTIALS_RE = /([a-z][a-z0-9+.-]*:\/\/)([^\s:/@'"`]+):([^\s@'"`]+)@/gi;

/**
 * Make a source line safe to show as finding evidence: trims it, redacts anything
 * matching a known secret pattern (only the captured value for patterns that
 * declare `valueGroup`), masks `scheme://user:pass@` credentials, and truncates.
 *
 * Lives in core (not shared) because the patterns live here.
 */
export function sanitizeEvidence(line: string, maxLength: number = MAX_EVIDENCE_LENGTH): string {
  let out = line.trim();

  for (const pattern of SECRET_PATTERNS) {
    const flags = pattern.regex.flags.includes("g") ? pattern.regex.flags : pattern.regex.flags + "g";
    const re = new RegExp(pattern.regex.source, flags);
    out = out.replace(re, (...args: unknown[]) => {
      const matched = args[0] as string;
      if (pattern.valueGroup !== undefined) {
        const value = args[pattern.valueGroup];
        if (typeof value === "string" && value.length > 0) {
          return matched.replace(value, () => redactSecret(value));
        }
      }
      return redactSecret(matched);
    });
  }

  out = out.replace(URL_CREDENTIALS_RE, (_m, scheme: string, user: string) => `${scheme}${user}:***@`);

  if (out.length > maxLength) {
    out = out.slice(0, maxLength) + "…";
  }
  return out;
}
