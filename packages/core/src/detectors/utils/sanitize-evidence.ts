import { redactSecret } from "@talaljaber/vibesafe-shared";
import { SECRET_PATTERNS, type SecretPattern } from "../patterns/secret-patterns.js";

/** Default maximum length of an `evidence` string. */
export const MAX_EVIDENCE_LENGTH = 200;

const URL_CREDENTIALS_RE = /([a-z][a-z0-9+.-]*:\/\/)([^\s:/@'"`]*):([^\s@'"`]+)@/gi;

/**
 * Redacts every match of `pattern` in `text`. For patterns with a `valueGroup`, only that
 * group is redacted, at its exact position in the match (so a password equal to the user
 * name, or contained in the host, is still the part that gets masked).
 */
function redactPattern(text: string, pattern: SecretPattern): string {
  let flags = pattern.regex.flags;
  if (!flags.includes("g")) flags += "g";
  if (!flags.includes("d")) flags += "d";
  const re = new RegExp(pattern.regex.source, flags);
  let out = "";
  let last = 0;
  for (const m of text.matchAll(re)) {
    const matched = m[0];
    const start = m.index ?? 0;
    if (!matched) continue;
    const end = start + matched.length;
    const span = pattern.valueGroup === undefined ? undefined : m.indices?.[pattern.valueGroup];
    out += text.slice(last, start);
    if (span && span[1] > span[0]) {
      out +=
        text.slice(start, span[0]) +
        redactSecret(text.slice(span[0], span[1])) +
        text.slice(span[1], end);
    } else {
      out += redactSecret(matched);
    }
    last = end;
  }
  return last === 0 ? text : out + text.slice(last);
}

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
    out = redactPattern(out, pattern);
  }

  out = out.replace(
    URL_CREDENTIALS_RE,
    (_m, scheme: string, user: string) => `${scheme}${user}:***@`,
  );

  if (out.length > maxLength) {
    out = out.slice(0, maxLength) + "…";
  }
  return out;
}

/**
 * Redacts `value` at its known position (`column`, 0-based) in `line`, leaving every other
 * occurrence of the same text (an identifier that happens to contain a short literal) intact.
 * When the span does not hold `value` (offset drift), every occurrence is redacted instead so
 * the secret can never leak.
 */
export function redactSpan(line: string, column: number, value: string): string {
  if (value.length === 0) return line;
  if (column >= 0 && line.startsWith(value, column)) {
    return line.slice(0, column) + redactSecret(value) + line.slice(column + value.length);
  }
  return line.split(value).join(redactSecret(value));
}
