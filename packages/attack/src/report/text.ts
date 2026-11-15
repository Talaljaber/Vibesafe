import type { AttackResult, AttackRun, Ledger, RetestDiff } from "../types.js";

/** Collapses a repo- or response-controlled string to one safe, bounded line. */
export function oneLine(value: string, max = 200): string {
  const cleaned = value
    .replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, " ")
    .replace(/`/g, "'")
    .replace(/\s+/g, " ")
    .trim();
  return cleaned.length > max ? `${cleaned.slice(0, max - 1)}\u2026` : cleaned;
}

/** Key names are emitted only when they look like plain identifiers; anything else is "<key>". */
export function safeKey(key: string): string {
  return /^[\w.-]{1,64}$/.test(key) ? key : "<key>";
}

export function safeLabel(label: string): string {
  return /^[\w.-]{1,16}$/.test(label) ? label : "?";
}

export function safeId(id: string): string {
  return /^[\w.-]{1,40}$/.test(id) ? id : "ATK-invalid";
}

export function routeText(r: Pick<AttackResult, "route" | "method">): string {
  if (!r.route) return "";
  return oneLine(`${r.method ? `${r.method} ` : ""}${r.route}`, 120);
}

export function ledgerLine(l: Ledger): string {
  return `Static flagged ${l.staticFlagged} · live confirmed ${l.confirmed} · refuted ${l.refuted} · couldn't test ${l.untested}`;
}

/** Retest runs split "refuted" into fixed & verified (BLOCKED on retest) and still-refuted. */
export function retestCounts(run: AttackRun): { fixed: number; refuted: number } | undefined {
  if (run.mode !== "retest" || !run.diff || run.diff.length === 0) return undefined;
  const fixed = run.diff.filter((d) => d.state === "BLOCKED").length;
  return { fixed, refuted: Math.max(0, run.ledger.refuted - fixed) };
}

/** Ledger line for a run; baseline output is unchanged, retests call out fixed & verified. */
export function runLedgerLine(run: AttackRun): string {
  const c = retestCounts(run);
  const l = run.ledger;
  if (!c) return ledgerLine(l);
  return `Static flagged ${l.staticFlagged} · fixed & verified ${c.fixed} · still vulnerable ${l.confirmed} · refuted ${c.refuted} · couldn't test ${l.untested}`;
}

export function diffFor(run: AttackRun, id: string): RetestDiff | undefined {
  return run.diff?.find((d) => d.attackId === id);
}
