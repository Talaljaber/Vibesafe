// ─────────────────────────────────────────────────────────────────────────────
// Typosquat Detector
//
// 1. Exact deny list: names published as malware imitating a popular package
//    (critical, high confidence: depending on one is never intended).
// 2. Conservative look-alike check: an unscoped name of 5+ characters that is one
//    edit (insert, delete, substitute or swap adjacent) away from a popular package,
//    and is neither popular itself nor a known legitimate neighbour (medium, low
//    confidence: it is a hint to double-check the spelling, not proof of malware).
// ─────────────────────────────────────────────────────────────────────────────

import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { makeFinding } from "./utils/finding.js";
import { manifestFiles, parseManifest, isValidPackageName } from "./utils/deps-manifest.js";
import {
  KNOWN_TYPOSQUATS,
  LEGITIMATE_NEIGHBOURS,
  POPULAR_PACKAGES,
  TOP_PACKAGES,
} from "./patterns/npm-typosquats.js";

const POPULAR = new Set(POPULAR_PACKAGES);
const NEIGHBOURS = new Set(LEGITIMATE_NEIGHBOURS);
const DENY = new Map(Object.entries(KNOWN_TYPOSQUATS));

/** True when a and b are at most one edit apart (Damerau, adjacent swap counts as one). */
export function withinOneEdit(a: string, b: string): boolean {
  if (a === b) return true;
  const la = a.length;
  const lb = b.length;
  if (Math.abs(la - lb) > 1) return false;
  if (la === lb) {
    let first = -1;
    let diffs = 0;
    for (let i = 0; i < la; i++) {
      if (a[i] !== b[i]) {
        if (diffs === 0) first = i;
        diffs++;
        if (diffs > 2) return false;
      }
    }
    if (diffs <= 1) return true;
    // Exactly two differences: only an adjacent transposition counts as one edit.
    return a[first] === b[first + 1] && a[first + 1] === b[first] && first + 1 < la;
  }
  const [s, l] = la < lb ? [a, b] : [b, a];
  let i = 0;
  let j = 0;
  let skipped = false;
  while (i < s.length && j < l.length) {
    if (s[i] === l[j]) {
      i++;
      j++;
    } else {
      if (skipped) return false;
      skipped = true;
      j++;
    }
  }
  return true;
}

/** True when a is b with one letter dropped or one letter doubled (length differs by one). */
function dropOrDouble(name: string, top: string): boolean {
  if (name.length === top.length - 1) return withinOneEdit(name, top);
  if (name.length !== top.length + 1) return false;
  for (let i = 1; i < name.length; i++) {
    if (name[i] === name[i - 1] && name.slice(0, i) + name.slice(i + 1) === top) return true;
  }
  return false;
}

/** True when a and b (same length) differ by exactly one adjacent transposition. */
function adjacentSwap(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let i = 0;
  while (i < a.length && a[i] === b[i]) i++;
  return (
    i + 1 < a.length && a[i] === b[i + 1] && a[i + 1] === b[i] && a.slice(i + 2) === b.slice(i + 2)
  );
}

/** The top package `name` is a transposition, doubled or dropped letter of, or undefined. */
export function topLookAlikeTarget(name: string): string | undefined {
  if (name.length < 5 || name.startsWith("@")) return undefined;
  if (POPULAR.has(name) || NEIGHBOURS.has(name)) return undefined;
  for (const top of TOP_PACKAGES) {
    if (top.length < 4 || Math.abs(top.length - name.length) > 1) continue;
    if (name.length === top.length ? adjacentSwap(name, top) : dropOrDouble(name, top)) return top;
  }
  return undefined;
}

/** The popular package `name` probably meant to be, or undefined. */
export function lookAlikeTarget(name: string): string | undefined {
  if (name.length < 5 || name.startsWith("@")) return undefined;
  if (POPULAR.has(name) || NEIGHBOURS.has(name)) return undefined;
  for (const popular of POPULAR_PACKAGES) {
    if (popular.length < 4) continue;
    if (withinOneEdit(name, popular)) return popular;
  }
  return undefined;
}

const DENY_PROMPT =
  "My package.json depends on a package whose name is a known malicious typosquat of a popular " +
  "package. Remove it from package.json, install the legitimate package it imitates instead, " +
  "regenerate the lockfile, and check that no install script from it ran: rotate any secrets " +
  "(environment variables, tokens, SSH keys) that were present on machines or CI runners where " +
  "it was installed.";

const LOOKALIKE_PROMPT =
  "My package.json lists a dependency whose name is one character away from a popular package. " +
  "Check on npmjs.com whether it is the package I meant (publisher, download count, repository). " +
  "If it is a misspelling, replace it with the correct package name, reinstall to update the " +
  "lockfile, and fix the imports. If it is intentional, leave it and note why in a comment in the " +
  "PR.";

export class TyposquatDetector implements Detector {
  id = "typosquat-detector";
  name = "npm Typosquat Detection";
  category = "dependency" as const;
  description =
    "Flags dependencies named like known malicious typosquats, and names one edit away from a popular package.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    try {
      for (const file of manifestFiles(context)) {
        const manifest = parseManifest(file, await context.readFile(file));
        if (!manifest) continue;
        for (const dep of manifest.deps) {
          if (!isValidPackageName(dep.name)) continue;
          const imitated = DENY.get(dep.name);
          if (imitated !== undefined) {
            findings.push(
              makeFinding({
                category: "dependency",
                ruleId: "dependency/typosquat-package",
                title: `"${dep.name}" is a known malicious typosquat of "${imitated}"`,
                severity: "critical",
                confidence: "high",
                file,
                line: dep.line,
                evidence: dep.text ?? `"${dep.name}"`,
                discriminator: `${dep.section}:${dep.name}`,
                plainEnglishProblem: `Your package.json depends on "${dep.name}", a package name that was published as malware imitating "${imitated}".`,
                whyItMatters:
                  "Typosquats like this one ran install scripts that stole environment variables (API keys, database URLs, tokens) from every machine and CI runner that installed them. Even when npm has since replaced it with a placeholder, the dependency is a mistake that a re-published version could exploit.",
                fixSteps: [
                  `Remove "${dep.name}" and install "${imitated}" instead.`,
                  "Delete node_modules and regenerate the lockfile.",
                  "Rotate any secrets that were present where it was installed (local .env files, CI secrets).",
                ],
                aiFixPrompt: DENY_PROMPT,
              }),
            );
            continue;
          }
          const topTarget = topLookAlikeTarget(dep.name);
          const target = topTarget ?? lookAlikeTarget(dep.name);
          if (target === undefined) continue;
          const strong = topTarget !== undefined;
          findings.push(
            makeFinding({
              category: "dependency",
              ruleId: "dependency/typosquat-package",
              title: `"${dep.name}" looks like a misspelling of "${target}"`,
              severity: strong ? "high" : "medium",
              confidence: strong ? "medium" : "low",
              file,
              line: dep.line,
              evidence: dep.text ?? `"${dep.name}"`,
              discriminator: `${dep.section}:${dep.name}`,
              plainEnglishProblem: `Your package.json depends on "${dep.name}", which is one character away from the popular package "${target}".`,
              whyItMatters:
                "Attackers publish packages with names one typo away from popular ones so that a slip in `npm install` (or an AI suggestion) installs their code. It may be a legitimate package, so check before trusting it.",
              fixSteps: [
                `Check on npmjs.com that "${dep.name}" is the package you meant (publisher, downloads, repository link).`,
                `If you meant "${target}", replace it and reinstall.`,
                "If it is intentional, keep it: this check only hints at a possible misspelling.",
              ],
              aiFixPrompt: LOOKALIKE_PROMPT,
            }),
          );
        }
      }
    } catch {
      // Never throw from a detector.
    }
    return findings;
  }
}
