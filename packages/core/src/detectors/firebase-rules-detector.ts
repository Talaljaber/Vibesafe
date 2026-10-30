import { posix } from "node:path";
import type {
  Confidence,
  Detector,
  Finding,
  ScanContext,
  Severity,
} from "@talaljaber/vibesafe-shared";
import { classifyPath, isTestOrFixturePath } from "./utils/file-kind.js";
import { makeFinding } from "./utils/finding.js";
import { sanitizeEvidence } from "./utils/sanitize-evidence.js";
import { capFindingsPerRule } from "./utils/infra-common.js";
import {
  classifyCondition,
  classifyRtdbValue,
  collectRuleFunctions,
  maskRulesSource,
  nameSensitivity,
  parseDatabaseRules,
  parseRulesFile,
  stripRulesComments,
  type AccessClass,
  type ConditionClass,
  type Sensitivity,
} from "./utils/firebase-rules.js";

const MAX_FILE_CHARS = 500_000;
const MAX_BUILT_PER_FILE = 200;
const LEARN_MORE = "https://firebase.google.com/docs/rules/insecure-rules";

type Product = "firestore" | "storage" | "rtdb";
type Column = "write" | "create" | "read";
type RuleKind = "public-write" | "public-read" | "any-signed-in" | "test-mode";

interface Scope {
  root: boolean;
  /** Last literal path segment of a named scope. */
  name: string;
}

interface Outcome {
  kind: RuleKind;
  severity: Severity;
  confidence: Confidence;
  column: Column;
}

const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const CONFIDENCE_RANK: Record<Confidence, number> = { high: 3, medium: 2, low: 1 };
const COLUMN_RANK: Record<Column, number> = { write: 3, create: 2, read: 1 };

/** The more severe outcome; ties go to the write rule. */
function worse(a: Outcome | undefined, b: Outcome | undefined): Outcome | undefined {
  if (!a) return b;
  if (!b) return a;
  const d =
    SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
    CONFIDENCE_RANK[a.confidence] - CONFIDENCE_RANK[b.confidence] ||
    COLUMN_RANK[a.column] - COLUMN_RANK[b.column];
  return d >= 0 ? a : b;
}

/** Applies the rule table (spec 2.3) to one access class, scope and column. */
function decide(
  cls: AccessClass,
  column: Column,
  scope: Scope,
  product: Product,
): Omit<Outcome, "column"> | undefined {
  const sens: Sensitivity | null = scope.root ? null : nameSensitivity(scope.name);
  if (cls === "open") {
    if (column === "write") {
      return {
        kind: "public-write",
        severity: scope.root ? "critical" : "high",
        confidence: "high",
      };
    }
    if (column === "create") {
      return scope.root
        ? { kind: "public-write", severity: "high", confidence: "high" }
        : undefined;
    }
    if (scope.root) {
      return product === "storage"
        ? { kind: "public-read", severity: "high", confidence: "medium" }
        : { kind: "public-read", severity: "critical", confidence: "high" };
    }
    return sens !== null
      ? { kind: "public-read", severity: "high", confidence: "medium" }
      : undefined;
  }
  if (cls === "test-mode") {
    if (column === "write") {
      return { kind: "test-mode", severity: scope.root ? "critical" : "high", confidence: "high" };
    }
    if (column === "create") {
      return scope.root ? { kind: "test-mode", severity: "high", confidence: "high" } : undefined;
    }
    if (scope.root) return { kind: "test-mode", severity: "high", confidence: "high" };
    return sens !== null
      ? { kind: "test-mode", severity: "high", confidence: "medium" }
      : undefined;
  }
  if (cls === "signed-in") {
    if (column === "create") return undefined;
    if (column === "write") {
      return {
        kind: "any-signed-in",
        severity: "high",
        confidence: scope.root ? "high" : "medium",
      };
    }
    if (scope.root) return { kind: "any-signed-in", severity: "high", confidence: "high" };
    if (sens === "private") {
      return { kind: "any-signed-in", severity: "medium", confidence: "medium" };
    }
    if (sens === "directory") {
      return { kind: "any-signed-in", severity: "medium", confidence: "low" };
    }
  }
  return undefined;
}

const WRITE_METHODS = new Set(["write", "update", "delete"]);
const READ_METHODS = new Set(["read", "get", "list"]);

/** Scope of a Firestore/Storage match path (segments after the service prefix). */
function scopeOfSegments(segments: string[]): Scope {
  const literals = segments.filter((s) => !s.includes("{"));
  const first = segments[0];
  if (segments.length === 0 || (segments.length === 1 && /^\{[^}]*=\*\*\}$/.test(first ?? ""))) {
    return { root: true, name: "" };
  }
  const last = literals[literals.length - 1];
  return last === undefined ? { root: true, name: "" } : { root: false, name: last };
}

/** Scope of an RTDB key path: all-`$` (or empty) paths match every child. */
function scopeOfRtdbPath(path: string[]): Scope {
  const named = path.filter((k) => !k.startsWith("$"));
  const last = named[named.length - 1];
  return path.length === 0 || last === undefined
    ? { root: true, name: "" }
    : { root: false, name: last };
}

function scopeText(scope: Scope, product: Product): string {
  if (scope.root) {
    if (product === "storage") return "every file in your bucket";
    return "every document in your database";
  }
  return `the records in \`${scope.name}\``;
}

interface RuleText {
  title: string;
  problem: (evidence: string, scope: string, expiry: string | undefined, column: Column) => string;
  why: string;
  fix: string[];
  prompt: string;
}

const FIX_COMMON = [
  "Replace any `match /{document=**}` catch-all with explicit matches per collection.",
  "Test the rules with the Firebase emulator and deploy them with `firebase deploy --only firestore:rules` (or `storage`/`database`).",
];

const TEXTS: Record<RuleKind, RuleText & { ruleId: string }> = {
  "public-write": {
    ruleId: "authorization/firebase-rules-public-write",
    title: "Firebase rules let anyone write data",
    problem: (e, s) =>
      `This rule (\`${e}\`) lets anyone on the internet, without signing in, create, change or delete ${s}.`,
    why: "Firebase config (API key, project id) ships in every client, so anyone can call your database directly and bypass your app: wipe data, plant spam or malware, or rewrite other users' records.",
    fix: [
      "Require sign-in and ownership: `allow write: if request.auth != null && request.auth.uid == userId;` under `match /users/{userId}`, or compare `resource.data.ownerId == request.auth.uid`.",
      ...FIX_COMMON,
    ],
    prompt:
      "My Firebase security rules allow public write access. Rewrite the rules so each collection (or storage path) is readable/writable only by its owner (`request.auth.uid` matched against the document id or an owner field), admins use a custom claim, public data is read-only, and validation of `request.resource.data` is kept. Remove catch-all `{document=**}` grants and test-mode time checks. Show the full rules file and the emulator tests that prove another user is denied.",
  },
  "public-read": {
    ruleId: "authorization/firebase-rules-public-read",
    title: "Firebase rules let anyone read private data",
    problem: (e, s) =>
      `This rule (\`${e}\`) lets anyone on the internet, without signing in, read ${s}.`,
    why: "Firebase config (API key, project id) ships in every client, so anyone can query your database directly and scrape every user's data, bypassing your app's checks.",
    fix: [
      "Require sign-in and ownership: `allow read: if request.auth != null && request.auth.uid == userId;` under `match /users/{userId}`, or compare `resource.data.ownerId == request.auth.uid`.",
      ...FIX_COMMON,
    ],
    prompt:
      "My Firebase security rules allow public read access. Rewrite the rules so each collection (or storage path) is readable/writable only by its owner (`request.auth.uid` matched against the document id or an owner field), admins use a custom claim, public data is read-only, and validation of `request.resource.data` is kept. Remove catch-all `{document=**}` grants and test-mode time checks. Show the full rules file and the emulator tests that prove another user is denied.",
  },
  "any-signed-in": {
    ruleId: "authorization/firebase-rules-any-signed-in",
    title: "Firebase rules let any signed-in user access every record",
    problem: (e, s, _x, column) =>
      `This rule (\`${e}\`) only checks that the caller is signed in. Anyone can create an account (or use anonymous sign-in), then ${column === "read" ? "read" : "change"} ${s}.`,
    why: "Sign-up is open to the internet, so 'any signed-in user' is effectively everyone: one throwaway account can read or overwrite every other user's data.",
    fix: [
      "Scope access to the owner: compare `request.auth.uid` with the document id or an owner field such as `resource.data.ownerId`, and use custom claims for admins.",
      ...FIX_COMMON,
    ],
    prompt:
      "My Firebase security rules allow any signed-in user to access every record. Rewrite the rules so each collection (or storage path) is readable/writable only by its owner (`request.auth.uid` matched against the document id or an owner field), admins use a custom claim, public data is read-only, and validation of `request.resource.data` is kept. Remove catch-all `{document=**}` grants and test-mode time checks. Show the full rules file and the emulator tests that prove another user is denied.",
  },
  "test-mode": {
    ruleId: "authorization/firebase-rules-test-mode",
    title: "Firebase rules are still in test mode",
    problem: (e, s, expiry) =>
      `These are Firebase 'test mode' rules (\`${e}\`): anyone can read and write ${s} ${expiry ? `until ${expiry}` : "until the rules are changed"}.`,
    why: "Test-mode rules are meant for the first days of a prototype. Until they expire, anyone with your public Firebase config can read, change or delete your data, and extending the date keeps it open.",
    fix: [
      "Write real rules before launch (owner checks with `request.auth.uid`); never extend the test-mode date.",
      ...FIX_COMMON,
    ],
    prompt:
      "My Firebase security rules allow open test-mode access. Rewrite the rules so each collection (or storage path) is readable/writable only by its owner (`request.auth.uid` matched against the document id or an owner field), admins use a custom claim, public data is read-only, and validation of `request.resource.data` is kept. Remove catch-all `{document=**}` grants and test-mode time checks. Show the full rules file and the emulator tests that prove another user is denied.",
  },
};

function severityFor(o: Outcome): Pick<Outcome, "severity" | "confidence"> {
  return { severity: o.severity, confidence: o.confidence };
}

function isoDate(ms: number | undefined): string | undefined {
  if (ms === undefined || !Number.isFinite(ms)) return undefined;
  try {
    return new Date(ms).toISOString().slice(0, 10);
  } catch {
    return undefined;
  }
}

interface Candidate {
  path: string;
  kind: "rules" | "rtdb";
}

export class FirebaseRulesDetector implements Detector {
  id = "firebase-rules-detector";
  name = "Firebase Security Rules";
  category = "authorization" as const;
  description =
    "Detects Firestore, Storage and Realtime Database rules that let anyone, or any signed-in user, read or write data, and test-mode rules left open.";

  private readonly lineCache = new WeakMap<string[], Map<number, string>>();

  constructor(private readonly now: () => number = Date.now) {}

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    try {
      const candidates = await this.candidates(context);
      for (const cand of candidates) {
        try {
          const text = await context.readFile(cand.path);
          if (text.trim() === "" || text.length > MAX_FILE_CHARS) continue;
          if (cand.kind === "rules") {
            if (!text.includes("allow")) continue;
            findings.push(...this.rulesFindings(cand.path, text));
          } else {
            if (!text.includes(".read") && !text.includes(".write")) continue;
            findings.push(...this.rtdbFindings(cand.path, text));
          }
        } catch {
          // Never throw from a detector.
        }
      }
    } catch {
      // Never throw from a detector.
    }
    return capFindingsPerRule(findings);
  }

  private async candidates(context: ScanContext): Promise<Candidate[]> {
    const includeTests = context.config.includeTests === true;
    const listed = new Set(context.files.map((f) => f.replace(/\\/g, "/")));
    const targeted = (context.config.targetFiles?.length ?? 0) > 0;
    const map = new Map<string, Candidate>();
    const add = (file: string, kind: "rules" | "rtdb"): void => {
      const key = file.replace(/\\/g, "/");
      if (map.has(key)) return;
      if (isTestOrFixturePath(key) && !includeTests) return;
      map.set(key, { path: file, kind });
    };

    for (const f of context.files) {
      const base = f.replace(/\\/g, "/").split("/").pop() ?? "";
      if (classifyPath(f) === "firebase-rules") add(f, "rules");
      else if (/^database\.rules\.json$/i.test(base) || /\.rules\.json$/i.test(base))
        add(f, "rtdb");
    }

    for (const f of context.files) {
      const norm = f.replace(/\\/g, "/");
      if ((norm.split("/").pop() ?? "") !== "firebase.json") continue;
      try {
        const text = await context.readFile(f);
        if (text.length > MAX_FILE_CHARS || !text.includes("rules")) continue;
        const json: unknown = JSON.parse(text.replace(/^\uFEFF/, ""));
        if (typeof json !== "object" || json === null) continue;
        const dir = posix.dirname(norm);
        for (const section of ["firestore", "storage", "database"] as const) {
          const value = (json as Record<string, unknown>)[section];
          const entries = Array.isArray(value) ? value : [value];
          for (const entry of entries) {
            if (typeof entry !== "object" || entry === null) continue;
            const rules = (entry as Record<string, unknown>)["rules"];
            if (typeof rules !== "string" || rules === "") continue;
            const resolved = posix.normalize(posix.join(dir, rules.replace(/\\/g, "/")));
            if (resolved.startsWith("..") || posix.isAbsolute(resolved)) continue;
            if (targeted && !listed.has(resolved)) continue;
            add(resolved, /\.json$/i.test(resolved) ? "rtdb" : "rules");
          }
        }
      } catch {
        // Not valid JSON: nothing to discover.
      }
    }
    return [...map.values()];
  }

  private rulesFindings(file: string, text: string): Finding[] {
    const statements = parseRulesFile(text);
    if (statements.length === 0) return [];
    const fns = collectRuleFunctions(maskRulesSource(text), stripRulesComments(text));
    const lines = text.split(/\r?\n/);
    const findings: Finding[] = [];
    const now = this.now();
    for (const st of statements) {
      if (findings.length >= MAX_BUILT_PER_FILE) break;
      const cls = classifyCondition(st.condition, fns, now);
      if (cls.cls === "scoped" || cls.cls === "deny") continue;
      const scope = scopeOfSegments(st.segments);
      const writes = st.methods.some((m) => WRITE_METHODS.has(m));
      const reads = st.methods.some((m) => READ_METHODS.has(m));
      const creates = st.methods.includes("create");
      const consider = (column: Column): Outcome | undefined => {
        const d = decide(cls.cls, column, scope, st.service);
        return d ? { ...d, column } : undefined;
      };
      let best: Outcome | undefined;
      if (writes) best = worse(best, consider("write"));
      else if (creates) best = worse(best, consider("create"));
      if (reads) best = worse(best, consider("read"));
      if (!best) continue;
      findings.push(
        this.build(
          file,
          best,
          cls,
          scope,
          st.service,
          st.line,
          st.endLine,
          lines,
          st.methods.join(","),
        ),
      );
    }
    return findings;
  }

  private rtdbFindings(file: string, text: string): Finding[] {
    const rules = parseDatabaseRules(text);
    const lines = text.split(/\r?\n/);
    const findings: Finding[] = [];
    const now = this.now();
    for (const rule of rules) {
      if (findings.length >= MAX_BUILT_PER_FILE) break;
      const cls = classifyRtdbValue(rule.value, now);
      if (cls.cls === "scoped" || cls.cls === "deny") continue;
      const scope = scopeOfRtdbPath(rule.path);
      const column: Column = rule.key === ".write" ? "write" : "read";
      const d = decide(cls.cls, column, scope, "rtdb");
      if (!d) continue;
      findings.push(
        this.build(
          file,
          { ...d, column },
          cls,
          scope,
          "rtdb",
          rule.line,
          rule.line,
          lines,
          rule.key,
        ),
      );
    }
    return findings;
  }

  /** Sanitized (secrets redacted, truncated) text of a line, computed once per line. */
  private cleanLine(lines: string[], line: number): string {
    const cached = this.lineCache.get(lines);
    const cache = cached ?? new Map<number, string>();
    if (!cached) this.lineCache.set(lines, cache);
    let v = cache.get(line);
    if (v === undefined) {
      v = sanitizeEvidence(lines[line - 1] ?? "");
      cache.set(line, v);
    }
    return v;
  }

  private build(
    file: string,
    outcome: Outcome,
    cls: ConditionClass,
    scope: Scope,
    product: Product,
    line: number,
    endLine: number,
    lines: string[],
    discriminator: string,
  ): Finding {
    const t = TEXTS[outcome.kind];
    const evidence = this.cleanLine(lines, line);
    const sev = severityFor(outcome);
    return makeFinding({
      category: "authorization",
      ruleId: t.ruleId,
      title: t.title,
      severity: sev.severity,
      confidence: sev.confidence,
      file,
      line,
      endLine: endLine > line ? endLine : undefined,
      evidence,
      discriminator: `${line}:${discriminator}`,
      plainEnglishProblem: t.problem(
        evidence,
        scopeText(scope, product),
        isoDate(cls.expiresAt),
        outcome.column,
      ),
      whyItMatters: t.why,
      fixSteps: t.fix,
      aiFixPrompt: t.prompt,
      learnMoreUrl: LEARN_MORE,
    });
  }
}
