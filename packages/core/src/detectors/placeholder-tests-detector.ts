// ─────────────────────────────────────────────────────────────────────────────
// Placeholder Tests Detector
//
// "There are tests" is not the same as "something is tested". Default mode reads
// package.json only:
//   - a `test` script that is just `echo ...` (npm's default placeholder),
//   - a test command with `--passWithNoTests`, which turns "zero tests" into a pass.
// With `includeTests`, test files are read too: a test file whose only tests are
// `it.todo` / `it.skip` placeholders, or whose only assertions compare constants
// (`expect(true).toBe(true)`), is reported, and `--passWithNoTests` is no longer
// reported once a real test file is seen.
// ─────────────────────────────────────────────────────────────────────────────

import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { makeFinding } from "./utils/finding.js";
import { isJsLike } from "./utils/file-kind.js";
import { stripComments } from "./utils/strip-comments.js";
import { manifestFiles, parseManifest } from "./utils/deps-manifest.js";

const MAX_FILE_FINDINGS = 25;

const AI_FIX_PROMPT =
  "My project's test setup gives a passing result without testing anything (placeholder test " +
  "script, --passWithNoTests, or test files that only contain todo/skipped tests or assertions " +
  "on constants). Write real tests with the project's existing test runner for the riskiest code " +
  "first: authentication and session checks, authorization (users can only access their own " +
  "data), payment and order logic, and input validation on API routes. Each test must exercise " +
  "real application code and assert on its result. Then make the `test` script fail when no tests " +
  "are found (remove --passWithNoTests or the placeholder echo).";

const LITERAL = String.raw`(?:true|false|null|undefined|-?\d+(?:\.\d+)?|'[^'\n]*'|"[^"\n]*")`;
const TRIVIAL_ASSERT_RE = new RegExp(
  String.raw`\bexpect\s*\(\s*${LITERAL}\s*\)\s*\.\s*(?:not\s*\.\s*)?(?:toBe|toEqual|toStrictEqual|toBeTruthy|toBeFalsy|toBeDefined|toBeNull)\s*\(\s*(?:${LITERAL}\s*)?\)`,
  "g",
);
const ANY_ASSERT_RE = /\bexpect\s*\(|\bassert(?:\.\w+)?\s*\(|\bexpectTypeOf\s*\(/g;
const REAL_TEST_RE = /\b(?:it|test)(?:\.only|\.concurrent)?\s*\(/g;
const PLACEHOLDER_RE =
  /\b(?:it|test|describe)\s*\.\s*(?:todo|skip)\s*\(|\b(?:xit|xtest|xdescribe)\s*\(/g;

function isTestFile(file: string): boolean {
  const p = file.replace(/\\/g, "/");
  if (!isJsLike(p)) return false;
  return /\.(?:test|spec)\.[^/]+$/.test(p) || /(?:^|\/)__tests__\//.test(p);
}

function count(re: RegExp, text: string): number {
  re.lastIndex = 0;
  return (text.match(re) ?? []).length;
}

function lineOf(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

interface TestFileVerdict {
  placeholderOnly: boolean;
  /** Index of the first placeholder (todo/skip or constant assertion). */
  at: number;
  kind: "todo" | "trivial";
}

/** Classifies a test file's code (comments stripped, same offsets). */
export function classifyTestFile(code: string): TestFileVerdict | null {
  const real = count(REAL_TEST_RE, code);
  PLACEHOLDER_RE.lastIndex = 0;
  const placeholder = PLACEHOLDER_RE.exec(code);
  if (real === 0) {
    if (!placeholder) return null; // no tests at all: not this rule's business
    return { placeholderOnly: true, at: placeholder.index, kind: "todo" };
  }
  const asserts = count(ANY_ASSERT_RE, code);
  TRIVIAL_ASSERT_RE.lastIndex = 0;
  const firstTrivial = TRIVIAL_ASSERT_RE.exec(code);
  const trivial = count(TRIVIAL_ASSERT_RE, code);
  if (firstTrivial && asserts > 0 && trivial === asserts) {
    return { placeholderOnly: true, at: firstTrivial.index, kind: "trivial" };
  }
  return { placeholderOnly: false, at: 0, kind: "todo" };
}

export class PlaceholderTestsDetector implements Detector {
  id = "placeholder-tests-detector";
  name = "Placeholder-Only Tests";
  category = "structure" as const;
  description =
    "Detects test setups that pass without testing anything: echo test scripts, --passWithNoTests, and (with includeTests) todo-only or constant-assertion test files.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    try {
      let realTestSeen = false;
      const fileFindings: Finding[] = [];
      if (context.config?.includeTests === true) {
        for (const file of context.files) {
          if (!isTestFile(file)) continue;
          const text = await context.readFile(file);
          if (!text) continue;
          const code = stripComments(text);
          const verdict = classifyTestFile(code);
          if (!verdict) continue;
          if (!verdict.placeholderOnly) {
            realTestSeen = true;
            continue;
          }
          if (fileFindings.length >= MAX_FILE_FINDINGS) continue;
          const line = lineOf(code, verdict.at);
          fileFindings.push(
            this.fileFinding(file, line, text.split("\n")[line - 1] ?? "", verdict),
          );
        }
      }

      for (const file of manifestFiles(context)) {
        const manifest = parseManifest(file, await context.readFile(file));
        if (!manifest) continue;
        const scripts = manifest.json.scripts;
        if (typeof scripts !== "object" || scripts === null) continue;
        const test = (scripts as Record<string, unknown>).test;
        if (typeof test !== "string") continue;
        const at = manifest.scriptLines.get("test");
        if (/^\s*echo\b/.test(test)) {
          findings.push(
            makeFinding({
              category: "structure",
              ruleId: "structure/placeholder-only-tests",
              title: "The test script is a placeholder",
              severity: "low",
              confidence: "high",
              file,
              line: at?.line,
              evidence: at?.text ?? `"test": "echo ..."`,
              discriminator: "echo",
              plainEnglishProblem:
                "Your package.json `test` script only prints a message; it does not run any tests.",
              whyItMatters:
                "CI and teammates see a test step, but nothing about login, permissions or payments is ever checked, so regressions ship silently.",
              fixSteps: [
                "Install a test runner (for example Vitest or Jest) and point the `test` script at it.",
                "Add tests for authentication, authorization and payment logic first.",
              ],
              aiFixPrompt: AI_FIX_PROMPT,
            }),
          );
        } else if (/--pass-?with-?no-?tests\b/i.test(test) && !realTestSeen) {
          findings.push(
            makeFinding({
              category: "structure",
              ruleId: "structure/placeholder-only-tests",
              title: "Tests pass even when there are none (--passWithNoTests)",
              severity: "low",
              confidence: "medium",
              file,
              line: at?.line,
              evidence: at?.text ?? `"test": "--passWithNoTests"`,
              discriminator: "pass-with-no-tests",
              plainEnglishProblem:
                "Your `test` script uses `--passWithNoTests`, so the test step reports success even when no test file exists.",
              whyItMatters:
                "A green CI run then says nothing: deleting or never writing tests goes unnoticed, and security-critical logic stays untested.",
              fixSteps: [
                "Remove `--passWithNoTests` from the `test` script so an empty test suite fails.",
                "Add real tests for authentication, authorization and payment logic.",
              ],
              aiFixPrompt: AI_FIX_PROMPT,
            }),
          );
        }
      }
      findings.push(...fileFindings);
    } catch {
      // Never throw from a detector.
    }
    return findings;
  }

  private fileFinding(
    file: string,
    line: number,
    evidence: string,
    verdict: TestFileVerdict,
  ): Finding {
    return makeFinding({
      category: "structure",
      ruleId: "structure/placeholder-only-tests",
      title:
        verdict.kind === "todo"
          ? "Test file contains only todo or skipped tests"
          : "Test file only asserts on constants",
      severity: "low",
      confidence: "medium",
      file,
      line,
      evidence,
      discriminator: verdict.kind,
      plainEnglishProblem:
        verdict.kind === "todo"
          ? "This test file only declares placeholder tests (`it.todo`, `it.skip`, `xit`), so it never runs any check."
          : "Every assertion in this test file compares constants (like `expect(true).toBe(true)`), so it always passes without exercising your code.",
      whyItMatters:
        "Placeholder tests make the suite look healthy while nothing about authentication, permissions or payments is actually verified.",
      fixSteps: [
        "Replace the placeholders with tests that call your application code and assert on the result.",
        "Start with the riskiest paths: login/session checks, per-user data access, payments.",
      ],
      aiFixPrompt: AI_FIX_PROMPT,
    });
  }
}
