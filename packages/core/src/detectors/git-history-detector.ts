import { Detector, Finding, ScanContext, redactSecret } from "@vibesafe/shared";
import { SECRET_PATTERNS } from "./patterns/secret-patterns.js";
import {
  getHistoricalAddedLines,
  isGitAvailable,
  looksLikeGitRepo,
  type HistoricalHunk,
} from "./utils/git-log-parser.js";
import crypto from "crypto";

const MAX_COMMITS_TO_SCAN = 500;
const SHORT_SHA_LENGTH = 7;

interface SecretOccurrence {
  patternId: string;
  patternName: string;
  confidence: "high" | "medium" | "low";
  secretValue: string;
  file: string;
  sha: string;
  author: string;
  date: string;
  occurrenceCount: number;
}

export class GitHistoryDetector implements Detector {
  id = "git-history-detector";
  name = "Git History Secret Forensics";
  category = "secret" as const;
  description =
    "Scans git commit history for secrets that were committed and later deleted from the working tree, but remain permanently recoverable in .git.";

  async detect(context: ScanContext): Promise<Finding[]> {
    // Gated behind --deep. History scanning is much slower than a file scan,
    // and must never run (or spawn git) on a default scan.
    if (context.config.deep !== true) {
      return [];
    }

    // Graceful no-op if this isn't a git repo, or git isn't installed.
    if (!looksLikeGitRepo(context.rootPath)) {
      return [];
    }
    if (!(await isGitAvailable())) {
      return [];
    }

    let hunks: HistoricalHunk[];
    try {
      hunks = await getHistoricalAddedLines(context.rootPath, MAX_COMMITS_TO_SCAN);
    } catch {
      // Never let a git failure crash the scan.
      return [];
    }

    if (hunks.length === 0) {
      return [];
    }

    // Dedupe by secret value: one finding per unique secret, carrying its
    // earliest commit plus a total occurrence count.
    const occurrencesBySecret = new Map<string, SecretOccurrence>();

    for (const hunk of hunks) {
      for (const added of hunk.addedLines) {
        const normalizedLine = added.line.replace(/\r$/, "");

        for (const pattern of SECRET_PATTERNS) {
          const match = pattern.regex.exec(normalizedLine);
          if (!match || !match[0]) continue;

          const secretValue = match[0];
          const key = `${pattern.id}::${secretValue}`;
          const existing = occurrencesBySecret.get(key);

          if (existing) {
            existing.occurrenceCount++;
            // Keep the earliest commit. git log output is newest-first, so a
            // later-seen occurrence is actually an earlier commit.
            existing.sha = hunk.sha;
            existing.author = hunk.author;
            existing.date = hunk.date;
            existing.file = hunk.file;
          } else {
            occurrencesBySecret.set(key, {
              patternId: pattern.id,
              patternName: pattern.name,
              confidence: pattern.confidence,
              secretValue,
              file: hunk.file,
              sha: hunk.sha,
              author: hunk.author,
              date: hunk.date,
              occurrenceCount: 1,
            });
          }
        }
      }
    }

    if (occurrencesBySecret.size === 0) {
      return [];
    }

    // Cross-check the working tree: is this secret still present in a
    // currently-scanned file? If so it's a duplicate of what SecretDetector
    // already reports, so we downgrade severity instead of double-alarming.
    const workingTreeContent = await this.readAllFiles(context);

    const findings: Finding[] = [];

    for (const occurrence of occurrencesBySecret.values()) {
      const stillPresent = workingTreeContent.includes(occurrence.secretValue);
      const shortSha = occurrence.sha.slice(0, SHORT_SHA_LENGTH);
      const redacted = redactSecret(occurrence.secretValue);

      if (stillPresent) {
        findings.push(
          this.buildFinding({
            occurrence,
            shortSha,
            redacted,
            severity: "high",
            recoverable: false,
          }),
        );
      } else {
        findings.push(
          this.buildFinding({
            occurrence,
            shortSha,
            redacted,
            severity: "critical",
            recoverable: true,
          }),
        );
      }
    }

    return findings;
  }

  private async readAllFiles(context: ScanContext): Promise<string> {
    const contents = await Promise.all(
      context.files.map(async (file) => {
        try {
          return await context.readFile(file);
        } catch {
          return "";
        }
      }),
    );
    return contents.join("\n");
  }

  private buildFinding(params: {
    occurrence: SecretOccurrence;
    shortSha: string;
    redacted: string;
    severity: "critical" | "high";
    recoverable: boolean;
  }): Finding {
    const { occurrence, shortSha, redacted, severity, recoverable } = params;

    const title = recoverable
      ? `Leaked ${occurrence.patternName} found in git history (commit ${shortSha}), deleted but still recoverable`
      : `Leaked ${occurrence.patternName} found in git history (commit ${shortSha}), still present in working tree`;

    const occurrenceNote =
      occurrence.occurrenceCount > 1
        ? ` It appears in ${occurrence.occurrenceCount} commits; the earliest is shown here.`
        : "";

    const plainEnglishProblem = recoverable
      ? `A ${occurrence.patternName} was committed to git in ${occurrence.file} by ${occurrence.author} and later removed from the file. Deleting the file, or the line, does not remove it from git history.${occurrenceNote}`
      : `A ${occurrence.patternName} was committed to git in ${occurrence.file} by ${occurrence.author} and is still present in the current version of the file, in addition to being permanently recorded in git history.${occurrenceNote}`;

    const whyItMatters = recoverable
      ? "Anyone who has ever cloned or forked this repository can recover this key from the git object database, even though it no longer appears in the current files. Deleted commits often remain reachable through GitHub forks, reflogs, and cached objects even after a force-push."
      : "This key is exposed twice: once in the current working tree (where the standard secret scanner already flags it) and permanently in git history. Removing it from the file alone will not remove it from history.";

    return {
      id: `SEC-${crypto.randomBytes(3).toString("hex")}`,
      ruleId: `secret/git-history-${occurrence.patternId}`,
      title,
      severity,
      category: "secret",
      deployBlocking: severity === "critical",
      confidence: occurrence.confidence,
      file: occurrence.file,
      // Line numbers from history are misleading against the current file,
      // so we omit `line` rather than guess.
      evidence: `${redacted} (commit ${shortSha} by ${occurrence.author})`,
      plainEnglishProblem,
      whyItMatters,
      fixSteps: [
        "Rotate this key immediately, treat it as compromised regardless of whether it's still in the working tree.",
        "Remove the key from any file that still references it and move it into an environment variable.",
        "Optionally, rewrite git history to purge the secret (e.g., with git filter-repo or BFG Repo-Cleaner) and force-push, then have every collaborator re-clone.",
        "Add the key's pattern to a secret-scanning pre-commit hook to prevent recurrence.",
      ],
      autoFixAvailable: false,
      aiFixPrompt: `A ${occurrence.patternName} was committed to git history (commit ${shortSha}) in ${occurrence.file}. First rotate this key with the provider immediately. Then help me migrate it to an environment variable, show me the .env entry, and update the code to use process.env instead. Do not attempt to rewrite git history yourself.`,
    };
  }
}
