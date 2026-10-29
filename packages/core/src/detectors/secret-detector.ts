import { type Detector, type Finding, type ScanContext } from "@talaljaber/vibesafe-shared";
import { CATEGORY_PREFIX, classifyEnvFileName, createFindingId } from "@talaljaber/vibesafe-shared";
import { sanitizeEvidence } from "./utils/sanitize-evidence.js";
import { SECRET_PATTERNS, matchSecretPattern } from "./patterns/secret-patterns.js";
import path from "path";
import ignore from "ignore";

export class SecretDetector implements Detector {
  id = "secret-detector";
  name = "Secret Detection";
  category = "secret" as const;
  description = "Detects hardcoded secrets, API keys, and exposed .env files.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check that every discovered .env* file is actually ignored by the root .gitignore
    const envFiles = context.files.filter((f) => isEnvFile(f));
    if (envFiles.length > 0) {
      const gitignoreContent = await this.getGitignoreContent(context);
      const ig = ignore().add(gitignoreContent ?? "");
      for (const envFile of envFiles) {
        const rel = envFile.replace(/\\/g, "/").replace(/^\.?\//, "");
        let ignored = false;
        try {
          ignored = ig.ignores(rel);
        } catch {
          ignored = false;
        }
        if (!ignored) findings.push(this.createGitignoreFinding(rel));
      }
    }

    // Scan all files for hardcoded secrets
    for (const filePath of context.files) {
      if (
        filePath.endsWith("package-lock.json") ||
        filePath.endsWith("pnpm-lock.yaml") ||
        filePath.endsWith("yarn.lock")
      )
        continue;

      const content = await context.readFile(filePath);
      const lines = content.split("\n");

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line === undefined) continue;

        for (const pattern of SECRET_PATTERNS) {
          const match = matchSecretPattern(pattern, line);
          if (match) {
            findings.push({
              id: createFindingId(
                CATEGORY_PREFIX.secret,
                `secret/${pattern.id}`,
                filePath,
                i + 1,
                match[0],
              ),
              ruleId: `secret/${pattern.id}`,
              title: `Exposed ${pattern.name}`,
              severity: pattern.severity,
              category: "secret",
              deployBlocking: pattern.severity === "critical",
              confidence: pattern.confidence,
              file: filePath,
              line: i + 1,
              evidence: sanitizeEvidence(match[0]),
              plainEnglishProblem:
                pattern.advice?.problem ??
                `We found what looks like a ${pattern.name} written directly in your code.`,
              whyItMatters:
                pattern.advice?.why ??
                `If you deploy this, anyone who can see this file can extract the key and use your account, potentially running up large bills or accessing private data.`,
              fixSteps: pattern.advice?.fixSteps ?? [
                `Remove the key from this file.`,
                `Move the key to a .env file (e.g., \`MY_KEY=your_key_here\`).`,
                `Update this file to use \`process.env.MY_KEY\` instead.`,
                `Ensure your .env file is added to your .gitignore.`,
              ],
              autoFixAvailable: false,
              aiFixPrompt:
                pattern.advice?.aiFixPrompt ??
                `I have a hardcoded secret in this file. Please modify the code to read this value from an environment variable instead, and show me what I need to add to my .env file.`,
            });
          }
        }
      }
    }

    return findings;
  }

  private async getGitignoreContent(context: ScanContext): Promise<string | null> {
    try {
      if (context.files.includes(".gitignore")) {
        return await context.readFile(".gitignore");
      }
      return null;
    } catch {
      return null;
    }
  }

  private createGitignoreFinding(envFile: string): Finding {
    return {
      id: createFindingId(CATEGORY_PREFIX.secret, "secret/env-not-ignored", envFile),
      ruleId: "secret/env-not-ignored",
      title: `${envFile} is not ignored by .gitignore`,
      severity: "critical",
      category: "secret",
      deployBlocking: true,
      confidence: "high",
      file: envFile,
      plainEnglishProblem: `You have a ${envFile} file that probably contains secrets, but your .gitignore does not ignore it.`,
      whyItMatters:
        "When you commit your code, git will include your env file and push it to GitHub. This exposes all your database passwords and API keys to the public.",
      fixSteps: [
        "Open your .gitignore file.",
        "Add a new line with exactly `.env`",
        "Add another line with `.env.*` to cover other local env files (and `!.env.example` to keep the template).",
      ],
      autoFixAvailable: true,
    };
  }
}

/** A real env file (not a template or a dotenv-vault file), which must be gitignored. */
function isEnvFile(file: string): boolean {
  return classifyEnvFileName(path.posix.basename(file.replace(/\\/g, "/"))) === "env";
}
