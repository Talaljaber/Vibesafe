import { Detector, Finding, ScanContext } from "@vibeguard/shared";
import { SECRET_PATTERNS } from "./patterns/secret-patterns.js";
import path from "path";
import crypto from "crypto";

export class SecretDetector implements Detector {
  id = "secret-detector";
  name = "Secret Detection";
  category = "secret" as const;
  description = "Detects hardcoded secrets, API keys, and exposed .env files.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    
    // Check if .env is missing from .gitignore
    const hasEnvFile = context.files.some(f => path.basename(f) === ".env" || path.basename(f) === ".env.local");
    const gitignoreContent = await this.getGitignoreContent(context);
    
    if (hasEnvFile && (!gitignoreContent || !gitignoreContent.includes(".env"))) {
      findings.push(this.createGitignoreFinding(context));
    }

    // Scan all files for hardcoded secrets
    for (const filePath of context.files) {
      if (filePath.endsWith("package-lock.json") || filePath.endsWith("pnpm-lock.yaml")) continue;

      const content = await context.readFile(filePath);
      const lines = content.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line === undefined) continue;
        
        for (const pattern of SECRET_PATTERNS) {
          const match = pattern.regex.exec(line);
          if (match && match[0]) {
            findings.push({
              id: `SEC-${crypto.randomBytes(3).toString("hex")}`,
              ruleId: `secret/${pattern.id}`,
              title: `Exposed ${pattern.name}`,
              severity: "critical",
              category: "secret",
              deployBlocking: true,
              confidence: pattern.confidence,
              file: filePath,
              line: i + 1,
              evidence: match[0],
              plainEnglishProblem: `We found what looks like a ${pattern.name} written directly in your code.`,
              whyItMatters: `If you deploy this, anyone who can see this file can extract the key and use your account, potentially running up large bills or accessing private data.`,
              fixSteps: [
                `Remove the key from this file.`,
                `Move the key to a .env file (e.g., \`MY_KEY=your_key_here\`).`,
                `Update this file to use \`process.env.MY_KEY\` instead.`,
                `Ensure your .env file is added to your .gitignore.`
              ],
              autoFixAvailable: false,
              aiFixPrompt: `I have a hardcoded secret in this file. Please modify the code to read this value from an environment variable instead, and show me what I need to add to my .env file.`
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

  private createGitignoreFinding(context: ScanContext): Finding {
    return {
      id: `SEC-${crypto.randomBytes(3).toString("hex")}`,
      ruleId: "secret/env-not-ignored",
      title: ".env file not in .gitignore",
      severity: "critical",
      category: "secret",
      deployBlocking: true,
      confidence: "high",
      file: ".gitignore",
      plainEnglishProblem: "You have a .env file containing secrets, but it's not listed in your .gitignore file.",
      whyItMatters: "When you commit your code, git will include your .env file and push it to GitHub. This exposes all your database passwords and API keys to the public.",
      fixSteps: [
        "Open your .gitignore file.",
        "Add a new line with exactly `.env`",
        "Add another line with `.env.*` to cover other local env files."
      ],
      autoFixAvailable: true,
    };
  }
}
