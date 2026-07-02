import type { Detector, Finding, ScanContext } from "@vibesafe/shared";
import crypto from "crypto";

const CODE_FILE_EXTENSIONS = [".ts", ".tsx", ".js", ".jsx"];
const OCTET = "(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)";
const LOCAL_NETWORK_HOST_REGEX = new RegExp(
  `\\b(?:localhost|127\\.0\\.0\\.1|10\\.${OCTET}\\.${OCTET}\\.${OCTET}|192\\.168\\.${OCTET}\\.${OCTET}|172\\.(?:1[6-9]|2\\d|3[01])\\.${OCTET}\\.${OCTET})\\b`,
  "i",
);

function isCodeFile(filePath: string): boolean {
  if (!CODE_FILE_EXTENSIONS.some((extension) => filePath.endsWith(extension))) {
    return false;
  }

  const normalizedPath = filePath.replace(/\\/g, "/");
  const fileName = normalizedPath.split("/").pop() ?? normalizedPath;

  return (
    !normalizedPath.includes("/__tests__/") &&
    !fileName.includes(".test.") &&
    !fileName.includes(".spec.")
  );
}

export class HardcodedLocalhostDetector implements Detector {
  id = "hardcoded-localhost-detector";
  name = "Hardcoded Localhost Detection";
  category = "code_quality" as const;
  description = "Detects localhost and private network hosts hardcoded in application code.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const filePath of context.files) {
      if (!isCodeFile(filePath)) {
        continue;
      }

      const content = await context.readFile(filePath);
      if (!LOCAL_NETWORK_HOST_REGEX.test(content)) {
        continue;
      }

      const lines = content.split("\n");

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!line) continue;

        const match = LOCAL_NETWORK_HOST_REGEX.exec(line);
        if (!match || !match[0]) {
          continue;
        }

        findings.push({
          id: `QUAL-${crypto.randomBytes(3).toString("hex")}`,
          ruleId: "code_quality/hardcoded-localhost",
          title: "Hardcoded localhost or private IP address",
          severity: "medium",
          category: "code_quality",
          deployBlocking: false,
          confidence: "high",
          file: filePath,
          line: i + 1,
          evidence: line.trim(),
          plainEnglishProblem: `This code hardcodes "${match[0]}", which usually only works on a developer machine or private network.`,
          whyItMatters:
            "Hardcoded local hosts often break after deployment because production users and servers cannot reach your local machine or internal network.",
          fixSteps: [
            "Move the host or base URL into an environment variable.",
            "Use a production-safe public URL in deployed environments.",
            "Document the required local development value in an example env file.",
          ],
          autoFixAvailable: false,
          aiFixPrompt:
            "Please replace this hardcoded local host or private IP address with an environment-driven configuration value that supports separate local and production URLs.",
        });
      }
    }

    return findings;
  }
}
