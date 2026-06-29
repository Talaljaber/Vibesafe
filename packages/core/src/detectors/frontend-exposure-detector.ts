import { Detector, Finding, ScanContext } from "@vibeguard/shared";
import { isClientFile } from "./utils/file-classifier.js";
import crypto from "crypto";

export class FrontendExposureDetector implements Detector {
  id = "frontend-exposure-detector";
  name = "Frontend Exposure Detection";
  category = "frontend_exposure" as const;
  description = "Detects sensitive environment variables or admin SDKs used in client-side code.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const filePath of context.files) {
      if (!filePath.endsWith(".ts") && !filePath.endsWith(".tsx") && !filePath.endsWith(".js") && !filePath.endsWith(".jsx")) {
        continue;
      }

      const content = await context.readFile(filePath);
      
      if (!isClientFile(filePath, content)) {
        continue;
      }

      const lines = content.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line === undefined) continue;

        // 1. Detect service_role keys being used in client code
        if (line.includes("SERVICE_ROLE_KEY") || line.includes("service_role")) {
          findings.push({
            id: `FE-${crypto.randomBytes(3).toString("hex")}`,
            ruleId: "frontend_exposure/service-role-key",
            title: "Service Role Key used in client code",
            severity: "critical",
            category: "frontend_exposure",
            deployBlocking: true,
            confidence: "high",
            file: filePath,
            line: i + 1,
            evidence: line.trim(),
            plainEnglishProblem: "You are using an admin 'service role' key in frontend code.",
            whyItMatters: "Client code is visible to everyone in the browser. Anyone can extract this key and gain full admin access to your database, bypassing all row-level security.",
            fixSteps: [
              "Never use service role keys in the browser.",
              "Use the regular anonymous/public key for the frontend client.",
              "If you need to perform admin actions, create a backend API route, do the action there, and call it from the frontend."
            ],
            autoFixAvailable: false,
          });
        }

        // 2. Detect missing NEXT_PUBLIC_ on sensitive vars
        const nextPublicSecretRegex = /NEXT_PUBLIC_[A-Z_]*(SECRET|PRIVATE|PASSWORD|SERVICE_ROLE)[A-Z_]*/i;
        const match = nextPublicSecretRegex.exec(line);
        if (match && match[0]) {
          findings.push({
            id: `FE-${crypto.randomBytes(3).toString("hex")}`,
            ruleId: "frontend_exposure/public-secret-var",
            title: "Sensitive variable exposed to frontend",
            severity: "high",
            category: "frontend_exposure",
            deployBlocking: true,
            confidence: "high",
            file: filePath,
            line: i + 1,
            evidence: match[0],
            plainEnglishProblem: `You have prefixed a sensitive variable (${match[0]}) with NEXT_PUBLIC_.`,
            whyItMatters: "The NEXT_PUBLIC_ prefix bundles this variable into the code sent to the user's browser, exposing your secret.",
            fixSteps: [
              `Remove the NEXT_PUBLIC_ prefix from this variable in your .env file and code.`,
              `Move the logic that requires this secret to a server-side API route or Server Component.`
            ],
            autoFixAvailable: false,
          });
        }
      }
    }

    return findings;
  }
}
