import { Detector, Finding, ScanContext } from "@vibeguard/shared";
import { isApiRoute, hasRiskyHttpMethods, hasAuthCheck, isRiskyRoutePattern } from "./utils/route-analyzer.js";
import crypto from "crypto";

export class MissingAuthDetector implements Detector {
  id = "missing-auth-detector";
  name = "Missing Auth Detection";
  category = "auth" as const;
  description = "Detects API routes that perform risky operations without checking authentication.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const filePath of context.files) {
      if (!isApiRoute(filePath)) {
        continue;
      }

      const content = await context.readFile(filePath);

      const isMutatingRoute = hasRiskyHttpMethods(content);
      const isSensitivePath = isRiskyRoutePattern(filePath);

      if (isMutatingRoute || isSensitivePath) {
        if (!hasAuthCheck(content)) {
          findings.push({
            id: `AUTH-${crypto.randomBytes(3).toString("hex")}`,
            ruleId: "auth/missing-route-auth",
            title: "Missing authentication in API Route",
            severity: isSensitivePath ? "critical" : "high",
            category: "auth",
            deployBlocking: isSensitivePath,
            confidence: "medium", 
            file: filePath,
            plainEnglishProblem: "This API route appears to modify data or access sensitive info, but we couldn't find any code verifying who the user is.",
            whyItMatters: "Without an auth check, anyone on the internet can call this API directly and modify your database or view private data.",
            fixSteps: [
              "Import your authentication library's server-side session checker.",
              "Call the session checker at the very beginning of the route handler.",
              "If the session is null, immediately `return new Response('Unauthorized', { status: 401 })`."
            ],
            autoFixAvailable: false,
            aiFixPrompt: `I need to secure this Next.js API route. Please add an authentication check at the beginning of the handler so that unauthenticated users receive a 401 response.`
          });
        }
      }
    }

    return findings;
  }
}
