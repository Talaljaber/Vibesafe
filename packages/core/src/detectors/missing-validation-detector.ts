import { Detector, Finding, ScanContext } from "@vibeguard/shared";
import { isApiRoute } from "./utils/route-analyzer.js";
import { VALIDATION_LIB_IMPORTS, VALIDATION_METHOD_CALLS } from "./patterns/validation-patterns.js";
import crypto from "crypto";

export class MissingValidationDetector implements Detector {
  id = "missing-validation-detector";
  name = "Missing Input Validation";
  category = "validation" as const;
  description = "Detects API routes that read request data without validating it.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const filePath of context.files) {
      if (!isApiRoute(filePath)) {
        continue;
      }

      const content = await context.readFile(filePath);
      
      const readsJson = content.includes("req.json()") || content.includes("request.json()");
      const readsBody = content.includes("req.body");

      if (readsJson || readsBody) {
        const hasValidationImport = VALIDATION_LIB_IMPORTS.some((lib: string) => content.includes(lib));
        const hasValidationCall = VALIDATION_METHOD_CALLS.some((call: string) => content.includes(call));

        if (!hasValidationImport && !hasValidationCall) {
          findings.push({
            id: `VAL-${crypto.randomBytes(3).toString("hex")}`,
            ruleId: "validation/missing-body-validation",
            title: "Unvalidated Request Body",
            severity: "high",
            category: "validation",
            deployBlocking: false,
            confidence: "medium", 
            file: filePath,
            plainEnglishProblem: "This API route reads data sent by the user, but doesn't validate if the data is correct before using it.",
            whyItMatters: "Malicious users can send unexpected data types (like an object instead of a string) to crash your server or bypass security checks. This is a common cause of downtime.",
            fixSteps: [
              "Install a validation library like Zod (`npm i zod`).",
              "Define a schema that strictly types what you expect the request body to look like.",
              "Parse the request body with the schema before using it."
            ],
            autoFixAvailable: false,
            aiFixPrompt: `This API route reads the request body but doesn't validate it. Please write a Zod schema for the expected data and parse the body using safeParse.`
          });
        }
      }
    }

    return findings;
  }
}
