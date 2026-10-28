import { type Detector, type Finding, type ScanContext } from "@vibesafe/shared";
import { CATEGORY_PREFIX, createFindingId } from "@vibesafe/shared";
import { isApiRoute, lineOfIndex } from "./utils/route-analyzer.js";
import {
  VALIDATION_LIB_IMPORT_REGEX,
  VALIDATION_CALL_REGEXES,
  VALIDATION_LIB_CALL_REGEX,
  INPUT_READ_REGEXES,
} from "./patterns/validation-patterns.js";

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

      let inputIndex = -1;
      for (const re of INPUT_READ_REGEXES) {
        const m = re.exec(content);
        if (m && (inputIndex === -1 || m.index < inputIndex)) inputIndex = m.index;
      }

      if (inputIndex !== -1) {
        const line = lineOfIndex(content, inputIndex);
        const hasImport = VALIDATION_LIB_IMPORT_REGEX.test(content);
        const validated =
          VALIDATION_CALL_REGEXES.some((re) => re.test(content)) ||
          (hasImport && VALIDATION_LIB_CALL_REGEX.test(content));

        if (!validated) {
          findings.push({
            id: createFindingId(
              CATEGORY_PREFIX.validation,
              "validation/missing-body-validation",
              filePath,
              line,
            ),
            ruleId: "validation/missing-body-validation",
            title: "Unvalidated Request Body",
            severity: "high",
            category: "validation",
            deployBlocking: false,
            confidence: "medium",
            file: filePath,
            line,
            plainEnglishProblem:
              "This API route reads data sent by the user, but doesn't validate if the data is correct before using it.",
            whyItMatters:
              "Malicious users can send unexpected data types (like an object instead of a string) to crash your server or bypass security checks. This is a common cause of downtime.",
            fixSteps: [
              "Install a validation library like Zod (`npm i zod`).",
              "Define a schema that strictly types what you expect the request body to look like.",
              "Parse the request body with the schema before using it.",
            ],
            autoFixAvailable: false,
            aiFixPrompt: `This API route reads the request body but doesn't validate it. Please write a Zod schema for the expected data and parse the body using safeParse.`,
          });
        }
      }
    }

    return findings;
  }
}
