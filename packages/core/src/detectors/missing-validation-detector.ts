import { type Detector, type Finding, type ScanContext } from "@talaljaber/vibesafe-shared";
import { CATEGORY_PREFIX, createFindingId } from "@talaljaber/vibesafe-shared";
import {
  isApiRoute,
  lineOfIndex,
  isExpressCandidateFile,
  usesExpress,
  extractExpressRoutes,
  isExpressMutatingMethod,
  splitTopLevel,
  displayRoutePath,
} from "./utils/route-analyzer.js";
import {
  EXPRESS_VALIDATOR_IMPORT_REGEX,
  EXPRESS_VALIDATOR_CALL_REGEX,
  EXPRESS_VALIDATE_MIDDLEWARE_CALL_REGEX,
  EXPRESS_VALIDATE_MIDDLEWARE_IDENT_REGEX,
  EXPRESS_BODY_READ_REGEX,
  EXPRESS_QUERY_READ_REGEX,
  VALIDATION_LIB_IMPORT_REGEX,
  VALIDATION_CALL_REGEXES,
  VALIDATION_LIB_CALL_REGEX,
  INPUT_READ_REGEXES,
  FORM_DATA_READ_REGEX,
  OTHER_INPUT_READ_REGEX,
  FILE_INSTANCE_CHECK_REGEX,
  FILE_SIZE_CHECK_REGEX,
  FILE_TYPE_CHECK_REGEX,
} from "./patterns/validation-patterns.js";
import { isStripeWebhookRoute, isStripeWebhookExpressRoute } from "./stripe-webhook-detector.js";
import { classifyPath } from "./utils/file-kind.js";
import { enclosingFunction, extractFunctions } from "./utils/js-functions.js";
import { createJsSource, isJsxPath } from "./utils/js-source.js";

const HANDLER_ROLES = new Set(["app-route-handler", "pages-api-handler", "express-handler"]);

/**
 * Last line of the request handler containing `offset`: the innermost enclosing App
 * Router, Pages API or Express handler span, else the outermost enclosing function.
 * Precedence rules with `enclosing` scope use it so a specific finding inside the same
 * handler hides this generic one (and only that handler's).
 */
function handlerEndLine(filePath: string, content: string, offset: number): number | undefined {
  try {
    const src = createJsSource(content, { jsx: isJsxPath(filePath) });
    const spans = extractFunctions(src, { kind: classifyPath(filePath) });
    let span = enclosingFunction(spans, offset);
    let outer = span;
    while (span !== undefined && !HANDLER_ROLES.has(span.role)) {
      outer = span;
      span = span.parent;
    }
    return (span ?? outer)?.endLine;
  } catch {
    return undefined;
  }
}

/**
 * A multipart upload checked the way a schema would: the handler reads `formData()` (and
 * no other request input), checks the value is a `File`/`Blob`, and checks its size and
 * MIME type before using it.
 */
function isValidatedFileUpload(content: string): boolean {
  return (
    FORM_DATA_READ_REGEX.test(content) &&
    !OTHER_INPUT_READ_REGEX.test(content) &&
    FILE_INSTANCE_CHECK_REGEX.test(content) &&
    FILE_SIZE_CHECK_REGEX.test(content) &&
    FILE_TYPE_CHECK_REGEX.test(content)
  );
}

export class MissingValidationDetector implements Detector {
  id = "missing-validation-detector";
  name = "Missing Input Validation";
  category = "validation" as const;
  description = "Detects API routes that read request data without validating it.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const filePath of context.files) {
      if (isExpressCandidateFile(filePath) && !isApiRoute(filePath)) {
        findings.push(...(await this.detectExpress(filePath, context)));
        continue;
      }
      if (!isApiRoute(filePath)) {
        continue;
      }

      const content = await context.readFile(filePath);

      // Webhook routes read the raw body for signature verification, handled by StripeWebhookDetector
      if (isStripeWebhookRoute(filePath, content)) {
        continue;
      }

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
          (hasImport && VALIDATION_LIB_CALL_REGEX.test(content)) ||
          isValidatedFileUpload(content);

        if (!validated) {
          const endLine = handlerEndLine(filePath, content, inputIndex);
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
            ...(endLine !== undefined && endLine > line ? { endLine } : {}),
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

  /**
   * Express: for each route whose inline handler chain reads `req.body` (or, on mutating
   * methods only, `req.query` / `req.params`, reported as medium), requires validation inside that chain:
   * express-validator / celebrate calls (only when imported), a schema
   * `parse`/`safeParse`/`validate` call, a `validate*(...)` middleware, or a
   * function-style call from an imported validation library. Best effort: a
   * handler defined elsewhere and passed by name is not inspected.
   */
  private async detectExpress(filePath: string, context: ScanContext): Promise<Finding[]> {
    const content = await context.readFile(filePath);
    if (!usesExpress(content, context.projectContext?.dependencies)) return [];

    const hasImport = VALIDATION_LIB_IMPORT_REGEX.test(content);
    const hasExpressValidator = EXPRESS_VALIDATOR_IMPORT_REGEX.test(content);
    const stripeWebhookFile = isStripeWebhookRoute(filePath, content);
    const findings: Finding[] = [];

    for (const route of extractExpressRoutes(content)) {
      // Stripe webhooks pass the raw body to constructEvent; StripeWebhookDetector covers them.
      // Non-Stripe webhook routes in the same file stay covered.
      if (stripeWebhookFile && isStripeWebhookExpressRoute(route)) continue;
      const chain = route.chainCode;
      let input = EXPRESS_BODY_READ_REGEX.exec(chain);
      let severity: "high" | "medium" = "high";
      if (!input && isExpressMutatingMethod(route.method)) {
        input = EXPRESS_QUERY_READ_REGEX.exec(chain);
        severity = "medium";
      }
      if (!input) continue;
      const middleware = splitTopLevel(chain).slice(0, -1);
      const validated =
        VALIDATION_CALL_REGEXES.some((re) => re.test(chain)) ||
        middleware.some(
          (arg) =>
            EXPRESS_VALIDATE_MIDDLEWARE_CALL_REGEX.test(arg) ||
            EXPRESS_VALIDATE_MIDDLEWARE_IDENT_REGEX.test(arg),
        ) ||
        (hasImport && VALIDATION_LIB_CALL_REGEX.test(chain)) ||
        (hasExpressValidator && EXPRESS_VALIDATOR_CALL_REGEX.test(chain));
      if (validated) continue;

      const line = route.chainStartLine + lineOfIndex(chain, input.index) - 1;
      const chainStart = content.indexOf(route.handlerChain, route.index);
      const endLine =
        chainStart < 0
          ? undefined
          : (handlerEndLine(filePath, content, chainStart + input.index) ??
            lineOfIndex(content, chainStart + Math.max(0, route.handlerChain.length - 1)));
      const shownPath = displayRoutePath(route.path);
      // The rule id is reused deliberately for query/params reads (existing suppressions and
      // baselines keep working); they are "medium" and only reported on mutating routes.
      findings.push({
        id: createFindingId(
          CATEGORY_PREFIX.validation,
          "validation/missing-body-validation",
          filePath,
          line,
        ),
        ruleId: "validation/missing-body-validation",
        title: "Unvalidated Request Input",
        severity,
        category: "validation",
        deployBlocking: false,
        confidence: "medium",
        file: filePath,
        line,
        ...(endLine !== undefined && endLine > line ? { endLine } : {}),
        plainEnglishProblem: `The Express route ${route.method} ${shownPath} reads data sent by the user (req.body, req.query or req.params), but doesn't validate it before using it.`,
        whyItMatters:
          "Malicious users can send unexpected data types (like an object instead of a string) to crash your server or bypass security checks.",
        fixSteps: [
          "Install a validation library like Zod (`npm i zod`) or express-validator.",
          "Define a schema describing exactly what you expect in the request.",
          "Validate the request with the schema (or a validation middleware) before using it.",
        ],
        autoFixAvailable: false,
        aiFixPrompt: `This Express route (${route.method} ${shownPath}) reads request data without validating it. Please add a Zod schema (or express-validator rules) and validate the input before using it.`,
      });
    }
    return findings;
  }
}
