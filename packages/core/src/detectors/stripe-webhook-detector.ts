import type { Detector, Finding, ScanContext } from "@vibesafe/shared";
import crypto from "crypto";

const SCANNABLE_SUFFIXES = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"] as const;

/**
 * Determines if a file is an API route or handler specifically dedicated to Stripe webhooks.
 */
export function isStripeWebhookRoute(filePath: string, fileContent: string): boolean {
  const normalizedPath = filePath.replace(/\\/g, "/").toLowerCase();

  // 1. Path-based check: path contains "stripe" and ("webhook" or "webhooks")
  const isStripeWebhookPath =
    normalizedPath.includes("stripe") &&
    (normalizedPath.includes("webhook") || normalizedPath.includes("webhooks"));

  // 2. Content-based checks
  const hasStripeReference =
    /['"]stripe['"]/i.test(fileContent) ||
    /\bnew\s+Stripe\b/.test(fileContent) ||
    /\bStripe\./.test(fileContent);

  const hasStripeWebhookSignals =
    /stripe-signature/i.test(fileContent) ||
    /checkout\.session\./i.test(fileContent) ||
    /customer\.subscription\./i.test(fileContent) ||
    /payment_intent\./i.test(fileContent) ||
    /invoice\./i.test(fileContent) ||
    /stripe\.webhooks/i.test(fileContent);

  if (isStripeWebhookPath) {
    return true;
  }

  if (hasStripeReference && hasStripeWebhookSignals) {
    return true;
  }

  return false;
}

/**
 * Checks if the file contains an active (uncommented) call to stripe.webhooks.constructEvent.
 */
export function hasStripeSignatureVerification(fileContent: string): boolean {
  const lines = fileContent.split("\n");
  const constructEventRegex = /(?:(?:stripe\.)?webhooks\.)?constructEvent\s*\(/i;

  for (const line of lines) {
    // Ignore lines that are comments
    if (/^\s*(?:\/\/|\/\*|\*)/.test(line)) {
      continue;
    }
    if (constructEventRegex.test(line)) {
      return true;
    }
  }

  return false;
}

/**
 * Detects Stripe webhook routes that do not verify incoming requests with stripe.webhooks.constructEvent().
 * Without signature verification, an external attacker can forge webhook events to grant themselves paid access.
 */
export class StripeWebhookDetector implements Detector {
  id = "stripe-webhook-detector";
  name = "Stripe Webhook Signature Detection";
  category = "auth" as const;
  description = "Ensures Stripe webhook routes verify signatures using stripe.webhooks.constructEvent().";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const filePath of context.files) {
      if (!SCANNABLE_SUFFIXES.some((suffix) => filePath.endsWith(suffix))) {
        continue;
      }

      const content = await context.readFile(filePath);

      if (!isStripeWebhookRoute(filePath, content)) {
        continue;
      }

      if (!hasStripeSignatureVerification(content)) {
        findings.push(this.createFinding(filePath, content));
      }
    }

    return findings;
  }

  private createFinding(filePath: string, content: string): Finding {
    const lines = content.split("\n");
    let lineNumber = 1;
    let evidence = lines[0]?.trim() || filePath;

    // Locate the most relevant line for evidence (handler function, stripe-signature, or route export)
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line === undefined) continue;

      if (
        /export\s+(?:async\s+)?function\s+(?:POST|handler)\b/.test(line) ||
        /router\.post\b/.test(line) ||
        /app\.post\b/.test(line) ||
        /export\s+default\s+(?:async\s+)?function\b/.test(line) ||
        /stripe-signature/i.test(line)
      ) {
        lineNumber = i + 1;
        evidence = line.trim();
        break;
      }
    }

    return {
      id: `AUTH-${crypto.randomBytes(3).toString("hex")}`,
      ruleId: "auth/stripe-webhook-unsigned",
      title: "Stripe webhook route without signature verification",
      severity: "critical",
      category: "auth",
      deployBlocking: true,
      confidence: "high",
      file: filePath,
      line: lineNumber,
      evidence,
      plainEnglishProblem:
        "This API route handles Stripe webhooks but does not call stripe.webhooks.constructEvent() to verify the signature header.",
      whyItMatters:
        "Without cryptographic signature verification, anyone on the internet can POST fake Stripe webhook events (such as checkout.session.completed or invoice.payment_succeeded) to grant themselves paid access, subscriptions, or orders without paying.",
      fixSteps: [
        "Read the raw request body as a Buffer or string before any automatic JSON body parsing.",
        "Retrieve the 'stripe-signature' header from the incoming request.",
        "Verify the signature with `stripe.webhooks.constructEvent(rawBody, signature, process.env.STRIPE_WEBHOOK_SECRET!)` inside a try/catch block.",
        "Return an HTTP 400 response immediately if verification throws an error, before executing any fulfillment or database logic."
      ],
      autoFixAvailable: false,
      aiFixPrompt:
        "Please secure this Stripe webhook endpoint by verifying incoming signatures using stripe.webhooks.constructEvent() with the raw request body, the stripe-signature header, and STRIPE_WEBHOOK_SECRET."
    };
  }
}
