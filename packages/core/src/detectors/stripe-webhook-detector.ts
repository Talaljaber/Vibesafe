import type { Detector, Finding, ScanContext } from "@vibesafe/shared";
import { CATEGORY_PREFIX, createFindingId } from "@vibesafe/shared";
import { sanitizeEvidence } from "./utils/sanitize-evidence.js";

const SCANNABLE_SUFFIXES = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"] as const;
const TEST_FILE_RE = /(?:\.(?:test|spec)\.[cm]?[jt]sx?$)|(?:(?:^|\/)__tests__\/)/;

/** Handler shapes: Next.js App/Pages router exports, Express/Fastify-style routes, raw signature header reads. */
const HANDLER_RE =
  /export\s+(?:async\s+)?function\s+(?:POST|handler)\b|export\s+const\s+POST\b|export\s+default\b|\b(?:router|app|server|fastify)\s*\.\s*(?:post|all|use)\s*\(|stripe-signature/i;

const CONSTRUCT_EVENT_RE = /\bconstructEvent(?:Async)?\s*\(/;

/**
 * Replace comments with whitespace (newlines kept so line numbers stay valid) while
 * leaving string and template literal contents untouched.
 */
export function stripComments(source: string): string {
  let out = "";
  let i = 0;
  const n = source.length;
  while (i < n) {
    const c = source[i] as string;
    const next = source[i + 1];
    if (c === "/" && next === "/") {
      while (i < n && source[i] !== "\n") {
        out += " ";
        i++;
      }
    } else if (c === "/" && next === "*") {
      out += "  ";
      i += 2;
      while (i < n && !(source[i] === "*" && source[i + 1] === "/")) {
        out += source[i] === "\n" ? "\n" : " ";
        i++;
      }
      if (i < n) {
        out += "  ";
        i += 2;
      }
    } else if (c === '"' || c === "'" || c === "`") {
      out += c;
      i++;
      while (i < n && source[i] !== c) {
        if (source[i] === "\\" && i + 1 < n) {
          out += source[i] as string;
          i++;
        }
        out += source[i] as string;
        i++;
      }
      if (i < n) {
        out += c;
        i++;
      }
    } else {
      out += c;
      i++;
    }
  }
  return out;
}

/**
 * Determines if a file is a handler dedicated to Stripe webhooks, by path naming
 * (`stripe` + `webhook`) or by content (Stripe usage plus webhook signals).
 * Expects comment-free content.
 */
export function isStripeWebhookRoute(filePath: string, fileContent: string): boolean {
  const normalizedPath = filePath.replace(/\\/g, "/").toLowerCase();
  if (TEST_FILE_RE.test(normalizedPath)) return false;

  const isStripeWebhookPath = normalizedPath.includes("stripe") && normalizedPath.includes("webhook");

  const hasStripeReference =
    /['"]stripe['"]/i.test(fileContent) || /\bnew\s+Stripe\b/.test(fileContent) || /\bStripe\./.test(fileContent);

  const hasStripeWebhookSignals =
    /stripe-signature/i.test(fileContent) ||
    /\bcheckout\.session\.[a-z_]+/i.test(fileContent) ||
    /\bcustomer\.subscription\.[a-z_]+/i.test(fileContent) ||
    /\bpayment_intent\.[a-z_]+/i.test(fileContent) ||
    /\binvoice\.(?:paid|payment_succeeded|payment_failed|finalized)\b/i.test(fileContent) ||
    /\bstripe\.webhooks\b/i.test(fileContent);

  if (isStripeWebhookPath || (hasStripeReference && hasStripeWebhookSignals)) {
    // Must actually look like a request handler (not e.g. a shared helper or type file).
    return HANDLER_RE.test(fileContent);
  }
  return false;
}

/** True when the (comment-free) source contains a call to constructEvent / constructEventAsync. */
export function hasStripeSignatureVerification(fileContent: string): boolean {
  return CONSTRUCT_EVENT_RE.test(fileContent);
}

/**
 * Returns the 1-indexed line of a constructEvent call whose payload argument is an already
 * parsed body (`req.body`, `await req.json()`, `JSON.stringify(...)`) instead of the raw text.
 */
function findParsedBodyVerification(content: string): number | undefined {
  const re = /\bconstructEvent(?:Async)?\s*\(\s*(JSON\.stringify\s*\(|await\s+[\w.]+\.json\s*\(|[\w.]+\.body\b)/g;
  const hasRawHint = /\braw\b|bodyParser\s*:\s*false|getRawBody|req\.text\s*\(|\.arrayBuffer\s*\(/i.test(content);
  for (const m of content.matchAll(re)) {
    const arg = m[1] ?? "";
    // `.body` alone is ambiguous (express.raw / bodyParser: false make it a Buffer), so trust raw hints.
    if (/\.body$/.test(arg) && hasRawHint) continue;
    return content.slice(0, m.index).split("\n").length;
  }
  return undefined;
}

function findHandlerLine(lines: string[]): { line: number; text: string } {
  for (let i = 0; i < lines.length; i++) {
    const text = lines[i] ?? "";
    if (HANDLER_RE.test(text)) return { line: i + 1, text };
  }
  return { line: 1, text: lines[0] ?? "" };
}

/**
 * Detects Stripe webhook routes that do not verify incoming requests with
 * stripe.webhooks.constructEvent() / constructEventAsync(), and routes that verify against a parsed body.
 * Without signature verification, an attacker can forge webhook events to grant themselves paid access.
 */
export class StripeWebhookDetector implements Detector {
  id = "stripe-webhook-detector";
  name = "Stripe Webhook Signature Detection";
  category = "auth" as const;
  description = "Ensures Stripe webhook routes verify signatures using stripe.webhooks.constructEvent() on the raw body.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const filePath of context.files) {
      if (!SCANNABLE_SUFFIXES.some((suffix) => filePath.endsWith(suffix))) continue;

      const content = stripComments(await context.readFile(filePath));
      if (!isStripeWebhookRoute(filePath, content)) continue;

      const lines = content.split("\n");

      if (!hasStripeSignatureVerification(content)) {
        const { line, text } = findHandlerLine(lines);
        findings.push({
          id: createFindingId(CATEGORY_PREFIX.auth, "auth/stripe-webhook-unsigned", filePath, line),
          ruleId: "auth/stripe-webhook-unsigned",
          title: "Stripe webhook route without signature verification",
          severity: "critical",
          category: "auth",
          deployBlocking: true,
          confidence: "high",
          file: filePath,
          line,
          evidence: sanitizeEvidence(text),
          plainEnglishProblem:
            "This route handles Stripe webhooks but never calls stripe.webhooks.constructEvent() to verify the stripe-signature header.",
          whyItMatters:
            "Without signature verification, anyone on the internet can POST fake Stripe events (such as checkout.session.completed) to grant themselves paid access or orders without paying.",
          fixSteps: [
            "Read the raw request body (`await req.text()` in App Router, or disable the body parser in Pages Router / use express.raw()).",
            "Read the 'stripe-signature' header from the request.",
            "Call `stripe.webhooks.constructEvent(rawBody, signature, process.env.STRIPE_WEBHOOK_SECRET!)` inside a try/catch (or constructEventAsync).",
            "Return HTTP 400 immediately if verification throws, before any fulfillment or database logic.",
          ],
          autoFixAvailable: false,
          aiFixPrompt:
            "Secure this Stripe webhook endpoint: read the raw request body, verify it with stripe.webhooks.constructEvent() using the stripe-signature header and STRIPE_WEBHOOK_SECRET, and return 400 when verification fails.",
        });
        continue;
      }

      const parsedLine = findParsedBodyVerification(content);
      if (parsedLine !== undefined) {
        findings.push({
          id: createFindingId(CATEGORY_PREFIX.auth, "auth/stripe-webhook-parsed-body", filePath, parsedLine),
          ruleId: "auth/stripe-webhook-parsed-body",
          title: "Stripe webhook verified against a parsed body",
          severity: "high",
          category: "auth",
          deployBlocking: false,
          confidence: "medium",
          file: filePath,
          line: parsedLine,
          evidence: sanitizeEvidence(lines[parsedLine - 1] ?? ""),
          plainEnglishProblem:
            "constructEvent() is given an already parsed or re-serialised body instead of the raw request body.",
          whyItMatters:
            "Stripe signs the exact raw bytes it sent. Verifying a parsed or re-stringified body fails for genuine events, which often leads people to remove verification altogether.",
          fixSteps: [
            "App Router: use `const body = await req.text()` and pass that string to constructEvent.",
            "Pages Router: export `config = { api: { bodyParser: false } }` and read the raw buffer.",
            "Express: mount `express.raw({ type: 'application/json' })` on the webhook route before any JSON parser.",
          ],
          autoFixAvailable: false,
          aiFixPrompt:
            "Change this Stripe webhook handler so stripe.webhooks.constructEvent() receives the raw, unparsed request body.",
        });
      }
    }

    return findings;
  }
}
