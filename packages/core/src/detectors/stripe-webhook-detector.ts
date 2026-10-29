import type { Detector, Finding, ScanContext } from "@vibesafe/shared";
import { CATEGORY_PREFIX, createFindingId } from "@vibesafe/shared";
import { sanitizeEvidence } from "./utils/sanitize-evidence.js";
import { stripComments } from "./utils/strip-comments.js";

export { stripComments };

const SCANNABLE_SUFFIXES = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"] as const;
const TEST_FILE_RE = /(?:\.(?:test|spec)\.[cm]?[jt]sx?$)|(?:(?:^|\/)__tests__\/)/;

/** Handler shapes that clearly mean "request handler" (case-sensitive export names). */
const EXPORT_HANDLER_RE =
  /export\s+(?:async\s+)?function\s+(?:POST|handler)\b|export\s+const\s+POST\b|export\s+default\s+(?:async\s+)?function\s+handler\b/;
const ROUTER_HANDLER_RE = /\b(?:router|app|server|fastify)\s*\.\s*(?:post|all|use)\s*\(/;
const SIGNATURE_HEADER_RE = /stripe-signature/i;
/** A bare default export only counts as a handler in a Pages Router API file. */
const DEFAULT_EXPORT_RE = /export\s+default\b/;

const ROUTE_LIKE_PATH_RE =
  /(?:^|\/)route\.[cm]?[jt]s$|(?:^|\/)pages\/api\/|(?:^|\/)app\/api\/|(?:^|\/)api\/|webhook[^/]*$/;

const HELPER_NAME_RE =
  /(?:verify|validate).*(?:stripe|webhook|signature|event)|construct.*(?:event|webhook)|webhook.*(?:event|signature)|stripe.*event/i;

/** Cheap raw-text pre-filter so unrelated files are never scanned or stripped. */
const RAW_PREFILTER_RE = /stripe|webhook/i;

/**
 * Cheap raw-text check run before any comment stripping: a file whose path and content never
 * mention `stripe` or `webhook` cannot be a Stripe webhook handler.
 */
export function mayBeStripeWebhookFile(filePath: string, fileContent: string): boolean {
  return RAW_PREFILTER_RE.test(filePath) || RAW_PREFILTER_RE.test(fileContent);
}

/** Route-level evidence that an Express webhook route is the Stripe receiver of its file. */
const ROUTE_STRIPE_EVIDENCE_RE = /stripe|constructEvent|(?:express|bodyParser)\s*\.\s*raw|rawBody/i;

function isHandlerText(text: string, allowDefaultExport: boolean, headerCounts = true): boolean {
  return (
    EXPORT_HANDLER_RE.test(text) ||
    ROUTER_HANDLER_RE.test(text) ||
    (headerCounts && SIGNATURE_HEADER_RE.test(text)) ||
    (allowDefaultExport && DEFAULT_EXPORT_RE.test(text))
  );
}

function allowsDefaultExport(normalizedPath: string): boolean {
  return /(?:^|\/)pages\/api\//.test(normalizedPath);
}

/** Event names only count when written as a string literal (not property access like `session.payment_intent.id`). */
const EVENT_NAME_LITERAL_RE =
  /(["'`])(?:checkout\.session\.(?:completed|expired|async_payment_succeeded|async_payment_failed)|customer\.subscription\.(?:created|updated|deleted|paused|resumed|trial_will_end)|payment_intent\.(?:succeeded|payment_failed|created|canceled|processing|requires_action|amount_capturable_updated|partially_funded)|invoice\.(?:paid|payment_succeeded|payment_failed|finalized))\1/;

function hasWebhookSignals(code: string): boolean {
  return (
    /stripe-signature/i.test(code) ||
    EVENT_NAME_LITERAL_RE.test(code) ||
    /\bstripe\.webhooks\b/i.test(code)
  );
}

function hasStripeReference(code: string): boolean {
  return (
    /['"]stripe['"]/i.test(code) ||
    /\bnew\s+Stripe\b/.test(code) ||
    /\bStripe\./.test(code) ||
    /from\s+['"][^'"]*stripe[^'"]*['"]/i.test(code) ||
    /\bstripe\s*\./.test(code)
  );
}

/**
 * Determines if a file is a handler dedicated to Stripe webhooks, by path naming (`stripe` +
 * `webhook`, route-like files only) or by content (Stripe usage plus webhook signals, or a
 * `stripe-signature` header read). Either way the file must show real handler evidence.
 * Comments are stripped internally so callers can pass raw file content; files that fail the
 * cheap `mayBeStripeWebhookFile` pre-filter return early without being stripped.
 */
export function isStripeWebhookRoute(filePath: string, fileContent: string): boolean {
  if (!mayBeStripeWebhookFile(filePath, fileContent)) return false;
  const normalizedPath = filePath.replace(/\\/g, "/").toLowerCase();
  if (TEST_FILE_RE.test(normalizedPath)) return false;

  const code = stripComments(fileContent);
  const signals = hasWebhookSignals(code);

  const isStripeWebhookPath =
    normalizedPath.includes("stripe") &&
    normalizedPath.includes("webhook") &&
    ROUTE_LIKE_PATH_RE.test(normalizedPath);

  // A route that manages webhook endpoints through the Stripe API is not itself a webhook receiver.
  if (isStripeWebhookPath && !signals && /\bwebhookEndpoints\b/.test(code)) return false;

  const isContentMatch = (hasStripeReference(code) && signals) || SIGNATURE_HEADER_RE.test(code);

  if (isStripeWebhookPath || isContentMatch) {
    // Reading the stripe-signature header alone is only handler evidence in route-like files
    // (a helper such as lib/stripe-signature.ts merely reads it).
    return isHandlerText(
      code,
      allowsDefaultExport(normalizedPath),
      ROUTE_LIKE_PATH_RE.test(normalizedPath),
    );
  }
  return false;
}

/**
 * True when an Express route path names a webhook endpoint. Used by `isStripeWebhookExpressRoute`,
 * which also needs route-level Stripe evidence, so only the Stripe receiver is exempt.
 */
export function isWebhookPath(routePath: string): boolean {
  return /webhook/i.test(routePath);
}

/**
 * True when an Express route in a Stripe webhook file is itself the Stripe receiver: its path names
 * a webhook and its path or handler chain shows Stripe evidence (`stripe`, `constructEvent`,
 * `express.raw`, `bodyParser.raw`, `rawBody`). `chainCode` has comments and string contents blanked, so only real
 * code counts. Other webhook routes in the same file (e.g. `/webhooks/github`) stay covered.
 */
export function isStripeWebhookExpressRoute(route: { path: string; chainCode: string }): boolean {
  return (
    isWebhookPath(route.path) &&
    (ROUTE_STRIPE_EVIDENCE_RE.test(route.path) || ROUTE_STRIPE_EVIDENCE_RE.test(route.chainCode))
  );
}

/**
 * True when the source calls `webhooks.constructEvent(...)`/`constructEventAsync(...)` or a bare
 * (imported) `constructEvent(...)`. Expects code with string contents blanked, so text inside
 * strings or comments never counts.
 */
export function hasStripeSignatureVerification(code: string): boolean {
  if (/\bwebhooks\s*\.\s*constructEvent(?:Async)?\s*\(/.test(code)) return true;
  if (/(?<![.\w$])constructEvent(?:Async)?\s*\(/.test(code)) return true;
  return /\.\s*constructEvent(?:Async)?\s*\(/.test(code) && /\bwebhooks\b/.test(code);
}

/** Names imported or required into the file (local binding names). */
function importedNames(code: string): Set<string> {
  const names = new Set<string>();
  const add = (list: string): void => {
    for (const part of list.split(",")) {
      const m = /(?:\b[\w$]+\s+as\s+|\*\s+as\s+)?([\w$]+)\s*$/.exec(part.trim());
      if (m?.[1]) names.add(m[1]);
    }
  };
  for (const m of code.matchAll(/import\s+([^'";]+?)\s+from\s*['"]/g)) {
    const clause = m[1] ?? "";
    const braces = /\{([^}]*)\}/.exec(clause);
    if (braces?.[1]) add(braces[1]);
    const def = /^([\w$]+)/.exec(clause.trim());
    if (def?.[1]) names.add(def[1]);
    const ns = /\*\s+as\s+([\w$]+)/.exec(clause);
    if (ns?.[1]) names.add(ns[1]);
  }
  for (const m of code.matchAll(
    /(?:const|let|var)\s+(\{[^}]*\}|[\w$]+)\s*=\s*(?:await\s+)?(?:import|require)\s*\(/g,
  )) {
    const target = m[1] ?? "";
    if (target.startsWith("{")) add(target.slice(1, -1));
    else names.add(target);
  }
  return names;
}

/**
 * True when verification is plausibly delegated: a call to an imported function with a
 * verification-like name, or a `stripe.webhooks` reference.
 */
export function mayDelegateVerification(code: string): boolean {
  if (/\bwebhooks\s*\.\s*(?:signature|constructEvent)/.test(code)) return true;
  for (const name of importedNames(code)) {
    if (!HELPER_NAME_RE.test(name)) continue;
    const escaped = name.replace(/\$/g, "\\$");
    if (new RegExp(`(?<![\\w$])${escaped}\\s*[(.]`).test(code)) return true;
  }
  return false;
}

/**
 * Returns the 1-indexed line of a constructEvent call whose payload argument is an already
 * parsed body (`req.body`, `await req.json()`, `JSON.stringify(...)`) instead of the raw text.
 */
function findParsedBodyVerification(code: string): number | undefined {
  const re =
    /\bconstructEvent(?:Async)?\s*\(\s*(JSON\.stringify\s*\(|await\s+[\w.]+\.json\s*\(|[\w.]+\.body\b)/g;
  const hasRawHint =
    /\b(?:express|bodyParser)\s*\.\s*raw\s*\(|bodyParser\s*:\s*false|\bgetRawBody\s*\(|(?<![.\w$])buffer\s*\(|\brawBody\b|\breq\.text\s*\(|\.arrayBuffer\s*\(/.test(
      code,
    );
  for (const m of code.matchAll(re)) {
    const arg = m[1] ?? "";
    // `.body` alone is ambiguous (express.raw / bodyParser: false make it a Buffer), so trust raw hints.
    if (/\.body$/.test(arg) && hasRawHint) continue;
    return code.slice(0, m.index).split("\n").length;
  }
  return undefined;
}

function findHandlerLine(
  lines: string[],
  allowDefaultExport: boolean,
): { line: number; text: string } {
  for (let i = 0; i < lines.length; i++) {
    const text = lines[i] ?? "";
    if (isHandlerText(text, allowDefaultExport)) return { line: i + 1, text };
  }
  return { line: 1, text: lines[0] ?? "" };
}

/** Webhook signing secrets can be shorter than the generic secret pattern; always redact them. */
function redactWebhookSecrets(line: string): string {
  return line.replace(/whsec_[A-Za-z0-9]+/g, "whsec_***");
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
  description =
    "Ensures Stripe webhook routes verify signatures using stripe.webhooks.constructEvent() on the raw body.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const filePath of context.files) {
      if (!SCANNABLE_SUFFIXES.some((suffix) => filePath.endsWith(suffix))) continue;

      const raw = await context.readFile(filePath);
      // isStripeWebhookRoute applies the cheap raw-text pre-filter before stripping comments.
      if (!isStripeWebhookRoute(filePath, raw)) continue;

      const content = stripComments(raw);
      const code = stripComments(raw, { blankStrings: true });
      const lines = content.split("\n");
      const allowDefault = allowsDefaultExport(filePath.replace(/\\/g, "/").toLowerCase());

      if (!hasStripeSignatureVerification(code)) {
        // Verification may live in a shared helper; only claim "unsigned" when none is plausible.
        if (mayDelegateVerification(code)) continue;

        const { line, text } = findHandlerLine(lines, allowDefault);
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
          evidence: sanitizeEvidence(redactWebhookSecrets(text)),
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

      const parsedLine = findParsedBodyVerification(code);
      if (parsedLine !== undefined) {
        findings.push({
          id: createFindingId(
            CATEGORY_PREFIX.auth,
            "auth/stripe-webhook-parsed-body",
            filePath,
            parsedLine,
          ),
          ruleId: "auth/stripe-webhook-parsed-body",
          title: "Stripe webhook verified against a parsed body",
          severity: "high",
          category: "auth",
          deployBlocking: false,
          confidence: "medium",
          file: filePath,
          line: parsedLine,
          evidence: sanitizeEvidence(redactWebhookSecrets(lines[parsedLine - 1] ?? "")),
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
