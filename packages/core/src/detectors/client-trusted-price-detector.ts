import type {
  Confidence,
  Detector,
  Finding,
  ScanContext,
  Severity,
} from "@talaljaber/vibesafe-shared";
import { makeFinding } from "./utils/finding.js";
import {
  enclosingOpen,
  expressionEnd,
  extractFunctions,
  handlerSpans,
  type FunctionSpan,
} from "./utils/js-functions.js";
import type { JsSource } from "./utils/js-source.js";
import { analyzeTaint, type TaintHit, type TaintState } from "./utils/taint.js";
import {
  calleeText,
  declarationInit,
  escapeRegExp,
  inIndexBracket,
  nextNonWs,
  prevNonWs,
  serverSources,
} from "./utils/tooling-js.js";

/**
 * `validation/client-trusted-price`: a request handler passes a price, amount or total
 * that comes from the request to a payment API, so the buyer chooses what they pay.
 *
 * Sinks (masked code, inside request handlers only):
 * - `unit_amount` / `unit_amount_decimal` inside a Stripe `price_data` object;
 * - `amount` in `stripe.checkout.sessions.create`, `paymentIntents.create`,
 *   `charges.create`, Razorpay `orders.create`, Mollie `payments.create` (`amount.value`)
 *   and Braintree `transaction.sale`;
 * - `amount.value` inside a PayPal `purchase_units` array.
 *
 * The value is client-controlled when it reads a price-like field (`price`, `amount`,
 * `unitPrice`, `total_cents`, ...) from request data: directly (`req.body.price`), from
 * a binding of it (`const { items } = parsed.data`), from the element parameter of an
 * iteration over it (`items.map((i) => i.price)`), or through up to two local
 * declarations (`const total = items.reduce((s, i) => s + i.price, 0)`). Server lookups
 * keyed by request data (`PRICES[body.plan]`, `catalog.find(...)`, awaited database
 * reads) are not client prices. Quantities and ids from the client are fine.
 *
 * Skipped: Stripe `prices.create` / `invoiceItems.create` (admin price setup), values
 * nested under `metadata`, handlers that compare the client price with another value
 * before the sink, and donation / tip / top-up handlers where the payer picks the amount.
 */

const MAX_PER_FILE = 25;

const PREFILTER = /unit_amount|purchase_units|\.\s*(?:create|sale)\s*\(/;

/** Price-like field names: price, amount, total, cost with common prefixes/suffixes. */
const PRICE_NAME_RE =
  /^(?:unit_?|total_?|sub_?|grand_?|line_?|item_?)?(?:price|amount|total|cost)(?:_?(?:cents|in_?cents|usd|value|amount))?$/i;

/** Payment calls whose `amount` (or `amount.value`) is charged as given. */
const PAYMENT_CALLEE_RES: readonly RegExp[] = [
  /(?:^|\.)(?:checkout\.sessions|paymentIntents|charges)\.create$/,
  /razorpay\w*\.orders\.create$/i,
  /mollie\w*\.payments\.create$/i,
  /(?:^|\.)(?:gateway|braintree\w*)\.transaction\.sale$/i,
];

const PAYMENT_CALL_RE =
  /\b(?:sessions|paymentIntents|charges|orders|payments|transaction)\s*\.\s*(?:create|sale)\s*\(/g;
const PRICE_DATA_RE = /(?<![\w$.])price_data\s*:\s*\{/g;
const PURCHASE_UNITS_RE = /(?<![\w$.])purchase_units\s*:\s*\[/g;
const AMOUNT_KEY_RE = /(?<![\w$.])(unit_amount(?:_decimal)?|amount|value)\s*:(?!:)/g;
const SHORTHAND_RE = /[{,]\s*(amount|value)(?![\w$])/g;
const CHAIN_RE =
  /(?<![\w$.])([A-Za-z_$][\w$]*)((?:\s*\??\.\s*[A-Za-z_$][\w$]*|\s*\[\s*\d+\s*\])*)/g;
const DONATION_RE =
  /donat|\btips?\b|tip[-_]?amount|top-?up|pay[-_ ]?what|custom[-_ ]?amount|contribution|deposit/i;

const KEYWORDS = new Set([
  "await",
  "new",
  "typeof",
  "void",
  "return",
  "true",
  "false",
  "null",
  "undefined",
  "this",
  "as",
  "satisfies",
  "in",
  "of",
  "instanceof",
]);

interface Sink {
  /** Offset of the amount key. */
  key: number;
  valueStart: number;
  valueEnd: number;
  /** Payment call or provider-specific key (unit_amount, purchase_units). */
  reason: "unit-amount" | "payment-call" | "paypal";
}

interface Hit {
  direct: boolean;
}

interface Ctx {
  src: JsSource;
  state: TaintState;
  handler: FunctionSpan;
  spans: readonly FunctionSpan[];
}

/** Opening bracket of the object literal that directly contains `pos`, or -1. */
function enclosingObject(src: JsSource, pos: number): number {
  const open = enclosingOpen(src, pos);
  return open >= 0 && src.code[open] === "{" ? open : -1;
}

/** Key text before the object/array opening at `open` (`price_data` in `price_data: {`). */
function keyBefore(code: string, open: number): string {
  const p = prevNonWs(code, open - 1);
  if (code[p] !== ":") return "";
  const e = prevNonWs(code, p - 1);
  let s = e;
  while (s >= 0 && /[\w$]/.test(code[s]!)) s--;
  return code.slice(s + 1, e + 1);
}

/** True when some object between `pos` and `floor` is the value of a `metadata` key. */
function underMetadata(src: JsSource, pos: number, floor: number): boolean {
  let open = enclosingOpen(src, pos);
  for (let guard = 0; guard < 16 && open > floor; guard++) {
    if (src.code[open] === "{" && /^metadata$/i.test(keyBefore(src.code, open))) return true;
    open = enclosingOpen(src, open);
  }
  return false;
}

function amountKeysIn(src: JsSource, from: number, to: number, reason: Sink["reason"]): Sink[] {
  const code = src.code;
  const out: Sink[] = [];
  const seg = code.slice(from, to);
  AMOUNT_KEY_RE.lastIndex = 0;
  for (let m = AMOUNT_KEY_RE.exec(seg); m !== null; m = AMOUNT_KEY_RE.exec(seg)) {
    const key = from + m.index;
    const name = m[1]!;
    const p = prevNonWs(code, key - 1);
    if (code[p] !== "{" && code[p] !== ",") continue; // not an object key
    const valueStart = nextNonWs(code, key + m[0].length);
    if (code[valueStart] === "{" || code[valueStart] === "[") continue; // nested amount object
    const obj = enclosingObject(src, key);
    if (obj < 0) continue;
    if (name.startsWith("unit_amount")) {
      if (reason === "unit-amount" && obj !== from - 1) continue;
      if (keyBefore(code, obj) !== "price_data") continue;
    } else if (reason === "unit-amount") {
      continue; // only the price_data unit amount itself
    } else if (name === "value") {
      if (!/^amount$/i.test(keyBefore(code, obj))) continue;
    } else if (reason === "paypal") {
      continue; // PayPal amounts are `amount: { value }`
    }
    if (underMetadata(src, key, from - 1)) continue;
    const valueEnd = expressionEnd(src, valueStart, to);
    if (valueEnd <= valueStart) continue;
    out.push({ key, valueStart, valueEnd, reason });
  }
  // Shorthand properties: `{ amount, currency }`, `amount: { value, currency_code }`.
  if (reason === "unit-amount") return out;
  SHORTHAND_RE.lastIndex = 0;
  for (let m = SHORTHAND_RE.exec(seg); m !== null; m = SHORTHAND_RE.exec(seg)) {
    const key = from + m.index + m[0].length - m[1]!.length;
    const after = nextNonWs(code, key + m[1]!.length);
    if (code[after] !== "," && code[after] !== "}") continue;
    const obj = enclosingObject(src, key);
    if (obj < 0) continue;
    const parentIsAmount = /^amount$/i.test(keyBefore(code, obj));
    if (m[1] === "value" ? !parentIsAmount : reason === "paypal") continue;
    if (underMetadata(src, key, from - 1)) continue;
    out.push({ key, valueStart: key, valueEnd: key + m[1]!.length, reason });
  }
  return out;
}

function findSinks(src: JsSource): Sink[] {
  const code = src.code;
  const sinks: Sink[] = [];
  const seen = new Set<number>();
  const push = (list: Sink[]): void => {
    for (const s of list) {
      if (seen.has(s.key)) continue;
      seen.add(s.key);
      sinks.push(s);
    }
  };
  for (const m of code.matchAll(PRICE_DATA_RE)) {
    const open = m.index + m[0].length - 1;
    const close = src.matchOf(open);
    if (close > open) push(amountKeysIn(src, open + 1, close, "unit-amount"));
  }
  for (const m of code.matchAll(PAYMENT_CALL_RE)) {
    const open = m.index + m[0].length - 1;
    const callee = calleeText(code, open);
    if (!PAYMENT_CALLEE_RES.some((re) => re.test(callee))) continue;
    const close = src.matchOf(open);
    if (close > open) push(amountKeysIn(src, open + 1, close, "payment-call"));
  }
  for (const m of code.matchAll(PURCHASE_UNITS_RE)) {
    const open = m.index + m[0].length - 1;
    const close = src.matchOf(open);
    if (close > open) push(amountKeysIn(src, open + 1, close, "paypal"));
  }
  return sinks.sort((a, b) => a.key - b.key);
}

/** The span whose parameters contain `offset` (a callback element parameter), if any. */
function isCallbackParam(spans: readonly FunctionSpan[], offset: number, handler: FunctionSpan) {
  return spans.some(
    (s) =>
      s !== handler && s.paramsStart <= offset && offset < s.paramsEnd && s.start > handler.start,
  );
}

/**
 * True when the tainted base (`hit`) carries request data itself rather than the result
 * of a server-side lookup keyed by request data.
 */
function acceptHit(ctx: Ctx, hit: TaintHit, depth: number): boolean {
  if (hit.via === undefined) return hit.path !== "indirect";
  return acceptBinding(ctx, hit.via, hit.offset, depth);
}

function acceptBinding(ctx: Ctx, name: string, at: number, depth: number): boolean {
  const b = ctx.state.bindingAt(name, at);
  if (b?.hit === undefined) return false;
  if (b.hit.path === "indirect") return isCallbackParam(ctx.spans, b.offset, ctx.handler);
  const init = declarationInit(ctx.src, b.offset, ctx.handler.bodyEnd);
  if (init === undefined) return true; // handler parameter seeded with request data
  if (depth >= 4) return false;
  for (const h of ctx.state.exprTaints(init.start, init.end)) {
    if (inIndexBracket(ctx.src, h.offset, init.start)) continue; // PRICES[plan]
    if (inLookupCall(ctx.src, h.offset, init.start)) continue; // catalog.find(...), getPrice(id)
    if (h.via === undefined) return true;
    if (acceptBinding(ctx, h.via, h.offset, depth + 1)) return true;
  }
  return false;
}

/** Calls that hand request data back unchanged (validation, cloning, parsing). */
const CARRY_CALLEE_RE =
  /^(?:structuredClone|Object\.assign|JSON\.parse|Array\.from|[\w$.]*\.(?:parse|safeParse|parseAsync|safeParseAsync|validate|validateSync|validateAsync|cast))$/;
const NOT_CALL = new Set([
  "if",
  "for",
  "while",
  "switch",
  "catch",
  "return",
  "await",
  "typeof",
  "void",
  "function",
  "yield",
  "in",
  "of",
]);

/**
 * True when `pos` sits in the arguments of a call (between `floor` and `pos`) that does
 * not just hand its argument back: the value is a lookup or a transformation of the
 * request data, not the request data itself.
 */
function inLookupCall(src: JsSource, pos: number, floor: number): boolean {
  const code = src.code;
  let open = enclosingOpen(src, pos);
  for (let guard = 0; guard < 32 && open >= floor && open >= 0; guard++) {
    if (code[open] === "(") {
      const callee = calleeText(code, open);
      const last = callee.slice(callee.lastIndexOf(".") + 1);
      if (callee !== "" && !NOT_CALL.has(last) && !CARRY_CALLEE_RE.test(callee)) return true;
    }
    open = enclosingOpen(src, open);
  }
  return false;
}

/** Latest simple `const|let|var name = <init>` in the handler before `before`. */
function localInit(
  ctx: Ctx,
  name: string,
  before: number,
): { start: number; end: number } | undefined {
  const code = ctx.src.code;
  const re = new RegExp(
    String.raw`\b(?:const|let|var)\s+(${escapeRegExp(name)})\s*(?::[^=;\n]{0,120})?=(?![=>])`,
    "g",
  );
  re.lastIndex = ctx.handler.bodyStart;
  let last: { start: number; end: number } | undefined;
  for (let m = re.exec(code); m !== null && m.index < before; m = re.exec(code)) {
    const start = nextNonWs(code, m.index + m[0].length);
    last = { start, end: expressionEnd(ctx.src, start, ctx.handler.bodyEnd) };
  }
  return last;
}

/** The client-controlled price read inside `[start, end)`, if any. */
function clientPrice(
  ctx: Ctx,
  start: number,
  end: number,
  depth: number,
  seen: Set<string>,
): Hit | undefined {
  const code = ctx.src.code;
  const seg = code.slice(start, end);
  CHAIN_RE.lastIndex = 0;
  const matches = [...seg.matchAll(CHAIN_RE)];
  for (const m of matches) {
    const name = m[1]!;
    if (KEYWORDS.has(name) || /^\d/.test(name)) continue;
    const at = start + m.index;
    const chainEnd = at + m[0].length;
    const after = nextNonWs(code, chainEnd);
    if (code[after] === "(") continue; // a call, judged by its arguments
    const before = prevNonWs(code, at - 1);
    if (code[after] === ":" && (code[before] === "{" || code[before] === ",")) continue; // key
    const props = [...m[2]!.matchAll(/[A-Za-z_$][\w$]*/g)].map((x) => x[0]);
    if (props.length > 0) {
      if (!PRICE_NAME_RE.test(props[props.length - 1]!)) continue;
      const baseEnd = at + m[0].lastIndexOf(".");
      const hit = ctx.state.exprTaint(at, code[baseEnd - 1] === "?" ? baseEnd - 1 : baseEnd);
      if (hit === undefined || !acceptHit(ctx, hit, 0)) continue;
      if (comparedBefore(ctx, code.slice(at, chainEnd), at)) continue;
      return { direct: hit.path === "direct" && depth === 0 };
    }
    if (PRICE_NAME_RE.test(name)) {
      // A price-like name counts by itself only when it is a field taken out of request
      // data (`const { price } = body`) or a parameter carrying it; a plain local
      // (`const total = ...`) is judged by its initializer below.
      const b = ctx.state.bindingAt(name, at);
      const plainLocal =
        b !== undefined &&
        /[A-Za-z_$]/.test(code[b.offset] ?? "") &&
        declarationInit(ctx.src, b.offset, ctx.handler.bodyEnd) !== undefined;
      if (
        b !== undefined &&
        !plainLocal &&
        acceptBinding(ctx, name, at, 0) &&
        !comparedBefore(ctx, name, at)
      )
        return { direct: false };
    }
    if (depth < 2 && !seen.has(name)) {
      seen.add(name);
      const init = localInit(ctx, name, at);
      if (init !== undefined && clientPrice(ctx, init.start, init.end, depth + 1, seen))
        return { direct: false };
    }
  }
  return undefined;
}

/** The handler compares the client value with something before the sink (a price check). */
function comparedBefore(ctx: Ctx, expr: string, before: number): boolean {
  const parts = expr.split(/\s*\??\.\s*/).map(escapeRegExp);
  const e = String.raw`(?<![\w$.])${parts.join(String.raw`\s*\??\.\s*`)}(?![\w$])`;
  const re = new RegExp(String.raw`${e}\s*!==?|!==?\s*${e}`);
  return re.test(ctx.src.code.slice(ctx.handler.bodyStart, before));
}

export class ClientTrustedPriceDetector implements Detector {
  id = "client-trusted-price-detector";
  name = "Client-Trusted Payment Amount";
  category = "validation" as const;
  description =
    "Detects request handlers that charge a price, amount or total sent by the client (Stripe, PayPal, Razorpay, Mollie, Braintree) instead of a server-side price.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    try {
      for (const { file, src, classification } of await serverSources(context, PREFILTER)) {
        if (DONATION_RE.test(file)) continue;
        const sinks = findSinks(src);
        if (sinks.length === 0) continue;
        const handlers = handlerSpans(src, classification);
        if (handlers.length === 0) continue;
        const spans = extractFunctions(src, classification);
        const lines = new Set<number>();
        for (const sink of sinks) {
          if (lines.size >= MAX_PER_FILE) break;
          const handler = handlers.find((h) => h.start <= sink.key && sink.key < h.end);
          if (handler === undefined) continue;
          if (DONATION_RE.test(src.text.slice(handler.start, handler.end))) continue;
          const line = src.lineAt(sink.key);
          if (lines.has(line)) continue;
          const state = analyzeTaint(src, handler, { runtime: "server" });
          const ctx: Ctx = { src, state, handler, spans };
          const hit = clientPrice(ctx, sink.valueStart, sink.valueEnd, 0, new Set());
          if (hit === undefined) continue;
          lines.add(line);
          findings.push(this.finding(file, src, sink, line, hit.direct, handler.truncated));
        }
      }
    } catch {
      // Detectors never throw.
    }
    return findings;
  }

  private finding(
    file: string,
    src: JsSource,
    sink: Sink,
    line: number,
    direct: boolean,
    truncated: boolean,
  ): Finding {
    let severity: Severity = direct ? "critical" : "high";
    let confidence: Confidence = direct ? "high" : "medium";
    if (truncated) {
      confidence = "medium";
      if (severity === "critical") severity = "high";
    }
    const endLine = src.lineAt(Math.max(sink.valueStart, sink.valueEnd - 1));
    return makeFinding({
      category: "validation",
      ruleId: "validation/client-trusted-price",
      title: "Payment amount comes from the client",
      severity,
      confidence,
      file,
      line,
      endLine: endLine > line ? endLine : undefined,
      evidence: src.lineText(line).trim(),
      plainEnglishProblem:
        "This request handler sends a payment amount to the payment provider that it reads from the request (a price, amount or total field the browser sends) instead of looking the price up on the server.",
      whyItMatters:
        "Anyone can edit the request in the browser dev tools or with curl and set the price to one cent. The payment provider charges exactly the amount your server asks for, so the order is paid at the buyer's price, and a webhook that marks the order paid will then treat it as fully paid.",
      fixSteps: [
        "Accept only product ids (or server-created Stripe Price ids) and quantities from the client, never a price, amount or total.",
        "Load each product's price from your database (or use a Stripe Price id) and compute every line item amount and the order total on the server.",
        "Reject unknown, inactive or other-store product ids before creating the payment.",
        "Save the server-computed total on the order and compare it with the paid amount in the payment webhook before marking the order paid.",
      ],
      aiFixPrompt:
        "This request handler passes a price, amount or total taken from the request to the payment provider, so a buyer can choose what they pay. Change it so the client sends only product ids (or server-created Stripe Price ids) and quantities. Load each product's price from the database on the server, compute every line item amount and the order total from those prices, reject unknown or inactive products and products that belong to another store, and save the server-computed total on the order. Keep the existing input validation for ids and quantities, and do not read any price, amount or total field from the request.",
    });
  }
}
