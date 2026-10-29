import type {
  Confidence,
  Detector,
  Finding,
  ScanContext,
  Severity,
} from "@talaljaber/vibesafe-shared";
import {
  callArgs,
  capPerFile,
  findDeclaration,
  inServerOnlyFunction,
  lineOf,
  literalText,
  loadClientFile,
  wholeLiteral,
  type ArgRange,
  type ClientFile,
} from "./utils/client-source.js";
import { makeFinding } from "./utils/finding.js";
import { expressionEnd } from "./utils/js-functions.js";
import type { JsSource } from "./utils/js-source.js";

/**
 * Browser-side leaks of credentials (client-runtime files only):
 * - `frontend_exposure/secret-in-web-storage`: `localStorage`/`sessionStorage` writes
 *   whose key or value is secret-like (API secrets, tokens, sessions, passwords). Any
 *   script running in the origin (one XSS, a compromised dependency) can read them.
 * - `frontend_exposure/sensitive-data-console-log`: `console.*` calls that print a
 *   session, token, secret or auth user object (`high`), or card/identity numbers
 *   (`medium`). This rule coexists with `code_quality/console-log` on purpose: that
 *   finding carries the auto-fix that removes the call.
 *
 * Reads, `removeItem`, literal values and freshly generated ids (`crypto.randomUUID()`)
 * are never flagged.
 */

const MAX_PER_RULE_PER_FILE = 25;
const SET_ITEM_RE = /\b(localStorage|sessionStorage)\s*\.\s*setItem\s*\(/g;
const PROP_WRITE_RE =
  /\b(localStorage|sessionStorage)\s*(?:\.\s*([A-Za-z_$][\w$]*)|\[\s*(["'`])[^\]\n]*\])\s*=(?![=>])/g;
const CONSOLE_RE = /\bconsole\s*\.\s*(?:log|info|debug|warn|error|trace|dir|table)\s*\(/g;
const PREFILTER = /\b(?:localStorage|sessionStorage|console)\b/;

/** Keys that mention a credential but hold metadata about it. */
const NOT_SECRET_KEY_RE =
  /expir|time|date|count|dismiss|consent|seen|theme|lang|locale|cart|redirect|return|nonce|verifier|state|provider|method|type|name|email|ttl|url|id$|at$|flag|enabled/;
/** Value names that are credentials. */
const SECRET_VALUE_RE =
  /^(?:secret|apisecret|clientsecret|secretkey|apikey|accesstoken|refreshtoken|idtoken|token|authtoken|bearertoken|jwt|password|privatekey|session|credentials?|providertoken)$|(?:token|secret|apikey|password)$/;
/** Freshly generated, non-secret values. */
const GENERATED_VALUE_RE =
  /\bcrypto\s*\.\s*(?:randomUUID|getRandomValues)\b|\bnanoid\s*\(|\buuid\w*\s*\(|\bv4\s*\(|\bMath\s*\.\s*random\b|\bDate\s*\.\s*now\b|\bnew\s+Date\b/;

/** Logged names that are credentials or sessions. */
const LOG_HIGH_RE =
  /^(?:session|currentsession|authsession|sessiondata|accesstoken|refreshtoken|idtoken|token|tokens|authtoken|bearertoken|jwt|apikey|apisecret|secret|clientsecret|secretkey|password|credentials?|privatekey|providertoken)$|(?:token|secret|password)$/;
const LOG_USER_RE = /^(?:user|currentuser|authuser|sessionuser|me)$/;
const LOG_PII_RE =
  /^(?:ssn|socialsecuritynumber|creditcard|creditcardnumber|cardnumber|cvv|cvc|iban|accountnumber|routingnumber|dateofbirth|dob|taxid|passportnumber)$/;
const AUTH_ORIGIN_RE =
  /\bauth\b|getSession|useSession|getServerSession|getUser|useUser|currentUser|signIn\w*|onAuthStateChange|getToken|useAuth/;

/** Boolean/flag-style names (`showPassword`, `hasToken`) hold no credential. */
const BOOLEAN_NAME_RE = /^(?:show|hide|has|is|should|toggle|needs?|can|did|was)(?:[A-Z_]|$)/;

function isSecretValueName(name: string): boolean {
  return SECRET_VALUE_RE.test(norm(name)) && !BOOLEAN_NAME_RE.test(name);
}

/**
 * A storage key names a credential when its final word does (`auth_token`, `apiKey`,
 * `supabase.auth.token`); `onboardingSessionStep` or `showTokenBanner` only mention one.
 * `session` counts alone or after an auth-style qualifier.
 */
function isSecretKey(key: string): boolean {
  const tokens = key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t !== "");
  const last = tokens[tokens.length - 1];
  if (last === undefined) return false;
  const tail2 = tokens.slice(-2).join("");
  if (/^(?:apikey|privatekey|accesskey|secretkey|apisecret)$/.test(tail2)) return true;
  if (
    /^(?:secret|secrets|token|tokens|password|passwd|credential|credentials|jwt|bearer|apikey|privatekey|accesskey)$/.test(
      last,
    )
  )
    return true;
  if (last === "session") {
    const prev = tokens[tokens.length - 2];
    return prev === undefined || /^(?:auth|user|login|access|app|supabase|jwt)$/.test(prev);
  }
  return false;
}
interface Chain {
  segments: string[];
  start: number;
  end: number;
}

function norm(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, "");
}

/** Identifier/member chains used as values in `[start, end)` (not calls, tests or keys). */
function valueChains(src: JsSource, start: number, end: number): Chain[] {
  const code = src.code;
  const out: Chain[] = [];
  const re = /(?<![\w$.])([A-Za-z_$][\w$]*)((?:\s*\??\.\s*[A-Za-z_$][\w$]*)*)/g;
  re.lastIndex = start;
  for (let m = re.exec(code); m !== null && m.index < end; m = re.exec(code)) {
    const s = m.index;
    const e = Math.min(s + m[0].length, end);
    const segments = [m[1]!, ...(m[2] ?? "").split(/\s*\??\.\s*/).filter((p) => p !== "")];
    let a = e;
    while (a < code.length && /\s/.test(code[a]!)) a++;
    const after = code.slice(a, a + 3);
    let b = s - 1;
    while (b >= 0 && /\s/.test(code[b]!)) b--;
    const before = code[b];
    if (after.startsWith("(")) continue; // a call: its result is something else
    if (/^(?:===?|!==?|<|>|\?(?![.?]))/.test(after)) continue; // compared or tested
    if (after.startsWith(":") && (before === "{" || before === ",")) continue; // object key
    if (before === "!") continue;
    if (/\btypeof\s*$|\bin\s*$|\binstanceof\s*$/.test(code.slice(Math.max(0, b - 11), b + 1)))
      continue;
    if (/^(?:typeof|new|await|void|in|of|instanceof|true|false|null|undefined)$/.test(m[1]!))
      continue;
    out.push({ segments, start: s, end: e });
  }
  return out;
}

export class BrowserStorageDetector implements Detector {
  id = "browser-storage-detector";
  name = "Secrets in Browser Storage and Console";
  category = "frontend_exposure" as const;
  description =
    "Detects tokens, API secrets and sessions written to localStorage/sessionStorage or printed with console.* in browser code.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of context.files) {
      try {
        const cf = await loadClientFile(context, file, { prefilter: (t) => PREFILTER.test(t) });
        if (cf === undefined) continue;
        findings.push(
          ...capPerFile(this.storageWrites(cf), MAX_PER_RULE_PER_FILE, (n, f) => summary(f, n)),
          ...capPerFile(this.consoleLogs(cf), MAX_PER_RULE_PER_FILE, (n, f) => summary(f, n)),
        );
      } catch {
        // never throw from a detector
      }
    }
    return findings;
  }

  // ---- frontend_exposure/secret-in-web-storage ----

  private storageWrites(cf: ClientFile): Finding[] {
    const { src } = cf;
    const code = src.code;
    const writes: { at: number; store: string; key: string | undefined; value: ArgRange }[] = [];
    SET_ITEM_RE.lastIndex = 0;
    for (let m = SET_ITEM_RE.exec(code); m !== null; m = SET_ITEM_RE.exec(code)) {
      const args = callArgs(src, m.index + m[0].length - 1);
      if (args.length < 2) continue;
      writes.push({
        at: m.index,
        store: m[1]!,
        key: this.keyText(cf, args[0]!, m.index),
        value: args[1]!,
      });
    }
    PROP_WRITE_RE.lastIndex = 0;
    for (let m = PROP_WRITE_RE.exec(code); m !== null; m = PROP_WRITE_RE.exec(code)) {
      const prop = m[2];
      if (prop === "setItem" || prop === "removeItem" || prop === "clear") continue;
      let key = prop;
      if (key === undefined) {
        const q = code.indexOf(m[3]!, m.index + m[1]!.length);
        key = q >= 0 ? literalText(src, q) : undefined;
      }
      let vs = m.index + m[0].length;
      while (vs < code.length && /[ \t]/.test(code[vs]!)) vs++;
      writes.push({
        at: m.index,
        store: m[1]!,
        key,
        value: { start: vs, end: expressionEnd(src, vs) },
      });
    }

    const out: Finding[] = [];
    const seen = new Set<number>();
    for (const w of writes) {
      if (out.length > MAX_PER_RULE_PER_FILE) break;
      if (inServerOnlyFunction(cf, w.at)) continue;
      const valueCode = code.slice(w.value.start, w.value.end);
      if (GENERATED_VALUE_RE.test(valueCode)) continue;
      const chains = valueChains(src, w.value.start, w.value.end);
      if (chains.length === 0) continue; // literal-only value (e.g. clearing with "")
      const k = w.key === undefined ? "" : norm(w.key);
      // A CSRF/XSRF token is meant to be readable by the page.
      if (/csrf|xsrf/.test(k) || chains.some((c) => /csrf|xsrf/i.test(c.segments.join("")))) continue;
      const keySecret =
        k !== "" && w.key !== undefined && isSecretKey(w.key) && !NOT_SECRET_KEY_RE.test(k);
      const valueSecret = chains.some((c) => isSecretValueName(c.segments[c.segments.length - 1]!));
      if (!keySecret && !valueSecret) continue;
      const line = src.lineAt(w.at);
      if (seen.has(line)) continue;
      seen.add(line);
      out.push(
        this.storageFinding(cf, w.at, w.store, keySecret && valueSecret ? "high" : "medium"),
      );
    }
    return out;
  }

  /** The storage key's text: a literal, a constant's literal value, or the expression's name. */
  private keyText(cf: ClientFile, arg: ArgRange, at: number): string | undefined {
    const { src } = cf;
    const lit = wholeLiteral(src, arg.start, arg.end);
    if (lit !== undefined) return lit;
    const raw = src.code.slice(arg.start, arg.end).trim();
    if (/^[A-Za-z_$][\w$]*$/.test(raw)) {
      const decl = findDeclaration(src, raw, at);
      if (decl !== undefined) {
        const v = wholeLiteral(src, decl.initStart, decl.initEnd);
        if (v !== undefined) return v;
      }
      return raw;
    }
    return src.text.slice(arg.start, arg.end);
  }

  private storageFinding(
    cf: ClientFile,
    at: number,
    store: string,
    confidence: Confidence,
  ): Finding {
    const { line, text } = lineOf(cf.src, at);
    return makeFinding({
      category: "frontend_exposure",
      ruleId: "frontend_exposure/secret-in-web-storage",
      title: `Secret or token saved in ${store}`,
      severity: "medium",
      confidence,
      file: cf.file,
      line,
      evidence: text,
      plainEnglishProblem: `This code stores a credential (token, API secret, session or password) in ${store}, where every script running on your site can read it.`,
      whyItMatters:
        "Web storage has no HttpOnly protection: a single XSS bug or a compromised npm package can read the value and reuse it from anywhere, and it stays on shared computers after logout.",
      fixSteps: [
        "Keep session tokens in HttpOnly, Secure, SameSite cookies set by the server instead of web storage.",
        "Show one-time secrets (such as new API keys) once and do not persist them in the browser.",
        "If a token must live in the browser, keep it in memory only and make it short-lived.",
      ],
      aiFixPrompt:
        "This browser code writes a credential (token, API secret, session or password) to localStorage or sessionStorage. Remove the web-storage write: keep session tokens in HttpOnly Secure SameSite cookies set by the server, keep one-time secrets only in component state until the user leaves the page, and update any code that read the value back from storage. Also clear any value already stored under that key.",
    });
  }

  // ---- frontend_exposure/sensitive-data-console-log ----

  private consoleLogs(cf: ClientFile): Finding[] {
    const { src } = cf;
    const code = src.code;
    const out: Finding[] = [];
    const seen = new Set<number>();
    CONSOLE_RE.lastIndex = 0;
    for (let m = CONSOLE_RE.exec(code); m !== null; m = CONSOLE_RE.exec(code)) {
      if (out.length > MAX_PER_RULE_PER_FILE) break;
      if (inServerOnlyFunction(cf, m.index)) continue;
      const open = m.index + m[0].length - 1;
      const close = src.matchOf(open);
      if (close < 0) continue;
      let best: { severity: Severity; confidence: Confidence; what: string } | undefined;
      for (const c of valueChains(src, open + 1, close)) {
        const verdict = this.classifyLogged(cf, c, m.index);
        if (verdict === undefined) continue;
        if (best === undefined || rank(verdict) > rank(best)) best = verdict;
      }
      if (best === undefined) continue;
      const line = src.lineAt(m.index);
      if (seen.has(line)) continue;
      seen.add(line);
      out.push(this.logFinding(cf, m.index, best));
    }
    return out;
  }

  private classifyLogged(
    cf: ClientFile,
    c: Chain,
    at: number,
  ): { severity: Severity; confidence: Confidence; what: string } | undefined {
    const lastRaw = c.segments[c.segments.length - 1]!;
    const last = norm(lastRaw);
    const authTied = (): boolean => {
      if (c.segments.slice(0, -1).some((s) => /auth|session/i.test(s))) return true;
      const decl = findDeclaration(cf.src, c.segments[0]!, at);
      return (
        decl !== undefined && AUTH_ORIGIN_RE.test(cf.src.code.slice(decl.initStart, decl.initEnd))
      );
    };
    if (LOG_HIGH_RE.test(last) && !BOOLEAN_NAME_RE.test(lastRaw)) {
      const what = /session/.test(last) ? "a session object" : "a token or secret";
      return { severity: "high", confidence: authTied() ? "high" : "medium", what };
    }
    if (LOG_USER_RE.test(last) && authTied()) {
      return { severity: "high", confidence: "medium", what: "the signed-in user object" };
    }
    if (LOG_PII_RE.test(last)) {
      return { severity: "medium", confidence: "low", what: "payment or identity data" };
    }
    return undefined;
  }

  private logFinding(
    cf: ClientFile,
    at: number,
    v: { severity: Severity; confidence: Confidence; what: string },
  ): Finding {
    const { line, text } = lineOf(cf.src, at);
    return makeFinding({
      category: "frontend_exposure",
      ruleId: "frontend_exposure/sensitive-data-console-log",
      title: "Sensitive data printed to the browser console",
      severity: v.severity,
      confidence: v.confidence,
      file: cf.file,
      line,
      evidence: text,
      plainEnglishProblem: `This console call prints ${v.what} in the browser. Access and refresh tokens inside it end up in the console and in any tool that captures it.`,
      whyItMatters:
        "Session replay, error trackers, browser extensions and screen shares all capture console output; a leaked access or refresh token lets someone act as the user until it expires.",
      fixSteps: [
        "Remove the console call, or log only non-sensitive fields such as the user id.",
        "Never log whole session, token or user objects in browser code.",
        "If you need debug logging, guard it so it is stripped from production builds.",
      ],
      aiFixPrompt:
        "This browser code passes a session, token, secret or signed-in user object to console.log (or another console method). Remove that console call, or replace the argument with a non-sensitive field such as the user id. Do not log access tokens, refresh tokens, API keys, passwords or whole session/user objects anywhere in client code.",
    });
  }
}

function rank(v: { severity: Severity; confidence: Confidence }): number {
  const s = v.severity === "high" ? 2 : v.severity === "medium" ? 1 : 0;
  const c = v.confidence === "high" ? 2 : v.confidence === "medium" ? 1 : 0;
  return s * 3 + c;
}

function summary(first: Finding, dropped: number): Finding {
  return makeFinding({
    category: "frontend_exposure",
    ruleId: first.ruleId,
    title: `${dropped} more occurrence(s) of this issue in the file`,
    severity: first.severity,
    confidence: "medium",
    file: first.file,
    discriminator: `summary:${dropped}`,
    plainEnglishProblem: `${first.plainEnglishProblem} The same pattern appears ${dropped} more time(s) in this file.`,
    whyItMatters: first.whyItMatters,
    fixSteps: first.fixSteps,
    aiFixPrompt: first.aiFixPrompt ?? "",
  });
}
