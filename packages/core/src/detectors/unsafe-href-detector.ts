import type { Detector, Finding, ScanContext, Severity } from "@talaljaber/vibesafe-shared";
import {
  callArgs,
  capPerFile,
  clientTaint,
  findDeclaration,
  inServerOnlyFunction,
  leadingOperands,
  lineOf,
  loadClientFile,
  memberChain,
  outermostSpan,
  reactMajor,
  type ArgRange,
  type ClientFile,
} from "./utils/client-source.js";
import { makeFinding } from "./utils/finding.js";
import { enclosingFunction } from "./utils/js-functions.js";
import { taintConfidence } from "./utils/taint.js";
import type { Confidence } from "@talaljaber/vibesafe-shared";

/**
 * `xss/javascript-url-href`: a link or frame URL whose scheme the user controls.
 *
 * Fires on JSX `href={...}` (any element, including `<Link>`), `<iframe|frame|embed src>`,
 * `<object data>`, `<form action>` / `formAction`, and `window.open(...)`, when the start
 * of the value is either
 * - tainted by the page URL (`CLIENT_SOURCES`, client files only), or
 * - a profile-like field (`website`, `homepage`, `blog`, `portfolio`, or `url`/`link`
 *   on a user/store/org-like object) that comes from data rather than a local literal,
 * and no `^https?:` / `startsWith("http")` / `.protocol` / safe-URL helper check is
 * applied to it. `javascript:` URLs run script when clicked.
 *
 * Severity follows React: below 19 React renders `javascript:` URLs (medium); React 19
 * blocks them (low). JSX in App Router server components is scanned too: the markup
 * runs in the browser whatever runtime renders it, and no server-side rule owns hrefs.
 */

const MAX_PER_FILE = 25;
const ATTR_RE = /(?<![\w$-])(href|src|data|action|formAction)\s*=\s*\{/g;
const WINDOW_OPEN_RE = /\bwindow\s*\.\s*open\s*\(/g;
const PREFILTER = /\b(?:href|src|data|action|formAction)\s*=\s*\{|\bwindow\s*\.\s*open\s*\(/;

/** Field names that hold a user-supplied link (normalized: lower case, no `_`/`-`). */
const PROFILE_FIELD_RE =
  /^(?:website|homepage|homepageurl|blog|blogurl|portfolio|portfoliourl|personalsite|personalwebsite|personalurl|profileurl|socialurl|websiteurl|siteurl|companywebsite|companyurl|externalurl|externallink)$/;
/** Generic link fields count only on objects that look like user-owned records. */
const GENERIC_LINK_FIELD_RE = /^(?:url|link|href)$/;
const USER_RECORD_RE =
  /user|profile|author|member|owner|creator|customer|account|store|shop|org|organi[sz]ation|company|merchant|seller|vendor|team|tenant|listing|post|comment|review|contact|applicant|candidate/i;
const SCHEME_CHECK_RE =
  /\^https\?|\^\(\?:https?|startsWith\s*\(\s*["'`]https?|\.protocol\b|(?:sanitize|safe|valid|isSafe|isValid|isHttp|isExternal|normalize|clean)\w*(?:Url|Href|Link)\s*\(/i;

const ELEMENT_ATTRS: Readonly<Record<string, RegExp>> = {
  href: /^[\w$.]+$/,
  src: /^(?:iframe|frame|embed)$/i,
  data: /^object$/i,
  action: /^form$/i,
  formAction: /^(?:button|input)$/i,
};

export class UnsafeHrefDetector implements Detector {
  id = "unsafe-href-detector";
  name = "javascript: URL in Links";
  category = "xss" as const;
  description =
    "Detects links, frames and window.open calls whose URL comes from the page URL or a user-editable profile field without an http(s) scheme check.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const major = reactMajor(context.projectContext);
    const severity: Severity = major !== undefined && major < 19 ? "medium" : "low";
    for (const file of context.files) {
      try {
        const cf = await loadClientFile(context, file, {
          prefilter: (t) => PREFILTER.test(t),
          allowServerComponents: true,
        });
        if (cf === undefined) continue;
        const own = this.scan(cf, severity);
        findings.push(...capPerFile(own, MAX_PER_FILE, (n, f) => summary(f, n)));
      } catch {
        // never throw from a detector
      }
    }
    return findings;
  }

  private scan(cf: ClientFile, severity: Severity): Finding[] {
    const { src } = cf;
    const code = src.code;
    const sinks: { at: number; range: ArgRange; label: string }[] = [];
    if (src.jsx) {
      ATTR_RE.lastIndex = 0;
      for (let m = ATTR_RE.exec(code); m !== null; m = ATTR_RE.exec(code)) {
        const attr = m[1]!;
        const tag = elementAt(cf, m.index);
        if (tag === undefined || !ELEMENT_ATTRS[attr]!.test(tag)) continue;
        const open = m.index + m[0].length - 1;
        const close = src.matchOf(open);
        if (close < 0) continue;
        sinks.push({
          at: m.index,
          range: { start: open + 1, end: close },
          label: `${attr} of <${tag}>`,
        });
      }
    }
    if (cf.classification.runtime === "client") {
      WINDOW_OPEN_RE.lastIndex = 0;
      for (let m = WINDOW_OPEN_RE.exec(code); m !== null; m = WINDOW_OPEN_RE.exec(code)) {
        const first = callArgs(src, m.index + m[0].length - 1)[0];
        if (first !== undefined) sinks.push({ at: m.index, range: first, label: "window.open" });
      }
    }

    const out: Finding[] = [];
    const seenLines = new Set<number>();
    for (const sink of sinks) {
      if (inServerOnlyFunction(cf, sink.at)) continue;
      const line = src.lineAt(sink.at);
      if (seenLines.has(line)) continue;
      const verdict = this.judge(cf, sink);
      if (verdict === undefined) continue;
      seenLines.add(line);
      out.push(this.finding(cf, sink.at, sink.label, verdict, severity));
    }
    return out;
  }

  private judge(
    cf: ClientFile,
    sink: { at: number; range: ArgRange; label: string },
  ): { reason: string; confidence: Confidence } | undefined {
    const { src } = cf;
    const isOpen = sink.label === "window.open";
    for (const lead of leadingOperands(src, sink.range.start, sink.range.end)) {
      // Page-URL taint (client files). window.open fed by a redirect parameter is reported
      // as an open redirect by the client code rule; here only taint into links/frames.
      if (cf.classification.runtime === "client" && !isOpen) {
        const hit = clientTaint(cf, lead.start, lead.end);
        if (hit !== undefined && hit.source.id !== "message-data") {
          if (!this.schemeChecked(cf, lead, hit.via, sink.at)) {
            return { reason: hit.source.label, confidence: taintConfidence(hit) };
          }
          continue;
        }
      }
      const field = this.profileField(cf, lead, sink.at);
      if (field !== undefined && !this.schemeChecked(cf, lead, field, sink.at)) {
        return { reason: `the profile-style field "${field}"`, confidence: "low" };
      }
    }
    return undefined;
  }

  /** The user-editable link field the value reads, if any (see the module comment). */
  private profileField(cf: ClientFile, lead: ArgRange, at: number): string | undefined {
    const { src } = cf;
    const chain = memberChain(src.code, lead.start, lead.end);
    if (chain === undefined) return undefined;
    const last = chain[chain.length - 1]!;
    const norm = last.toLowerCase().replace(/[_-]/g, "");
    const root = chain[0]!;
    if (chain.length === 1) {
      if (!PROFILE_FIELD_RE.test(norm)) return undefined;
    } else if (!PROFILE_FIELD_RE.test(norm)) {
      if (!GENERIC_LINK_FIELD_RE.test(norm)) return undefined;
      const owner = chain[chain.length - 2]!;
      if (!USER_RECORD_RE.test(owner) && !(chain.length === 2 && USER_RECORD_RE.test(root)))
        return undefined;
    }
    if (/^[A-Z][A-Z0-9_]*$/.test(root)) return undefined; // constant config
    if (this.isLocalLiteral(cf, root, at)) return undefined;
    return last;
  }

  /** `root` is declared from a string/object/array literal, or maps over a literal array. */
  private isLocalLiteral(cf: ClientFile, root: string, at: number): boolean {
    const { src } = cf;
    const decl = findDeclaration(src, root, at);
    if (decl !== undefined) {
      const c = src.code[decl.initStart];
      if (c === "{" || c === "[" || c === '"' || c === "'" || c === "`") return true;
      return false;
    }
    // Callback parameter of `<receiver>.map(...)`: literal when the receiver is.
    const fn = enclosingFunction(cf.spans, at);
    for (let s = fn; s !== undefined; s = s.parent) {
      if (!s.params.some((p) => p.names.includes(root))) continue;
      const head = src.code.slice(Math.max(0, s.start - 200), s.start);
      const m = /([A-Za-z_$][\w$]*)\s*(?:\?\.|\.)\s*(?:map|flatMap|forEach|filter)\s*\(\s*$/.exec(
        head,
      );
      if (m === null) return false;
      const recv = m[1]!;
      if (/^[A-Z][A-Z0-9_]*$/.test(recv)) return true;
      return this.isLocalLiteral(cf, recv, s.start);
    }
    return false;
  }

  private schemeChecked(
    cf: ClientFile,
    lead: ArgRange,
    name: string | undefined,
    at: number,
  ): boolean {
    const { src } = cf;
    if (SCHEME_CHECK_RE.test(src.text.slice(lead.start, lead.end))) return true;
    if (name === undefined) return false;
    const outer = outermostSpan(cf, at);
    const esc = name.replace(/\$/g, "\\$");
    const nameRe = new RegExp(String.raw`(?<![\w$])${esc}(?![\w$])`);
    const startLine = src.lineAt(outer.start);
    const endLine = src.lineAt(Math.max(outer.start, outer.end - 1));
    for (let l = startLine; l <= endLine; l++) {
      const t = src.lineText(l);
      if (SCHEME_CHECK_RE.test(t) && nameRe.test(t)) return true;
    }
    return false;
  }

  private finding(
    cf: ClientFile,
    at: number,
    label: string,
    verdict: { reason: string; confidence: Confidence },
    severity: Severity,
  ): Finding {
    const { line, text } = lineOf(cf.src, at);
    return makeFinding({
      category: "xss",
      ruleId: "xss/javascript-url-href",
      title: "Link URL can be a javascript: URL",
      severity,
      confidence: verdict.confidence,
      file: cf.file,
      line,
      evidence: text,
      plainEnglishProblem: `The ${label} URL comes from ${verdict.reason} and nothing checks that it starts with http:// or https://. A value like javascript:alert(document.cookie) runs script when someone clicks it.`,
      whyItMatters:
        "Anyone who can set that value (a link they send, or a profile/store field they edit) gets cross-site scripting against every visitor who clicks, including logged-in admins.",
      fixSteps: [
        "Allow only http: and https: URLs (or relative paths starting with a single /) before rendering the link.",
        "Parse with new URL(value) and check url.protocol is 'http:' or 'https:'; render plain text otherwise.",
        "Validate the scheme where the value is saved as well, not only where it is shown.",
      ],
      aiFixPrompt:
        "A link (href, iframe src, form action or window.open) in this React code uses a URL from user-controlled data without checking its scheme, so a javascript: URL would run script. Add a small helper safeHref(value) that returns the value only when new URL(value, window.location.origin).protocol is 'http:' or 'https:' (or the value is a relative path starting with a single '/'), and otherwise returns undefined; use it for this attribute and skip rendering the link when it returns undefined. Also validate the scheme when the value is saved.",
    });
  }
}

/** Tag name of the JSX element whose attribute list contains `at`, or undefined. */
function elementAt(cf: ClientFile, at: number): string | undefined {
  const { src } = cf;
  const code = src.code;
  const limit = Math.max(0, at - 4000);
  for (let i = at - 1; i >= limit; i--) {
    const c = code[i]!;
    if (c === "}" || c === ")" || c === "]") {
      const m = src.matchOf(i);
      if (m < 0) return undefined;
      i = m;
      continue;
    }
    if (c === ">" || c === ";") return undefined;
    if (c === "<") {
      const m = /^<\s*([A-Za-z][\w$.:-]*)/.exec(code.slice(i, i + 80));
      return m?.[1];
    }
  }
  return undefined;
}

function summary(first: Finding, dropped: number): Finding {
  return makeFinding({
    category: "xss",
    ruleId: "xss/javascript-url-href",
    title: `${dropped} more link(s) with an unchecked URL in this file`,
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
