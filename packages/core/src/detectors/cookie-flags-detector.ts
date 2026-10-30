import type { Confidence, Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { makeFinding } from "./utils/finding.js";
import {
  classifyFile,
  isGenerated,
  isJsLike,
  isServerScope,
  isTestOrFixturePath,
} from "./utils/file-kind.js";
import { getJsSource } from "./utils/js-source.js";
import { callKey, capPerRule } from "./utils/sinks.js";
import { findCookieSites, type CookieSite } from "./utils/cookie-options.js";

const LEARN_MORE = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security";

type Rule = "no-httponly" | "samesite-none" | "not-secure";

interface Decision {
  rule: Rule;
  confidence: Confidence;
}

function decide(site: CookieSite): Decision | undefined {
  const { flags, defaultsOff } = site;
  if (flags.httpOnly === "false") return { rule: "no-httponly", confidence: "high" };
  if (flags.httpOnly === "missing" && defaultsOff)
    return { rule: "no-httponly", confidence: "medium" };
  if (flags.sameSite === "none") return { rule: "samesite-none", confidence: "medium" };
  if (flags.secure === "false") return { rule: "not-secure", confidence: "high" };
  if (flags.secure === "missing" && defaultsOff)
    return { rule: "not-secure", confidence: "medium" };
  return undefined;
}

/** Every weak flag of the call, for the problem text. */
function weakFlags(site: CookieSite): string[] {
  const { flags, defaultsOff } = site;
  const out: string[] = [];
  if (flags.httpOnly === "false" || (flags.httpOnly === "missing" && defaultsOff))
    out.push("no HttpOnly");
  if (flags.sameSite === "none") out.push("SameSite=None");
  if (flags.secure === "false" || (flags.secure === "missing" && defaultsOff))
    out.push("no Secure");
  return out;
}

function safeName(name: string): string {
  const cleaned = name.replace(/[^\w.$ -]/g, "").trim();
  return cleaned === "" ? "session" : cleaned.slice(0, 40);
}

/**
 * Session and auth cookies set without `HttpOnly` or `Secure`, or with `SameSite=None`
 * (Express `res.cookie`, `cookies().set`, `NextResponse.cookies.set`, Koa, `cookie.serialize`,
 * literal `Set-Cookie` headers, express-session, cookie-session, iron-session). Theme, locale,
 * CSRF, consent and one-purpose flow cookies, deletions, `__Host-` cookies and options that
 * cannot be resolved statically are not reported.
 */
export class CookieFlagsDetector implements Detector {
  id = "cookie-flags-detector";
  name = "Session Cookie Flags";
  category = "security_config" as const;
  description =
    "Detects session and auth cookies set without HttpOnly or Secure, or with SameSite=None.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (!isJsLike(file)) continue;
      if (context.config.includeTests !== true && isTestOrFixturePath(file)) continue;
      if (isGenerated(file)) continue;
      try {
        const src = await getJsSource(context, file);
        if (!src.text.includes("ookie") && !src.text.includes("express-session")) continue;
        if (isGenerated(file, src.text)) continue;
        if (!isServerScope(classifyFile(file, src.text, context.projectContext))) continue;
        findings.push(...capPerRule(this.scanFile(file, src)));
      } catch {
        // a detector never throws
      }
    }
    return findings;
  }

  private scanFile(file: string, src: Parameters<typeof findCookieSites>[0]): Finding[] {
    const out: Finding[] = [];
    for (const site of findCookieSites(src)) {
      try {
        if (!site.session || site.deletes) continue;
        if (/^__(?:Host|Secure)-/.test(site.name)) site.flags.secure = "true";
        const d = decide(site);
        if (d === undefined) continue;
        const line = src.lineAt(site.start);
        const endLine = src.lineAt(site.end);
        out.push(
          this.build(
            d,
            file,
            line,
            endLine > line ? endLine : undefined,
            src.lineText(line).trim(),
            callKey(src, site.start, site.kind),
            safeName(site.name),
            weakFlags(site),
          ),
        );
      } catch {
        // skip the call
      }
    }
    return out;
  }

  private build(
    d: Decision,
    file: string,
    line: number,
    endLine: number | undefined,
    evidence: string,
    discriminator: string,
    name: string,
    weak: string[],
  ): Finding {
    const weakText = weak.join(", ");
    const base = {
      category: "security_config" as const,
      file,
      line,
      endLine,
      evidence,
      discriminator,
    };
    if (d.rule === "no-httponly") {
      return makeFinding({
        ...base,
        ruleId: "security_config/session-cookie-no-httponly",
        title: "Session cookie readable by JavaScript (no HttpOnly)",
        severity: "medium",
        confidence: d.confidence,
        plainEnglishProblem: `The \`${name}\` cookie holds a session/auth token but is set without \`httpOnly: true\` (${weakText}), so any script on the page (including injected XSS) can read it with \`document.cookie\` and send it to an attacker.`,
        whyItMatters:
          "A stolen session cookie lets the attacker act as the user until it expires; HttpOnly is the standard defence and costs nothing.",
        fixSteps: [
          "Add `httpOnly: true` to the cookie options.",
          'Also set `secure: true` (or `process.env.NODE_ENV === "production"`) and `sameSite: "lax"`.',
          "Keep the options in one shared constant so every place that sets the session cookie uses them.",
        ],
        aiFixPrompt:
          "This code sets a session or auth cookie without HttpOnly. Add httpOnly: true, secure: true (or secure: process.env.NODE_ENV === 'production'), and sameSite: 'lax' to the options, keep them in one shared options constant used everywhere the session cookie is set, and do not change the cookie name or value.",
        learnMoreUrl: LEARN_MORE,
      });
    }
    if (d.rule === "samesite-none") {
      return makeFinding({
        ...base,
        ruleId: "security_config/session-cookie-samesite-none",
        title: "Session cookie sent on cross-site requests (SameSite=None)",
        severity: "medium",
        confidence: d.confidence,
        plainEnglishProblem: `The \`${name}\` session/auth cookie is set with \`sameSite: "none"\` (${weakText}), so browsers attach it to requests from any site, which enables CSRF. Chromium-based browsers reject a SameSite=None cookie unless \`secure: true\` is set.`,
        whyItMatters:
          "Another site can make a logged-in visitor's browser send authenticated requests to your app without them noticing.",
        fixSteps: [
          'Use `sameSite: "lax"` (or `"strict"`) for session cookies.',
          "Keep `none` only for a real cross-site embed, with `secure: true` and CSRF tokens on every state-changing route.",
        ],
        aiFixPrompt:
          "This code sets a session or auth cookie with sameSite: 'none'. Change it to sameSite: 'lax' (or 'strict') unless the app is intentionally embedded cross-site; if it must stay 'none', also set secure: true and add CSRF token protection to every state-changing route. Keep httpOnly: true.",
        learnMoreUrl: LEARN_MORE,
      });
    }
    return makeFinding({
      ...base,
      ruleId: "security_config/session-cookie-not-secure",
      title: "Session cookie can travel over plain HTTP (no Secure)",
      severity: "low",
      confidence: d.confidence,
      plainEnglishProblem: `The \`${name}\` session/auth cookie is set without \`secure: true\` (${weakText}), so the browser may send it over plain \`http://\` where anyone on the network can read it.`,
      whyItMatters:
        "A session cookie sent in clear text can be copied from public Wi-Fi or a compromised router and replayed to take over the account.",
      fixSteps: [
        'Set `secure: true` in production, for example `secure: process.env.NODE_ENV === "production"`.',
        "Serve the site over HTTPS only and send an HSTS header.",
      ],
      aiFixPrompt:
        "This code sets a session or auth cookie without the Secure flag. Add secure: process.env.NODE_ENV === 'production' (or true) to the cookie options, keep httpOnly: true and sameSite: 'lax', and make sure the app is served over HTTPS with an HSTS header. Do not change the cookie name or value.",
      learnMoreUrl: LEARN_MORE,
    });
  }
}
