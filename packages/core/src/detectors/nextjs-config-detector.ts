import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { classifyPath, isTestOrFixturePath } from "./utils/file-kind.js";
import { makeFinding } from "./utils/finding.js";
import { stripComments } from "./utils/strip-comments.js";

const SOURCE_MAPS_RE = /\bproductionBrowserSourceMaps\s*:\s*true\b/g;
/** `hostname: "**"` / `"*"` (any host), not `"**.example.com"`. */
const WILDCARD_HOST_RE = /\bhostname\s*:\s*(["'`])\*{1,2}\1/g;
/** `new URL("https://**")` / `"https://**\/**"` remote patterns (Next.js 15). */
const WILDCARD_URL_RE = /\bnew\s+URL\(\s*(["'`])https?:\/\/\*{1,2}(?:[/:][^"'`]*)?\1/g;
/** `domains: ["*"]` style lists. */
const WILDCARD_DOMAINS_RE = /\bdomains\s*:\s*\[[^\]]*?(["'`])\*{1,2}\1/g;
const IGNORE_BUILD_ERRORS_RE = /\bignoreBuildErrors\s*:\s*true\b/g;

interface Hit {
  line: number;
}

/**
 * Matches `re` on `code` (comments blanked, strings kept) and keeps only matches whose
 * leading keyword is real code, i.e. still present in `bare` (strings blanked too).
 */
function hits(code: string, bare: string, re: RegExp): Hit[] {
  const out: Hit[] = [];
  for (const m of code.matchAll(re)) {
    const keyword = /^[A-Za-z]+/.exec(m[0])?.[0] ?? "";
    if (keyword === "" || !bare.startsWith(keyword, m.index)) continue;
    out.push({ line: code.slice(0, m.index).split("\n").length });
  }
  return out;
}

/**
 * next.config rules: public browser source maps in production, `next/image`
 * remote patterns that allow any host, and builds that ignore TypeScript errors.
 */
export class NextjsConfigDetector implements Detector {
  id = "nextjs-config-detector";
  name = "Next.js Config Security";
  category = "security_config" as const;
  description =
    "Detects productionBrowserSourceMaps, next/image remote patterns that allow any host, and ignoreBuildErrors in next.config.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (classifyPath(file) !== "next-config") continue;
      if (isTestOrFixturePath(file) && context.config.includeTests !== true) continue;
      try {
        const text = await context.readFile(file);
        if (
          !text.includes("productionBrowserSourceMaps") &&
          !text.includes("*") &&
          !text.includes("ignoreBuildErrors")
        )
          continue;
        const code = stripComments(text);
        const bare = stripComments(text, { blankStrings: true });
        const lines = text.split("\n");
        const evidence = (line: number): string => lines[line - 1] ?? "";

        for (const h of hits(code, bare, SOURCE_MAPS_RE)) {
          findings.push(
            makeFinding({
              category: "security_config",
              ruleId: "security_config/nextjs-browser-source-maps",
              title: "Browser source maps are published in production",
              severity: "medium",
              confidence: "high",
              file,
              line: h.line,
              evidence: evidence(h.line),
              plainEnglishProblem:
                "`productionBrowserSourceMaps: true` makes Next.js publish full source maps for the client bundles, so anyone can download your original, unminified front-end source code.",
              whyItMatters:
                "Readable source makes it much easier to find hidden endpoints, client-side checks to bypass and any keys or internal URLs bundled into the client.",
              fixSteps: [
                "Remove `productionBrowserSourceMaps` (it defaults to false) or set it to false.",
                "If you need source maps for error tracking, upload them privately to your error tracker (e.g. Sentry) during the build and do not serve them.",
              ],
              aiFixPrompt:
                "My next.config enables productionBrowserSourceMaps, which publishes the original client source code. Disable it, and if I use an error tracker, show me how to upload source maps privately at build time and delete them from the build output so they are never served.",
            }),
          );
        }

        const wildcard = [
          ...hits(code, bare, WILDCARD_HOST_RE),
          ...hits(code, bare, WILDCARD_URL_RE),
          ...hits(code, bare, WILDCARD_DOMAINS_RE),
        ];
        const seen = new Set<number>();
        for (const h of wildcard) {
          if (seen.has(h.line)) continue;
          seen.add(h.line);
          findings.push(
            makeFinding({
              category: "security_config",
              ruleId: "security_config/nextjs-image-wildcard-host",
              title: "next/image allows images from any host",
              severity: "medium",
              confidence: "high",
              file,
              line: h.line,
              evidence: evidence(h.line),
              plainEnglishProblem:
                "The `images` config allows any hostname, so the `/_next/image` optimizer will fetch, resize and serve images from any URL an attacker passes to it.",
              whyItMatters:
                "Your server becomes an open image proxy: attackers can burn your bandwidth and image-optimization bill, hide abusive content behind your domain, and make your server request hosts of their choosing.",
              fixSteps: [
                "List the exact hosts you serve images from in `images.remotePatterns` (for example your storage bucket or CDN domain), optionally with a `pathname` prefix.",
                "For user-supplied image URLs, upload them to your own storage first, or render them with `unoptimized` so they never go through the optimizer.",
              ],
              aiFixPrompt:
                "My next.config allows next/image to load images from any hostname ('**'). Replace the wildcard with explicit remotePatterns for the hosts my app actually loads images from (protocol, hostname and pathname), and for images whose URLs users control, suggest storing them in my own bucket or rendering them unoptimized.",
            }),
          );
        }

        for (const h of hits(code, bare, IGNORE_BUILD_ERRORS_RE)) {
          findings.push(
            makeFinding({
              category: "security_config",
              ruleId: "security_config/nextjs-ignore-build-errors",
              title: "Production builds ignore TypeScript errors",
              severity: "low",
              confidence: "high",
              file,
              line: h.line,
              evidence: evidence(h.line),
              plainEnglishProblem:
                "`typescript.ignoreBuildErrors: true` lets `next build` succeed even when the code has type errors.",
              whyItMatters:
                "Type errors often hide real bugs, such as a missing auth check result being used as a boolean or an undefined user id, and they reach production without anyone noticing.",
              fixSteps: [
                "Remove `ignoreBuildErrors` and fix the reported type errors.",
                "Run `tsc --noEmit` in CI so type errors block merges.",
              ],
              aiFixPrompt:
                "My next.config sets typescript.ignoreBuildErrors to true. Remove it, run the type checker, and fix the type errors it reports without using `any` or ts-ignore comments to silence them.",
            }),
          );
        }
      } catch {
        // Never throw from a detector.
      }
    }
    return findings;
  }
}
