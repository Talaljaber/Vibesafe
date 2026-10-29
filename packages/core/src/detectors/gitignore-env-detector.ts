// .gitignore ignores `.env` but not the variants frameworks load (`.env.local`,
// `.env.production.local`, ...). Anchors on the .gitignore line that causes it, which is
// the root cause of `secret/env-not-ignored` reported on the env file itself.

import path from "node:path";
import ignore from "ignore";
import {
  classifyEnvFileName,
  type Detector,
  type Finding,
  type ScanContext,
} from "@talaljaber/vibesafe-shared";
import { makeFinding } from "./utils/finding.js";

const PROBES = [".env.local", ".env.development.local", ".env.production.local", ".env.test.local"];
const FRAMEWORKS = [
  "next",
  "vite",
  "react-scripts",
  "nuxt",
  "@sveltejs/kit",
  "astro",
  "expo",
  "@remix-run/dev",
  "dotenv-flow",
  "@next/env",
];

const AI_FIX_PROMPT =
  "My .gitignore ignores `.env` but not `.env.local`, `.env.production.local` and similar " +
  "variants that my framework loads and that usually hold the real keys. Update .gitignore to " +
  "ignore `.env*` (or `.env.*` followed by `!.env.example` so the template stays tracked). Then " +
  "check `git ls-files` for any committed env variant, remove it from the index with " +
  "`git rm --cached`, and tell me which keys I must rotate because they were pushed.";

const normalize = (f: string): string => f.replace(/\\/g, "/");

export class GitignoreEnvDetector implements Detector {
  id = "gitignore-env-detector";
  name = "Gitignore Env Variants";
  category = "security_config" as const;
  description =
    ".gitignore ignores .env but not .env.local or .env.*.local, which frameworks load and which usually hold real keys.";

  async detect(context: ScanContext): Promise<Finding[]> {
    try {
      if (!context.files.some((f) => normalize(f) === ".gitignore")) return [];
      const content = await context.readFile(".gitignore");
      if (!content.trim()) return [];
      const lines = content.split(/\r?\n/);

      let anchor = -1;
      for (let i = 0; i < lines.length; i++) {
        const l = (lines[i] ?? "").trim();
        if (!l || l.startsWith("#") || l.startsWith("!")) continue;
        if (ignore().add(l).ignores(".env")) {
          anchor = i;
          break;
        }
      }
      if (anchor < 0) return [];

      const full = ignore().add(content);
      if (PROBES.every((p) => full.ignores(p))) return [];

      const variantPresent = context.files.some((f) => {
        const p = normalize(f);
        const base = path.posix.basename(p);
        return classifyEnvFileName(base) === "env" && base !== ".env" && !full.ignores(p);
      });
      const deps = {
        ...(context.projectContext?.dependencies ?? {}),
        ...(context.projectContext?.devDependencies ?? {}),
      };
      const frameworkLoadsVariants = FRAMEWORKS.some((d) => d in deps);
      // An unignored variant file already gets secret/env-not-ignored (critical); reporting the
      // same cause on .gitignore too would double-count it.
      if (variantPresent || !frameworkLoadsVariants) return [];

      return [
        makeFinding({
          category: "security_config",
          ruleId: "security_config/gitignore-env-variants",
          title: ".gitignore ignores .env but not .env.local and other variants",
          severity: "medium",
          confidence: "high",
          file: ".gitignore",
          line: anchor + 1,
          evidence: lines[anchor] ?? "",
          discriminator: "framework",
          autoFixAvailable: true,
          plainEnglishProblem:
            "`.gitignore` ignores `.env` but not `.env.local` / `.env.*.local`, which Next.js/Vite load and which usually hold the real keys.",
          whyItMatters:
            "Frameworks read the variant files first, so real API keys end up there, and nothing stops them from being committed and pushed.",
          fixSteps: [
            "Add `.env*` to .gitignore (or `.env.*` followed by `!.env.example` to keep the template tracked).",
            "Run `git rm --cached` on any env variant that is already committed.",
            "Rotate every key that was pushed to a remote.",
          ],
          aiFixPrompt: AI_FIX_PROMPT,
        }),
      ];
    } catch {
      return [];
    }
  }
}
