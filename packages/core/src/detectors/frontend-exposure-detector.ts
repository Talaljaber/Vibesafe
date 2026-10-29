import path from "node:path";
import { type Detector, type Finding, type ScanContext } from "@talaljaber/vibesafe-shared";
import { CATEGORY_PREFIX, classifyEnvFileName, createFindingId } from "@talaljaber/vibesafe-shared";
import { isServerOnlyPublicName } from "./patterns/public-env-names.js";
import { sanitizeEvidence } from "./utils/sanitize-evidence.js";
import {
  hasUseServerDirective,
  isClientFile,
  isViteConfigFile,
  usesServerSideDataFetching,
} from "./utils/file-classifier.js";

const CODE_EXTENSIONS = [".ts", ".tsx", ".js", ".jsx"];
const PUBLIC_PREFIXES = [
  "NEXT_PUBLIC_",
  "VITE_",
  "REACT_APP_",
  "EXPO_PUBLIC_",
  "NUXT_PUBLIC_",
  "PUBLIC_",
];

/** A public-prefixed variable whose name looks like a secret (not preceded by another name char). */
const PUBLIC_SECRET_REGEX =
  /(?<![A-Z0-9_])(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|PUBLIC)_[A-Z0-9_]*(?:SECRET|PRIVATE|PASSWORD|SERVICE_ROLE)[A-Z0-9_]*/i;

/** Any public-prefixed identifier on a line (checked with isServerOnlyPublicName). */
const PUBLIC_NAME_TOKEN =
  /(?<![A-Za-z0-9_])(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|PUBLIC)_[A-Za-z0-9_]+/g;

/**
 * Inside a vite.config `define` block: `"process.env": process.env` (optionally wrapped in
 * JSON.stringify, or followed by a TS cast such as `as any`), or a spread of process.env.
 * Member access (`process.env.FOO`, `process.env["FOO"]`) is safe and not matched.
 */
const VITE_DEFINE_LEAK_REGEX =
  /\.\.\.\s*process\.env(?![\w$.[(?])|["'`]?process\.env["'`]?\s*:\s*(?:JSON\.stringify\(\s*)?process\.env(?![\w$.[(?])/;

/** `const env = process.env` or `const env = loadEnv(mode, cwd, "")` (empty prefix leaks every variable). */
const ENV_ALIAS_REGEX =
  /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:process\.env(?![\w$.[(?])|loadEnv\((?:[^()]|\([^()]*\))*,\s*(?:""|'')\s*\))/g;

const SERVER_ENV_REGEX =
  /process\.env(?:\.([A-Za-z_][A-Za-z0-9_]*)|\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\])/g;
const SECRET_LOOKING_NAME = /SERVICE_ROLE|SECRET|PRIVATE|PASSWORD|TOKEN|API_KEY|APIKEY/i;
const SERVICE_ROLE_REGEX = /SERVICE_ROLE_KEY|service_role/;
/** firebase-admin (or a subpath) pulled in via import/require/dynamic import; `import type` is erased at build time. */
const FIREBASE_ADMIN_REGEX =
  /(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(?\s*)["']firebase-admin(?:\/[^"']*)?["']/;
/** Whole-statement type-only imports/exports (multi-line and all-`type` specifier lists); erased at build time. */
const TYPE_ONLY_IMPORT_REGEX =
  /\b(?:import|export)\s+type\b[^;"']*?\bfrom\s*["'][^"']+["']|\bimport\s*\{\s*(?:type\s+[\w$]+(?:\s+as\s+[\w$]+)?\s*,?\s*)+\}\s*from\s*["'][^"']+["']/g;
/** Service account key files: firebase-adminsdk-*.json, serviceAccount.json, serviceAccountKey.json, ...Credentials.json. */
const SERVICE_ACCOUNT_JSON_REGEX =
  /(?:firebase[-_.]?adminsdk[^"'/\\]*|service[-_.]?account[^"'/\\]*?(?:key|credentials?)|service[-_.]?account)\.json$/i;
const REQUIRE_REGEX = /\b(?:require|import)\s*\(\s*["']([^"']+)["']\s*\)/g;
const IMPORT_REGEX =
  /(?:import|export)\s[^"';]*?from\s*["']([^"']+)["']|import\s*["']([^"']+)["']/g;

/** Removes block and line comments, keeping line structure so line numbers stay valid. */
function stripComments(content: string): string[] {
  const noBlock = content.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "));
  return noBlock.split("\n").map((l) => {
    const idx = l.search(/(^|[^:"'`])\/\//);
    if (idx === -1) return l;
    return l.slice(0, l.indexOf("//", idx));
  });
}

/** 1-based line numbers where firebase-admin is really imported (comments and type-only imports ignored). */
function firebaseAdminLines(content: string): number[] {
  const text = stripComments(content)
    .join("\n")
    .replace(TYPE_ONLY_IMPORT_REGEX, (m) => m.replace(/[^\n]/g, " "));
  const re = new RegExp(FIREBASE_ADMIN_REGEX.source, "g");
  const found = new Set<number>();
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) found.add(text.slice(0, m.index).split("\n").length);
  return [...found];
}

/**
 * Public-by-design keys: Supabase anon keys and publishable keys (Stripe, Clerk, ...) are
 * meant to ship to browsers, so a public prefix on them is not an exposure. A name that
 * also says SERVICE_ROLE is never treated as public.
 */
const PUBLIC_BY_DESIGN_REGEX = /(?:^|_)(?:ANON|PUBLISHABLE)(?:_|$)/i;
const NEVER_PUBLIC_REGEX = /SERVICE_ROLE/i;

function isPublicSecretName(name: string): boolean {
  if (!PUBLIC_SECRET_REGEX.test(name)) return false;
  return !PUBLIC_BY_DESIGN_REGEX.test(name) || NEVER_PUBLIC_REGEX.test(name);
}

function hasPublicPrefix(name: string): boolean {
  return PUBLIC_PREFIXES.some((p) => name.startsWith(p));
}

export class FrontendExposureDetector implements Detector {
  id = "frontend-exposure-detector";
  name = "Frontend Exposure Detection";
  category = "frontend_exposure" as const;
  description = "Detects sensitive environment variables or admin SDKs used in client-side code.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const fileSet = new Set(context.files.map((f) => f.replace(/\\/g, "/")));

    const resolveImport = (fromFile: string, spec: string): string | undefined => {
      const bases: string[] = [];
      const dir = path.posix.dirname(fromFile.replace(/\\/g, "/"));
      if (spec.startsWith("./") || spec.startsWith("../")) {
        bases.push(path.posix.normalize(path.posix.join(dir, spec)));
      } else if (spec.startsWith("@/")) {
        bases.push(`src/${spec.slice(2)}`, spec.slice(2));
      } else {
        return undefined;
      }
      for (const base of bases) {
        const candidates = [
          base,
          ...CODE_EXTENSIONS.map((e) => base + e),
          ...CODE_EXTENSIONS.map((e) => `${base}/index${e}`),
        ];
        const hit = candidates.find(
          (c) => fileSet.has(c) && CODE_EXTENSIONS.some((e) => c.endsWith(e)),
        );
        if (hit) return hit;
      }
      return undefined;
    };

    for (const filePath of context.files) {
      const base = path.basename(filePath);
      // .env files: public-prefixed names that look like secrets. Templates
      // (.env.example/.sample/.template/.dist) and .env.vault ciphertext are skipped.
      const envKind = classifyEnvFileName(base);
      if (envKind !== null && envKind !== "env") continue;
      if (envKind === "env") {
        const lines = (await context.readFile(filePath)).split("\n");
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i] ?? "";
          if (line.trim().startsWith("#")) continue;
          const name = /^\s*(?:export\s+)?([A-Za-z0-9_]+)\s*=/.exec(line)?.[1];
          if (name && (isPublicSecretName(name.toUpperCase()) || isServerOnlyPublicName(name))) {
            findings.push(this.publicSecretFinding(filePath, i + 1, name, name));
          }
        }
        continue;
      }

      if (isViteConfigFile(filePath)) {
        findings.push(...this.detectViteDefineLeak(filePath, await context.readFile(filePath)));
        continue;
      }

      if (!CODE_EXTENSIONS.some((e) => filePath.endsWith(e))) continue;

      const content = await context.readFile(filePath);
      if (!isClientFile(filePath, content, context.projectContext)) continue;

      const rawLines = content.split("\n");
      const lines = stripComments(content);

      // Pages-router files with server-side data fetching have firebase-admin tree-shaken from the client bundle
      const serverSideData = usesServerSideDataFetching(filePath, content);
      if (!serverSideData) {
        for (const ln of firebaseAdminLines(content)) {
          findings.push(this.firebaseAdminFinding(filePath, ln, rawLines[ln - 1] ?? ""));
        }
      }

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i] ?? "";
        const raw = rawLines[i] ?? "";

        // 1. service_role keys used directly in client code
        if (SERVICE_ROLE_REGEX.test(line)) {
          findings.push(this.serviceRoleFinding(filePath, i + 1, raw));
        }

        // 2. Public-prefixed variables with secret-looking names
        const match = PUBLIC_SECRET_REGEX.exec(line);
        if (match?.[0] && isPublicSecretName(match[0])) {
          findings.push(this.publicSecretFinding(filePath, i + 1, match[0], match[0]));
        } else {
          // Provider keys, DB URLs and admin keys under a public prefix (no "SECRET" in the name)
          PUBLIC_NAME_TOKEN.lastIndex = 0;
          let t: RegExpExecArray | null;
          while ((t = PUBLIC_NAME_TOKEN.exec(line)) !== null) {
            if (isServerOnlyPublicName(t[0])) {
              findings.push(this.publicSecretFinding(filePath, i + 1, t[0], t[0]));
              break;
            }
          }
        }
      }

      // 3. Follow relative / "@/" imports one level and inspect the imported module
      // Type-only imports are erased at build time and never bring server code to the browser.
      const noBlock = content
        .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "))
        .replace(TYPE_ONLY_IMPORT_REGEX, (m) => m.replace(/[^\n]/g, " "));
      IMPORT_REGEX.lastIndex = 0;
      let m: RegExpExecArray | null;
      REQUIRE_REGEX.lastIndex = 0;
      while ((m = REQUIRE_REGEX.exec(noBlock)) !== null) {
        const ln = noBlock.slice(0, m.index).split("\n").length;
        if (m[1] && SERVICE_ACCOUNT_JSON_REGEX.test(m[1]) && (lines[ln - 1] ?? "").trim() !== "") {
          findings.push(this.firebaseAdminFinding(filePath, ln, rawLines[ln - 1] ?? "", m[1]));
        }
      }
      while ((m = IMPORT_REGEX.exec(noBlock)) !== null) {
        const spec = m[1] ?? m[2];
        if (!spec) continue;
        const importLine = noBlock.slice(0, m.index).split("\n").length;
        if ((lines[importLine - 1] ?? "").trim() === "") continue; // commented-out import
        if (SERVICE_ACCOUNT_JSON_REGEX.test(spec)) {
          findings.push(
            this.firebaseAdminFinding(filePath, importLine, rawLines[importLine - 1] ?? "", spec),
          );
          continue;
        }
        const target = resolveImport(filePath, spec);
        if (!target || target === filePath) continue;

        const targetContent = await context.readFile(target);
        // server-only modules and Server Actions ("use server") are never bundled for the browser
        if (
          /^\s*import\s+["']server-only["']/m.test(targetContent) ||
          hasUseServerDirective(targetContent)
        )
          continue;
        const targetLines = stripComments(targetContent);
        const raw = rawLines[importLine - 1] ?? "";

        if (
          !serverSideData &&
          !usesServerSideDataFetching(target, targetContent) &&
          firebaseAdminLines(targetContent).length > 0
        ) {
          findings.push(this.firebaseAdminFinding(filePath, importLine, raw, target));
          continue;
        }

        if (targetLines.some((l) => SERVICE_ROLE_REGEX.test(l))) {
          findings.push(this.serviceRoleFinding(filePath, importLine, raw, target));
          continue;
        }

        const seen = new Set<string>();
        for (const l of targetLines) {
          SERVER_ENV_REGEX.lastIndex = 0;
          let e: RegExpExecArray | null;
          while ((e = SERVER_ENV_REGEX.exec(l)) !== null) {
            const name = e[1] ?? e[2];
            if (
              name &&
              !hasPublicPrefix(name) &&
              SECRET_LOOKING_NAME.test(name) &&
              !seen.has(name)
            ) {
              seen.add(name);
              findings.push(this.serverEnvImportFinding(filePath, importLine, raw, target, name));
            }
          }
        }
      }
    }

    return findings;
  }

  /**
   * Flags `define` blocks in vite.config that inline the whole of process.env into the bundle.
   * vite.config is intentionally excluded from the other frontend-exposure checks.
   * Limitations: braces inside template-literal interpolations are not tracked, and a `define`
   * value that is a variable (`define: envDefine`) is not followed.
   */
  private detectViteDefineLeak(file: string, content: string): Finding[] {
    const code = stripComments(content).join("\n");
    const rawLines = content.split("\n");
    const out: Finding[] = [];
    const aliases = [...code.matchAll(ENV_ALIAS_REGEX)].map((a) =>
      (a[1] ?? "").replace(/\$/g, "\\$"),
    );
    const aliasRe = aliases.length
      ? new RegExp(
          `\\.\\.\\.\\s*(?:${aliases.join("|")})(?![\\w$.[(?])|["'\`]?process\\.env["'\`]?\\s*:\\s*(?:JSON\\.stringify\\(\\s*)?(?:${aliases.join("|")})(?![\\w$.[(?])`,
        )
      : null;
    const defineRe = /["']?\bdefine["']?\s*:\s*\{/g;
    let m: RegExpExecArray | null;
    while ((m = defineRe.exec(code)) !== null) {
      const start = m.index + m[0].length;
      let depth = 1;
      let end = start;
      let quote: string | null = null;
      while (end < code.length && depth > 0) {
        const ch = code[end];
        if (quote) {
          if (ch === "\\") end++;
          else if (ch === quote) quote = null;
        } else if (ch === '"' || ch === "'" || ch === "`") quote = ch;
        else if (ch === "{") depth++;
        else if (ch === "}") depth--;
        end++;
      }
      const body = code.slice(start, end);
      const leak = VITE_DEFINE_LEAK_REGEX.exec(body) ?? aliasRe?.exec(body) ?? null;
      if (!leak) continue;
      const line = code.slice(0, start + leak.index).split("\n").length;
      out.push(this.viteDefineFinding(file, line, rawLines[line - 1] ?? ""));
    }
    return out;
  }

  private viteDefineFinding(file: string, line: number, evidence: string): Finding {
    return {
      id: createFindingId(
        CATEGORY_PREFIX.frontend_exposure,
        "frontend_exposure/vite-define-process-env",
        file,
        line,
      ),
      ruleId: "frontend_exposure/vite-define-process-env",
      title: "vite.config exposes all environment variables to the browser",
      severity: "critical",
      category: "frontend_exposure",
      deployBlocking: true,
      confidence: "high",
      file,
      line,
      evidence: sanitizeEvidence(evidence),
      plainEnglishProblem:
        "Your Vite `define` config copies the whole of process.env into the client bundle, including every secret on the machine that builds it.",
      whyItMatters:
        "Vite replaces these expressions with literal values in the JavaScript sent to browsers. Anyone can read API keys, database passwords and tokens from the bundle.",
      fixSteps: [
        "Remove `process.env` from `define` (or the spread of it).",
        "Expose only specific, non-secret values, using the VITE_ prefix and import.meta.env.",
        "Rotate any secret that was present in the environment of a build that has already been deployed.",
      ],
      autoFixAvailable: false,
    };
  }

  private serviceRoleFinding(
    file: string,
    line: number,
    evidence: string,
    importedFile?: string,
  ): Finding {
    const via = importedFile ? ` (via imported module ${importedFile})` : "";
    return {
      id: createFindingId(
        CATEGORY_PREFIX.frontend_exposure,
        "frontend_exposure/service-role-key",
        file,
        line,
        importedFile,
      ),
      ruleId: "frontend_exposure/service-role-key",
      title: "Service Role Key used in client code",
      severity: "critical",
      category: "frontend_exposure",
      deployBlocking: true,
      confidence: importedFile ? "medium" : "high",
      file,
      line,
      evidence: sanitizeEvidence(evidence),
      plainEnglishProblem: `You are using an admin 'service role' key in frontend code${via}.`,
      whyItMatters:
        "Client code is visible to everyone in the browser. Anyone can extract this key and gain full admin access to your database, bypassing all row-level security.",
      fixSteps: [
        "Never use service role keys in the browser.",
        "Use the regular anonymous/public key for the frontend client.",
        "If you need to perform admin actions, create a backend API route, do the action there, and call it from the frontend.",
      ],
      autoFixAvailable: false,
    };
  }

  private firebaseAdminFinding(
    file: string,
    line: number,
    evidence: string,
    via?: string,
  ): Finding {
    const where = via ? ` (via ${via})` : "";
    return {
      id: createFindingId(
        CATEGORY_PREFIX.frontend_exposure,
        "frontend_exposure/firebase-admin",
        file,
        line,
        via,
      ),
      ruleId: "frontend_exposure/firebase-admin",
      title: "Firebase Admin SDK or service account used in client code",
      severity: "critical",
      category: "frontend_exposure",
      deployBlocking: true,
      confidence: via ? "medium" : "high",
      file,
      line,
      evidence: sanitizeEvidence(evidence),
      plainEnglishProblem: `Client-side code uses the Firebase Admin SDK or a service account key${where}.`,
      whyItMatters:
        "The Firebase Admin SDK runs with full administrative privileges and needs a service account private key. Bundling it for the browser exposes those credentials or breaks the build.",
      fixSteps: [
        "Remove 'firebase-admin' and service account JSON imports from client components and pages.",
        "Use the client Firebase SDK ('firebase/app', 'firebase/auth', 'firebase/firestore') in the browser.",
        "Move administrative operations to a server-side API route or a Server Action marked with 'use server', and rotate the service account key if it was ever bundled.",
      ],
      autoFixAvailable: false,
    };
  }

  private serverEnvImportFinding(
    file: string,
    line: number,
    evidence: string,
    importedFile: string,
    envName: string,
  ): Finding {
    return {
      id: createFindingId(
        CATEGORY_PREFIX.frontend_exposure,
        "frontend_exposure/server-env-in-client-import",
        file,
        line,
        `${importedFile}:${envName}`,
      ),
      ruleId: "frontend_exposure/server-env-in-client-import",
      title: "Client file imports a module that reads a server-only secret",
      severity: "high",
      category: "frontend_exposure",
      deployBlocking: false,
      confidence: "medium",
      file,
      line,
      evidence: sanitizeEvidence(evidence),
      plainEnglishProblem: `This client component imports ${importedFile}, which reads the server-only variable ${envName}.`,
      whyItMatters:
        "Modules imported by client components are bundled for the browser. Server-only secrets are either leaked (if inlined) or the code breaks, and it signals that server logic is mixed into client code.",
      fixSteps: [
        "Move the code that uses this secret into a server-only module, API route or Server Action.",
        "Call it from the client instead of importing it.",
        'Consider adding `import "server-only"` to the module so the build fails if it is imported by client code.',
      ],
      autoFixAvailable: false,
    };
  }

  /**
   * Severity: `high` and not deploy-blocking. The rule matches on the variable *name*, so we
   * cannot be sure the value is a real secret (e.g. `NEXT_PUBLIC_SECRET_SANTA`); the documented
   * convention reserves critical + blocking for confirmed exposures such as service-role keys.
   */
  private publicSecretFinding(
    file: string,
    line: number,
    evidence: string,
    varName: string,
  ): Finding {
    return {
      id: createFindingId(
        CATEGORY_PREFIX.frontend_exposure,
        "frontend_exposure/public-secret-var",
        file,
        line,
        varName,
      ),
      ruleId: "frontend_exposure/public-secret-var",
      title: "Sensitive variable exposed to frontend",
      severity: "high",
      category: "frontend_exposure",
      deployBlocking: false,
      confidence: "high",
      file,
      line,
      evidence: sanitizeEvidence(evidence),
      plainEnglishProblem: `You have given a sensitive-looking variable (${varName}) a public prefix.`,
      whyItMatters:
        "Public prefixes (NEXT_PUBLIC_, VITE_, REACT_APP_, EXPO_PUBLIC_, NUXT_PUBLIC_, PUBLIC_) bundle the variable into the code sent to the user's browser, exposing your secret.",
      fixSteps: [
        "Remove the public prefix from this variable in your .env file and code.",
        "Move the logic that requires this secret to a server-side API route or Server Component.",
      ],
      autoFixAvailable: false,
    };
  }
}
