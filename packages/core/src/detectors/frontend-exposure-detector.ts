import path from "node:path";
import { type Detector, type Finding, type ScanContext } from "@vibesafe/shared";
import { CATEGORY_PREFIX, createFindingId } from "@vibesafe/shared";
import { sanitizeEvidence } from "./utils/sanitize-evidence.js";
import { hasUseServerDirective, isClientFile, usesServerSideDataFetching } from "./utils/file-classifier.js";

const CODE_EXTENSIONS = [".ts", ".tsx", ".js", ".jsx"];
const PUBLIC_PREFIXES = ["NEXT_PUBLIC_", "VITE_", "REACT_APP_", "EXPO_PUBLIC_", "NUXT_PUBLIC_", "PUBLIC_"];

/** A public-prefixed variable whose name looks like a secret (not preceded by another name char). */
const PUBLIC_SECRET_REGEX =
  /(?<![A-Z0-9_])(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|PUBLIC)_[A-Z0-9_]*(?:SECRET|PRIVATE|PASSWORD|SERVICE_ROLE)[A-Z0-9_]*/i;

const SERVER_ENV_REGEX = /process\.env(?:\.([A-Za-z_][A-Za-z0-9_]*)|\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\])/g;
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
const IMPORT_REGEX = /(?:import|export)\s[^"';]*?from\s*["']([^"']+)["']|import\s*["']([^"']+)["']/g;

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
        const hit = candidates.find((c) => fileSet.has(c) && CODE_EXTENSIONS.some((e) => c.endsWith(e)));
        if (hit) return hit;
      }
      return undefined;
    };

    for (const filePath of context.files) {
      const base = path.basename(filePath);
      if (base === ".env.example" || base === ".env.sample") continue;

      // .env files: public-prefixed names that look like secrets
      if (base.startsWith(".env")) {
        const lines = (await context.readFile(filePath)).split("\n");
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i] ?? "";
          if (line.trim().startsWith("#")) continue;
          const name = /^\s*(?:export\s+)?([A-Za-z0-9_]+)\s*=/.exec(line)?.[1];
          if (name && PUBLIC_SECRET_REGEX.test(name.toUpperCase())) {
            findings.push(this.publicSecretFinding(filePath, i + 1, name, name));
          }
        }
        continue;
      }

      if (!CODE_EXTENSIONS.some((e) => filePath.endsWith(e))) continue;

      const content = await context.readFile(filePath);
      if (!isClientFile(filePath, content)) continue;

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
        if (match?.[0]) {
          findings.push(this.publicSecretFinding(filePath, i + 1, match[0], match[0]));
        }
      }

      // 3. Follow relative / "@/" imports one level and inspect the imported module
      const noBlock = content.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "));
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
          findings.push(this.firebaseAdminFinding(filePath, importLine, rawLines[importLine - 1] ?? "", spec));
          continue;
        }
        const target = resolveImport(filePath, spec);
        if (!target || target === filePath) continue;

        const targetContent = await context.readFile(target);
        // server-only modules and Server Actions ("use server") are never bundled for the browser
        if (/^\s*import\s+["']server-only["']/m.test(targetContent) || hasUseServerDirective(targetContent)) continue;
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
            if (name && !hasPublicPrefix(name) && SECRET_LOOKING_NAME.test(name) && !seen.has(name)) {
              seen.add(name);
              findings.push(this.serverEnvImportFinding(filePath, importLine, raw, target, name));
            }
          }
        }
      }
    }

    return findings;
  }

  private serviceRoleFinding(file: string, line: number, evidence: string, importedFile?: string): Finding {
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

  private firebaseAdminFinding(file: string, line: number, evidence: string, via?: string): Finding {
    const where = via ? ` (via ${via})` : "";
    return {
      id: createFindingId(CATEGORY_PREFIX.frontend_exposure, "frontend_exposure/firebase-admin", file, line, via),
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
  private publicSecretFinding(file: string, line: number, evidence: string, varName: string): Finding {
    return {
      id: createFindingId(CATEGORY_PREFIX.frontend_exposure, "frontend_exposure/public-secret-var", file, line, varName),
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
