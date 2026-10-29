import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { classifyEnvFileName, redactSecret } from "@talaljaber/vibesafe-shared";
import ignore from "ignore";
import path from "node:path";
import { SECRET_PATTERNS, matchSecretPattern } from "./patterns/secret-patterns.js";
import { classifyPath, isTestOrFixturePath } from "./utils/file-kind.js";
import { makeFinding } from "./utils/finding.js";
import {
  parseDockerfile,
  parseKeyValues,
  type DockerInstruction,
  type DockerStage,
} from "./utils/dockerfile.js";

/** Variable names that hold credentials. */
const SECRET_NAME_RE =
  /(?:SECRET|PASSWORD|PASSWD|PASSPHRASE|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|SERVICE_?ROLE|CREDENTIALS?|AUTH_?KEY|SIGNING_?KEY|ENCRYPTION_?KEY|CONNECTION_STRING|DSN|(?:_|^)(?:URL|URI)$)/i;
/** Names that look secret but are public by design or just configuration. */
const PUBLIC_NAME_RE =
  /(?:^|_)(?:PUBLIC|PUBLISHABLE|ANON)(?:_|$)|^NEXT_PUBLIC_|^VITE_|^REACT_APP_|^EXPO_PUBLIC_|_(?:FILE|PATH|DIR|URL_PATH|ENABLED|DISABLED|LENGTH|TTL|EXPIRY|EXPIRES(?:_IN)?|TIMEOUT|HEADER|NAME|ID)$/i;
const PLACEHOLDER_RE =
  /^(?:|x+|\*+|-|null|none|nil|undefined|false|true|change[-_]?me|replace[-_]?me|placeholder|dummy|example|sample|todo|tbd|<[^>]*>|\[[^\]]*\]|\{\{.*\}\}|your[-_].*|.*[-_]here)$/i;
const URL_NAME_RE = /URL|URI|DSN|CONNECTION_STRING/i;
/** Password of a `scheme://user:password@host` URL. */
const URL_PASSWORD_RE = /^[a-z][a-z0-9+.-]*:\/\/[^\s:@/]*:([^\s@/]+)@/i;

/** `COPY`/`ADD` sources that send the whole build context. */
const WHOLE_CONTEXT_RE = /^(?:\.|\.\/|\*|\.\/\*)$/;

/** Base images that run as a non-root user by default. */
const NONROOT_IMAGE_RE = /nonroot|distroless\/static|^cgr\.dev\/|chainguard/i;
/** Entrypoint helpers that drop root before starting the app. */
const PRIVILEGE_DROP_RE = /\b(?:gosu|su-exec|setpriv|runuser|chroot\s+--userspec|s6-setuidgid)\b/;

function lineHasKnownSecret(line: string): boolean {
  return SECRET_PATTERNS.some((p) => matchSecretPattern(p, line) !== null);
}

/**
 * Dockerfile rules: secrets baked in with ENV/ARG, the whole build context copied
 * without an adequate `.dockerignore`, containers that run as root and base images
 * without a version tag.
 */
export class DockerfileDetector implements Detector {
  id = "dockerfile-detector";
  name = "Dockerfile Security";
  category = "security_config" as const;
  description =
    "Detects secrets in ENV/ARG, COPY of the whole context without a .dockerignore, root containers and unpinned base images.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (classifyPath(file) !== "dockerfile") continue;
      if (isTestOrFixturePath(file) && context.config.includeTests !== true) continue;
      try {
        const text = await context.readFile(file);
        if (text.trim() === "") continue;
        const lines = text.split(/\r?\n/);
        const doc = parseDockerfile(text);
        findings.push(...this.secretRules(file, doc.instructions, lines));
        findings.push(...(await this.copyRule(context, file, doc.stages, lines)));
        findings.push(...this.rootRule(file, doc.stages, lines));
        findings.push(...this.baseImageRule(file, doc.stages, lines));
      } catch {
        // Never throw from a detector.
      }
    }
    return findings;
  }

  private secretRules(file: string, instructions: DockerInstruction[], lines: string[]): Finding[] {
    const out: Finding[] = [];
    for (const ins of instructions) {
      if (ins.keyword !== "ENV" && ins.keyword !== "ARG") continue;
      const sourceLines = lines.slice(ins.line - 1, ins.endLine).join("\n");
      if (lineHasKnownSecret(sourceLines)) continue; // reported by the secret detector
      for (const { key, value } of parseKeyValues(ins.args)) {
        if (value === undefined || !SECRET_NAME_RE.test(key) || PUBLIC_NAME_RE.test(key)) continue;
        const v = value.trim();
        if (v.includes("$") || v.length < 4 || /^\d+$/.test(v) || v.startsWith("/")) continue;
        if (PLACEHOLDER_RE.test(v)) continue;
        // Connection strings are only secret when they carry a password.
        if (URL_NAME_RE.test(key)) {
          const pw = URL_PASSWORD_RE.exec(v)?.[1];
          if (pw === undefined || PLACEHOLDER_RE.test(pw) || pw.includes("$")) continue;
        }
        const lineNo = this.lineOfKey(lines, ins, key);
        out.push(
          makeFinding({
            category: "security_config",
            ruleId: "security_config/docker-secret-in-env",
            title: `Secret baked into the image with ${ins.keyword}`,
            severity: "high",
            confidence: v.length >= 16 ? "high" : "medium",
            file,
            line: lineNo,
            evidence: (lines[lineNo - 1] ?? "").split(value).join(redactSecret(value)),
            discriminator: key,
            plainEnglishProblem: `The Dockerfile sets ${key} to a literal value with ${ins.keyword}. That value is committed to the repository and stored in the image metadata, where \`docker history\` and \`docker inspect\` show it to anyone who can pull the image.`,
            whyItMatters:
              "Images are pushed to registries, cached on CI runners and shared between teams. A credential written into a layer cannot be removed later without rebuilding and rotating it, and anyone with pull access can read it.",
            fixSteps: [
              "Remove the literal value from the Dockerfile and rotate the credential, since it is already in git history.",
              "Pass the value at runtime instead (docker run -e / --env-file, compose `environment:` from an uncommitted .env, or your platform's secret store).",
              "If the value is needed during the build, use a BuildKit secret mount: `RUN --mount=type=secret,id=name ...` with `docker build --secret id=name,src=...`.",
            ],
            aiFixPrompt:
              "My Dockerfile sets a secret with ENV or ARG, so the value is stored in the image and in git. Remove the hardcoded value, read it at runtime from an environment variable provided by the container platform (or a BuildKit `--mount=type=secret` if it is needed at build time), and list the commands I need to rotate the leaked credential.",
          }),
        );
      }
    }
    return out;
  }

  /** Finds the physical line of `key` inside a (possibly continued) instruction. */
  private lineOfKey(lines: string[], ins: DockerInstruction, key: string): number {
    for (let n = ins.line; n <= ins.endLine; n++) {
      if ((lines[n - 1] ?? "").includes(key)) return n;
    }
    return ins.line;
  }

  private async copyRule(
    context: ScanContext,
    file: string,
    stages: DockerStage[],
    lines: string[],
  ): Promise<Finding[]> {
    const copies: { ins: DockerInstruction; finalStage: boolean }[] = [];
    stages.forEach((stage, idx) => {
      for (const ins of stage.instructions) {
        if (ins.keyword !== "COPY" && ins.keyword !== "ADD") continue;
        const tokens = ins.args.split(/\s+/).filter(Boolean);
        if (tokens.some((t) => /^--from=/i.test(t))) continue;
        const operands = tokens.filter((t) => !t.startsWith("--"));
        if (operands.length < 2) continue;
        if (operands.slice(0, -1).some((s) => WHOLE_CONTEXT_RE.test(s))) {
          copies.push({ ins, finalStage: idx === stages.length - 1 });
        }
      }
    });
    if (copies.length === 0) return [];

    const dir = path.posix.dirname(file.replace(/\\/g, "/"));
    const base = path.posix.basename(file.replace(/\\/g, "/"));
    const join = (name: string): string => (dir === "." ? name : `${dir}/${name}`);
    // BuildKit reads `<Dockerfile>.dockerignore` next to the Dockerfile first, then the
    // context root's `.dockerignore`; the context is usually the Dockerfile's directory
    // or the project root.
    const candidates = [
      ...new Set([join(`${base}.dockerignore`), join(".dockerignore"), ".dockerignore"]),
    ];
    let ignoreText = "";
    for (const c of candidates) {
      ignoreText = await context.readFile(c);
      if (ignoreText.trim() !== "") break;
    }

    let missing: string[];
    let confidence: "high" | "medium";
    if (ignoreText.trim() === "") {
      missing = [".env files", ".git"];
      confidence = "medium"; // missing, empty or unreadable
    } else {
      const ig = ignore().add(ignoreText);
      const safeIgnores = (p: string): boolean => {
        try {
          return ig.ignores(p);
        } catch {
          return false;
        }
      };
      missing = [];
      const ctxPrefix = dir === "." ? "" : `${dir}/`;
      const envFiles = context.files
        .map((f) => f.replace(/\\/g, "/"))
        .filter((f) => classifyEnvFileName(path.posix.basename(f)) === "env")
        .map((f) => (ctxPrefix && f.startsWith(ctxPrefix) ? f.slice(ctxPrefix.length) : f));
      if (!safeIgnores(".env") || envFiles.some((f) => !safeIgnores(f))) missing.push(".env files");
      if (!safeIgnores(".git/") && !safeIgnores(".git/config")) missing.push(".git");
      confidence = "high";
    }
    if (missing.length === 0) return [];

    return copies.map(({ ins, finalStage }) =>
      makeFinding({
        category: "security_config",
        ruleId: "security_config/docker-copy-without-dockerignore",
        title:
          ignoreText.trim() === ""
            ? "COPY of the whole build context without a .dockerignore"
            : "COPY of the whole build context with an incomplete .dockerignore",
        severity: "high",
        confidence: finalStage ? confidence : "medium",
        file,
        line: ins.line,
        evidence: lines[ins.line - 1] ?? "",
        plainEnglishProblem:
          ignoreText.trim() === ""
            ? "This Dockerfile copies the entire build context into the image, and no .dockerignore was found (or it is empty). Local .env files, the .git directory with its full history, and node_modules end up inside the image."
            : `This Dockerfile copies the entire build context into the image, but the .dockerignore does not exclude ${missing.join(" and ")}. Those files end up inside the image.`,
        whyItMatters:
          "Anyone who can pull the image can unpack its layers and read every copied file: live secrets in .env files, and the git history including credentials that were deleted from the code later.",
        fixSteps: [
          "Add a .dockerignore next to the build context with at least: `.git`, `.env`, `.env.*` (re-include `!.env.example` if needed), `node_modules`, and build output.",
          "Prefer copying only what the build needs (package files first, then source directories) instead of `COPY . .`.",
          "Rebuild the image and rotate any secret that was present in a previously pushed image.",
        ],
        aiFixPrompt:
          "My Dockerfile uses `COPY . .` and the build context is not filtered by an adequate .dockerignore, so .env files and the .git directory are copied into the image. Create a .dockerignore that excludes .git, .env and .env.* (keeping .env.example), node_modules and build output, and change the Dockerfile to copy only the files the build needs.",
      }),
    );
  }

  private rootRule(file: string, stages: DockerStage[], lines: string[]): Finding[] {
    const final = stages.at(-1);
    if (!final) return [];
    // Follow `FROM <earlier stage>` chains back to the external base image.
    const chain: DockerStage[] = [final];
    let cur = final;
    for (let guard = 0; guard < 20 && cur.from.fromStage; guard++) {
      const prev = stages.find((s) => s.from.alias === cur.from.image.toLowerCase());
      if (!prev || chain.includes(prev)) break;
      chain.push(prev);
      cur = prev;
    }
    const root = chain.at(-1)!;
    const image = root.from.image.toLowerCase();
    if (image === "scratch" || root.from.variable || NONROOT_IMAGE_RE.test(image)) return [];

    // The last USER instruction along the chain (final stage first) decides.
    let lastUser: DockerInstruction | undefined;
    for (const stage of chain) {
      lastUser = [...stage.instructions].reverse().find((i) => i.keyword === "USER");
      if (lastUser) break;
    }
    if (lastUser) {
      const user = lastUser.args.trim().split(/[:\s]/)[0] ?? "";
      if (user !== "root" && user !== "0") return [];
    }
    const dropsPrivileges = chain.some((s) =>
      s.instructions.some(
        (i) =>
          (i.keyword === "ENTRYPOINT" || i.keyword === "CMD" || i.keyword === "RUN") &&
          PRIVILEGE_DROP_RE.test(i.args),
      ),
    );
    if (dropsPrivileges) return [];

    const anchor = lastUser ?? final.instructions[0]!;
    return [
      makeFinding({
        category: "security_config",
        ruleId: "security_config/docker-runs-as-root",
        title: "Container runs as root",
        severity: "medium",
        confidence: "medium",
        file,
        line: anchor.line,
        evidence: lines[anchor.line - 1] ?? "",
        plainEnglishProblem: lastUser
          ? "The final stage of this Dockerfile switches to the root user, so the application process runs as root inside the container."
          : "The final stage of this Dockerfile never sets a USER, so the application process runs as root inside the container.",
        whyItMatters:
          "Any remote-code-execution bug in the app then has root inside the container: it can modify the image's files, read every mounted secret and has a much easier path to escaping to the host.",
        fixSteps: [
          "Create or reuse an unprivileged user in the final stage (official Node images already ship a `node` user).",
          "Add `USER node` (or your user) after the steps that need root, such as package installs, and make sure the app's files are owned by or readable to that user (`COPY --chown=node:node ...`).",
          "Alternatively start from a base image that runs as non-root by default.",
        ],
        aiFixPrompt:
          "My Dockerfile's final stage runs the application as root. Update it so the app runs as an unprivileged user: keep package installation as root, then add a USER instruction (for Node images the built-in `node` user), use `COPY --chown` so the app can read its files, and make sure the port and file permissions still work.",
      }),
    ];
  }

  private baseImageRule(file: string, stages: DockerStage[], lines: string[]): Finding[] {
    const out: Finding[] = [];
    for (const stage of stages) {
      const f = stage.from;
      if (f.fromStage || f.variable || f.digest || f.image === "" || /^scratch$/i.test(f.image))
        continue;
      if (f.tag !== undefined && f.tag.toLowerCase() !== "latest") continue;
      out.push(
        makeFinding({
          category: "security_config",
          ruleId: "security_config/docker-unpinned-base-image",
          title:
            f.tag === undefined
              ? "Base image has no version tag"
              : "Base image uses the :latest tag",
          severity: "low",
          confidence: "high",
          file,
          line: stage.line,
          evidence: lines[stage.line - 1] ?? "",
          discriminator: f.image,
          plainEnglishProblem:
            "This FROM line does not pin a version of the base image, so every build pulls whatever `latest` points to at that moment.",
          whyItMatters:
            "Builds stop being reproducible: a new major version of the base image can silently change the runtime, break the app, or pull in a compromised image without any change in your repository.",
          fixSteps: [
            "Pin an explicit version tag, for example `node:20-alpine` instead of `node` or `node:latest`.",
            "For stronger guarantees, pin the digest too (`node:20-alpine@sha256:...`) and update it deliberately (for example with Dependabot or Renovate).",
          ],
          aiFixPrompt:
            "My Dockerfile uses a base image without a version tag (or with :latest). Change each FROM line to an explicit version tag that matches what the app runs on today, optionally pinned by digest, and explain how to keep it updated with Dependabot or Renovate.",
        }),
      );
    }
    return out;
  }
}
