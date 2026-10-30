import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { redactSecret } from "@talaljaber/vibesafe-shared";
import { classifyPath, isTestOrFixturePath } from "./utils/file-kind.js";
import { makeFinding } from "./utils/finding.js";
import {
  capFindingsPerRule,
  credentialNameKind,
  findUrlCredential,
  hasSpecificSecret,
  isPlaceholderValue,
  looksLikeSecretValue,
} from "./utils/infra-common.js";

/** Start of a pipeline stage that is a shell: `[sudo [-flags]] [env K=V ...] sh|bash|zsh|dash|ksh`. */
const SHELL_STAGE_RE = /^\s*(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+[^\s=]+=\S*\s+)*(?:ba|z|da|k)?sh\b/;
const DOWNLOADER_RE = /\b(?:curl|wget)\b/;
/** `sh <(curl ...` / `bash <(wget ...`: process substitution of a download. */
const PROCESS_SUBST_RE = /\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b/g;
/** A plain-HTTP URL starting at a word boundary. */
const HTTP_URL_RE = /\bhttp:\/\//;

/** Vendor installers that are normally piped into a shell (host, or host + path prefix). */
const VENDOR_INSTALL_HOSTS: readonly string[] = [
  "sh.rustup.rs",
  "get.docker.com",
  "deb.nodesource.com",
  "rpm.nodesource.com",
  "raw.githubusercontent.com/nvm-sh/",
  "install.python-poetry.org",
  "bun.sh",
  "deno.land",
  "get.pnpm.io",
  "astral.sh",
  "get.helm.sh",
  "cli.github.com",
  "aka.ms",
  "sdk.cloud.google.com",
  "awscli.amazonaws.com",
];
const HTTPS_URL_RE = /\bhttps:\/\/([^\s/"'$)\|]+)([^\s"'|)]*)/;

/** Public-read uploads to cloud storage. */
const PUBLIC_UPLOAD_RES: readonly RegExp[] = [
  /\baws\s+(?:\S+\s+)*?s3\s+(?:cp|sync|mv)\b[^;|&]*--acl[ =]["']?public-read(?:-write)?\b/,
  /\baws\s+(?:\S+\s+)*?s3api\s+put-object(?:-acl)?\b[^;|&]*--acl[ =]["']?public-read(?:-write)?\b/,
  /\bgsutil\s+(?:-\S+\s+)*acl\s+ch\b[^;|&]*-u\s+["']?(?:AllUsers|allAuthenticatedUsers):/,
  /\bgsutil\s+(?:-\S+\s+)*iam\s+ch\b[^;|&]*\b(?:allUsers|allAuthenticatedUsers):/,
  /\baz\s+storage\s+container\s+set-permission\b[^;|&]*--public-access[ =]["']?(?:blob|container)\b/,
];

/** True when the host/path is a well-known vendor installer. */
function isVendorInstaller(host: string, path: string): boolean {
  const h = host.toLowerCase();
  const hp = h + path;
  return VENDOR_INSTALL_HOSTS.some((v) =>
    v.includes("/") ? hp.startsWith(v) : h === v || h.endsWith("." + v),
  );
}

/** True when an https download from a non-vendor host is piped (or process-substituted) into a shell. */
function pipesHttpsDownloadToShell(code: string): boolean {
  const parts = code.split(/(\|\|?|&&?|;)/);
  for (let i = 0; i + 2 < parts.length; i += 2) {
    if (parts[i + 1] !== "|") continue;
    const stage = parts[i] ?? "";
    const dl = DOWNLOADER_RE.exec(stage);
    if (!dl) continue;
    const url = HTTPS_URL_RE.exec(stage.slice(dl.index));
    if (!url || isVendorInstaller(url[1] ?? "", url[2] ?? "")) continue;
    if (SHELL_STAGE_RE.test(parts[i + 2] ?? "")) return true;
  }
  for (const m of code.matchAll(PROCESS_SUBST_RE)) {
    const rest = code.slice(m.index + m[0].length);
    const close = rest.indexOf(")");
    const url = HTTPS_URL_RE.exec(close === -1 ? rest : rest.slice(0, close));
    if (url && !isVendorInstaller(url[1] ?? "", url[2] ?? "")) return true;
  }
  return false;
}

/** `NAME=value` / `export NAME=value` / `readonly NAME=value` with a credential-like name. */
const ASSIGN_RE =
  /^\s*(?:export\s+|readonly\s+|local\s+|declare\s+(?:-\w+\s+)?)?([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|[^\s;#]+)/;
/** `docker run -e NAME=value` / `--env NAME=value` / `--env=NAME=value`. */
const ENV_FLAG_RE = /\s(?:-e|--env)(?:\s+|=)([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|[^\s;|&]+)/g;

/**
 * Command-line password flags: `mysql -pS3cret`, `--password=...`, `sshpass -p ...`,
 * `curl -u user:pass`. `after` is a command word that must come earlier on the line;
 * the flag pattern then runs once on the rest of the line, so nothing backtracks
 * across the whole line per occurrence.
 */
const FLAG_CREDENTIALS: { after?: RegExp; flag: RegExp }[] = [
  {
    after: /\b(?:mysql|mysqldump|mysqladmin|mariadb)\b/,
    flag: /\s-p(?!\s)([^\s'"$;|&][^\s;|&]*)/,
  },
  { flag: /\s--password(?:=|\s+)(?!\$|"\$)("[^"$]+"|'[^']+'|[^\s;|&$'"]+)/ },
  { flag: /\bsshpass\s+-p\s*(?!\$|"\$)("[^"$]+"|'[^']+'|[^\s;|&$'"]+)/ },
  { after: /\bcurl\b/, flag: /\s(?:-u|--user)\s+["']?[^\s:'"$]+:(?!\$)([^\s'"@$]+)["']?/ },
];

/** Lines longer than this are generated or embedded data, not hand-written commands. */
const MAX_LINE_LENGTH = 10_000;

function unquote(v: string): string {
  if (v.length >= 2 && (v[0] === '"' || v[0] === "'") && v[v.length - 1] === v[0]) {
    return v.slice(1, -1);
  }
  return v;
}

/**
 * True when a `curl`/`wget` stage is piped (a single `|`) into a shell stage, or a
 * shell runs a download through process substitution (`bash <(curl ...)`). With
 * `requireHttp`, the download must use a plain `http://` URL. The line is split on
 * `|`, `;` and `&` once and every stage is tested with anchored or single-pass
 * patterns, so the check is linear in the line length.
 */
function pipesDownloadToShell(code: string, requireHttp: boolean): boolean {
  const parts = code.split(/(\|\|?|&&?|;)/);
  for (let i = 0; i + 2 < parts.length; i += 2) {
    if (parts[i + 1] !== "|") continue;
    const stage = parts[i] ?? "";
    const dl = DOWNLOADER_RE.exec(stage);
    if (!dl) continue;
    if (requireHttp && !HTTP_URL_RE.test(stage.slice(dl.index))) continue;
    if (SHELL_STAGE_RE.test(parts[i + 2] ?? "")) return true;
  }
  // Process substitution: the download runs up to the next closing parenthesis.
  // Both cursors only move forward, so this stays linear.
  let httpAt = -2;
  let closeAt = -2;
  for (const m of code.matchAll(PROCESS_SUBST_RE)) {
    if (!requireHttp) return true;
    const from = m.index + m[0].length;
    if (closeAt !== code.length && closeAt < from) {
      const c = code.indexOf(")", from);
      closeAt = c === -1 ? code.length : c;
    }
    if (httpAt !== -1 && httpAt < from) httpAt = nextHttpUrl(code, from);
    if (httpAt === -1) return false;
    if (httpAt < closeAt) return true;
  }
  return false;
}

/** Index of the next `http://` at a word boundary at or after `from`, or -1. */
function nextHttpUrl(code: string, from: number): number {
  let at = code.indexOf("http://", from);
  while (at > 0 && /\w/.test(code[at - 1] ?? "")) at = code.indexOf("http://", at + 1);
  return at;
}

/**
 * Shell script rules: piping a script downloaded over plain HTTP into a shell, and
 * credentials written literally into the script (secret-named variables, password
 * flags, connection strings with a password). Known token formats are left to the
 * secret detector.
 */
export class ShellScriptDetector implements Detector {
  id = "shell-script-detector";
  name = "Shell Script Security";
  category = "security_config" as const;
  description = "Detects curl|sh over plain HTTP and hardcoded credentials in shell scripts.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (classifyPath(file) !== "shell") continue;
      if (isTestOrFixturePath(file) && context.config.includeTests !== true) continue;
      try {
        const text = await context.readFile(file);
        if (text.trim() === "") continue;
        const lines = text.split(/\r?\n/);
        for (let i = 0; i < lines.length; i++) {
          const raw = lines[i] ?? "";
          if (raw.length > MAX_LINE_LENGTH) continue;
          const code = stripShellComment(raw);
          if (code.trim() === "") continue;
          if (
            code.includes("http://") &&
            pipesDownloadToShell(code, true) &&
            pipesDownloadToShell(blankQuoted(code), false)
          ) {
            findings.push(this.pipeFinding(file, i + 1, raw));
          }
          if (
            code.includes("https://") &&
            !code.includes("http://") &&
            pipesHttpsDownloadToShell(code) &&
            pipesDownloadToShell(blankQuoted(code), false)
          ) {
            findings.push(this.httpsPipeFinding(file, i + 1, raw));
          }
          const cred = this.credentialOf(code);
          if (cred && !hasSpecificSecret(raw)) {
            const evidence = raw.split(cred.value).join(redactSecret(cred.value));
            findings.push(this.credentialFinding(file, i + 1, evidence, cred.label));
          }
        }
        findings.push(...this.uploadFindings(file, lines));
      } catch {
        // Never throw from a detector.
      }
    }
    return capFindingsPerRule(findings);
  }

  private uploadFindings(file: string, lines: string[]): Finding[] {
    const out: Finding[] = [];
    for (let i = 0; i < lines.length; i++) {
      if ((lines[i] ?? "").length > MAX_LINE_LENGTH) continue;
      let joined = stripShellComment(lines[i] ?? "");
      let j = i;
      while (joined.trimEnd().endsWith("\\") && j + 1 < lines.length && j - i < 8) {
        j++;
        joined = joined.trimEnd().slice(0, -1) + " " + stripShellComment(lines[j] ?? "");
      }
      const start = i;
      i = j;
      if (!/--acl|AllUsers|allUsers|allAuthenticatedUsers|--public-access/.test(joined)) continue;
      if (!PUBLIC_UPLOAD_RES.some((re) => matchesOutsideQuotes(re, joined))) continue;
      out.push(this.uploadFinding(file, start + 1, lines[start] ?? ""));
    }
    return out;
  }

  private httpsPipeFinding(file: string, line: number, raw: string): Finding {
    return makeFinding({
      category: "security_config",
      ruleId: "security_config/shell-remote-script-pipe",
      title: "Script downloaded from a third-party host is piped into a shell",
      severity: "medium",
      confidence: "high",
      file,
      line,
      evidence: raw,
      plainEnglishProblem:
        "This line downloads a script over https from a host that is not a well-known vendor installer and runs it immediately, without any chance to review or verify it.",
      whyItMatters:
        "Whoever controls that host (or a compromised account or domain) can run arbitrary commands with the privileges of this script, often root or a CI runner holding deploy secrets. The script can also change between runs, so what you reviewed is not what runs.",
      fixSteps: [
        "Download to a file, verify a pinned SHA-256 checksum or signature, then run it.",
        "Better: install the tool from your package manager or a pinned, versioned release artifact.",
      ],
      aiFixPrompt:
        "My shell script pipes a script downloaded over https from a third-party host into a shell. Change it to download a pinned, versioned release into a temporary file, verify its SHA-256 checksum, and only then execute it, or install the tool from a package manager instead.",
    });
  }

  private uploadFinding(file: string, line: number, raw: string): Finding {
    return makeFinding({
      category: "security_config",
      ruleId: "security_config/shell-public-cloud-upload",
      title: "Script makes cloud storage objects publicly readable",
      severity: "high",
      confidence: "high",
      file,
      line,
      evidence: raw,
      plainEnglishProblem:
        "This command uploads to (or changes the permissions of) cloud storage so that anyone on the internet can read the objects, without authentication.",
      whyItMatters:
        "Backups, exports and build artifacts routinely contain customer data or secrets. A public-read ACL turns the bucket into a data leak that search engines and scanners find within hours.",
      fixSteps: [
        "Upload with a private ACL (omit --acl public-read, or use --acl private) and keep the bucket's Block Public Access enabled.",
        "Share objects that must be downloaded through short-lived pre-signed URLs.",
        "Check whether objects already uploaded this way contain sensitive data and make them private.",
      ],
      aiFixPrompt:
        "My shell script uploads to cloud storage with a public-read ACL (or grants allUsers/AllUsers access). Change it to upload privately, enable Block Public Access on the bucket, and use pre-signed URLs where a download link is needed. Tell me how to find and fix objects that were already made public.",
    });
  }

  private credentialOf(code: string): { value: string; label: string } | undefined {
    const named = (
      name: string,
      rawValue: string,
    ): { value: string; label: string } | undefined => {
      const value = unquote(rawValue);
      const kind = credentialNameKind(name);
      if (kind !== "credential" || !looksLikeSecretValue(value)) return undefined;
      // Connection strings are handled below (single-label hosts only).
      if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) return undefined;
      return { value, label: name };
    };
    const a = ASSIGN_RE.exec(code);
    if (a) {
      const hit = named(a[1] ?? "", a[2] ?? "");
      if (hit) return hit;
    }
    for (const m of code.matchAll(ENV_FLAG_RE)) {
      const hit = named(m[1] ?? "", m[2] ?? "");
      if (hit) return hit;
    }
    for (const { after, flag } of FLAG_CREDENTIALS) {
      let rest = code;
      if (after) {
        const cmd = after.exec(code);
        if (!cmd) continue;
        rest = code.slice(cmd.index);
      }
      const m = flag.exec(rest);
      const value = unquote(m?.[1] ?? "");
      if (m && value.length >= 3 && !isPlaceholderValue(value)) {
        return { value, label: "a command-line password" };
      }
    }
    const u = findUrlCredential(code);
    // Real hostnames are reported by the secret detector's database-URL rule.
    if (
      u &&
      !u.host.includes(".") &&
      !u.password.includes("$") &&
      !isPlaceholderValue(u.password)
    ) {
      return { value: u.password, label: "a connection string" };
    }
    return undefined;
  }

  private pipeFinding(file: string, line: number, raw: string): Finding {
    return makeFinding({
      category: "security_config",
      ruleId: "security_config/shell-curl-pipe-sh",
      title: "Script downloaded over plain HTTP is piped into a shell",
      severity: "high",
      confidence: "high",
      file,
      line,
      evidence: raw,
      plainEnglishProblem:
        "This line downloads a script over unencrypted http:// and executes it immediately. Anyone on the network path (public Wi-Fi, a compromised router, a malicious proxy or DNS) can replace the script with their own commands.",
      whyItMatters:
        "The script runs with the privileges of whoever runs this file, often root or a CI runner with deploy secrets, so a single tampered response compromises the machine.",
      fixSteps: [
        "Download over https:// only (`curl -fsSL https://...`).",
        "Better: download to a file, verify a published checksum or signature, then run it; or install the tool from your package manager or a pinned release.",
      ],
      aiFixPrompt:
        "My shell script pipes a script downloaded over plain http:// into a shell. Change it to download over https into a temporary file, verify it against a pinned SHA-256 checksum, and only then execute it; if the tool is available from a package manager or a versioned release, install it that way instead.",
    });
  }

  private credentialFinding(file: string, line: number, evidence: string, label: string): Finding {
    return makeFinding({
      category: "security_config",
      ruleId: "security_config/shell-hardcoded-credential",
      title: "Credential hardcoded in a shell script",
      severity: "high",
      confidence: "medium",
      file,
      line,
      evidence,
      discriminator: label,
      plainEnglishProblem: `This script contains ${label === "a command-line password" || label === "a connection string" ? label : `a literal value for ${label}`} that looks like a real credential. It is committed with the script and, for command-line flags, also visible to other users in the process list.`,
      whyItMatters:
        "Scripts are shared, copied into images and CI logs, and kept in git history. A credential written into one is effectively public to everyone with read access to the repository.",
      fixSteps: [
        "Remove the literal value and rotate the credential.",
        'Read it from the environment instead and fail fast when it is missing: `: "${DB_PASSWORD:?DB_PASSWORD must be set}"`.',
        "For database clients prefer an env var or config file the client reads (PGPASSWORD, ~/.pgpass, MYSQL_PWD, an option file) over password flags.",
      ],
      aiFixPrompt:
        "My shell script hardcodes a credential (a secret-named variable, a password flag or a connection string with a password). Change the script to read the value from an environment variable, exit with a clear error if it is not set, and avoid passing passwords as command-line arguments. Tell me which credential I need to rotate.",
    });
  }
}

/** True when `re` matches with its command anchor outside any quoted string. */
function matchesOutsideQuotes(re: RegExp, text: string): boolean {
  const g = new RegExp(re.source, "g");
  for (let m = g.exec(text); m; m = g.exec(text)) {
    if (!inQuote(text, m.index)) return true;
  }
  return false;
}

function inQuote(s: string, at: number): boolean {
  let quote: string | null = null;
  for (let i = 0; i < at; i++) {
    const ch = s[i];
    if (quote) {
      if (ch === quote) quote = null;
      else if (ch === "\\" && quote === '"') i++;
    } else if (ch === "\\") i++;
    else if (ch === '"' || ch === "'") quote = ch;
  }
  return quote !== null;
}

/** Replaces the contents of quoted strings with spaces (quotes kept). */
function blankQuoted(line: string): string {
  let out = "";
  let quote: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (quote) {
      if (ch === quote) {
        quote = null;
        out += ch;
      } else out += " ";
    } else {
      if (ch === '"' || ch === "'") quote = ch;
      out += ch;
    }
  }
  return out;
}

/** Removes a trailing `# comment` outside quotes (a `#` must start a word). */
function stripShellComment(line: string): string {
  let quote: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quote) {
      if (ch === quote) quote = null;
      else if (ch === "\\" && quote === '"') i++;
    } else if (ch === "\\") i++;
    else if (ch === '"' || ch === "'") quote = ch;
    else if (ch === "#" && (i === 0 || /\s/.test(line[i - 1] ?? ""))) return line.slice(0, i);
  }
  return line;
}
