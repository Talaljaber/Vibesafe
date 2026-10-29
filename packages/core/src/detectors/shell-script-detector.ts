import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { redactSecret } from "@talaljaber/vibesafe-shared";
import { SECRET_PATTERNS, matchSecretPattern } from "./patterns/secret-patterns.js";
import { classifyPath, isTestOrFixturePath } from "./utils/file-kind.js";
import { makeFinding } from "./utils/finding.js";

/** `curl|wget <plain http URL> ... | [sudo] sh|bash|zsh` and `sh <(curl http://...)`. */
const PIPE_TO_SHELL_RE =
  /\b(?:curl|wget)\b[^|;&\n]*?\bhttp:\/\/[^\s|;&]+[^|;&\n]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+\S+=\S*\s+)*(?:ba|z|da|k)?sh\b|\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b[^)]*\bhttp:\/\//;

/** The same shape with quoted text blanked: the curl and the pipe must be real code. */
const PIPE_SHAPE_RE =
  /\b(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+\S+=\S*\s+)*(?:ba|z|da|k)?sh\b|\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b/;

/** `NAME=value` / `export NAME=value` / `readonly NAME=value` with a credential-like name. */
const ASSIGN_RE =
  /^\s*(?:export\s+|readonly\s+|local\s+|declare\s+(?:-\w+\s+)?)?([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|[^\s;#]+)/;
const SECRET_NAME_RE =
  /(?:SECRET|PASSWORD|PASSWD|PASSPHRASE|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|SERVICE_?ROLE|CREDENTIALS?|AUTH_?KEY|SIGNING_?KEY)/i;
const PUBLIC_NAME_RE =
  /(?:^|_)(?:PUBLIC|PUBLISHABLE|ANON)(?:_|$)|_(?:FILE|PATH|DIR|NAME|ID|URL|ENABLED|LENGTH|TTL|TIMEOUT|HEADER)$/i;
const PLACEHOLDER_RE =
  /^(?:|x+|\*+|-|null|none|undefined|false|true|change[-_]?me|replace[-_]?me|placeholder|dummy|example|sample|todo|tbd|<[^>]*>|\[[^\]]*\]|your[-_].*|.*[-_]here)$/i;

/** Command-line password flags: `mysql -pS3cret`, `--password=...`, `sshpass -p ...`, `curl -u user:pass`. */
const FLAG_CREDENTIAL_RES: RegExp[] = [
  /\b(?:mysql|mysqldump|mysqladmin|mariadb)\b[^\n]*\s-p(?!\s)([^\s'"$;|&][^\s;|&]*)/,
  /\s--password(?:=|\s+)(?!\$|"\$)("[^"$]+"|'[^']+'|[^\s;|&$'"]+)/,
  /\bsshpass\s+-p\s*(?!\$|"\$)("[^"$]+"|'[^']+'|[^\s;|&$'"]+)/,
  /\bcurl\b[^\n]*\s(?:-u|--user)\s+["']?[^\s:'"$]+:(?!\$)([^\s'"@$]+)["']?/,
];

/** `scheme://user:password@host` with a literal password and a single-label host. */
const URL_CRED_RE = /\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/'"]*:([^\s@/'"]+)@([^\s:/?#'"]+)/i;

function lineHasKnownSecret(line: string): boolean {
  return SECRET_PATTERNS.some((p) => matchSecretPattern(p, line) !== null);
}

function unquote(v: string): string {
  if (v.length >= 2 && (v[0] === '"' || v[0] === "'") && v[v.length - 1] === v[0]) {
    return v.slice(1, -1);
  }
  return v;
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
        let perRule = 0;
        for (let i = 0; i < lines.length; i++) {
          const raw = lines[i] ?? "";
          const code = stripShellComment(raw);
          if (code.trim() === "") continue;
          if (
            code.includes("http://") &&
            PIPE_TO_SHELL_RE.test(code) &&
            PIPE_SHAPE_RE.test(blankQuoted(code))
          ) {
            findings.push(this.pipeFinding(file, i + 1, raw));
          }
          if (perRule >= 25) continue;
          const cred = this.credentialOf(code);
          if (cred && !lineHasKnownSecret(raw)) {
            perRule++;
            const evidence = raw.split(cred.value).join(redactSecret(cred.value));
            findings.push(this.credentialFinding(file, i + 1, evidence, cred.label));
          }
        }
      } catch {
        // Never throw from a detector.
      }
    }
    return findings;
  }

  private credentialOf(code: string): { value: string; label: string } | undefined {
    const a = ASSIGN_RE.exec(code);
    if (a) {
      const name = a[1] ?? "";
      const value = unquote(a[2] ?? "");
      if (
        SECRET_NAME_RE.test(name) &&
        !PUBLIC_NAME_RE.test(name) &&
        !value.includes("$") &&
        !value.includes("`") &&
        value.length >= 4 &&
        !/^\d+$/.test(value) &&
        !value.startsWith("/") &&
        !PLACEHOLDER_RE.test(value)
      ) {
        return { value, label: name };
      }
    }
    for (const re of FLAG_CREDENTIAL_RES) {
      const m = re.exec(code);
      const value = unquote(m?.[1] ?? "");
      if (m && value.length >= 3 && !PLACEHOLDER_RE.test(value)) {
        return { value, label: "a command-line password" };
      }
    }
    const u = URL_CRED_RE.exec(code);
    if (u) {
      const password = u[1] ?? "";
      const host = u[2] ?? "";
      // Real hostnames are reported by the secret detector's database-URL rule.
      if (!host.includes(".") && !password.includes("$") && !PLACEHOLDER_RE.test(password)) {
        return { value: password, label: "a connection string" };
      }
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
