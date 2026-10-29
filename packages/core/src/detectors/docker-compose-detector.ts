import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { SECRET_PATTERNS, matchSecretPattern } from "./patterns/secret-patterns.js";
import { classifyPath, isTestOrFixturePath } from "./utils/file-kind.js";
import { makeFinding } from "./utils/finding.js";
import {
  parseCompose,
  type ComposeEnvVar,
  type ComposePort,
  type ComposeService,
} from "./utils/yaml-lines.js";

/** Database, cache and queue images whose ports must never be public. */
const DATA_STORE_RE =
  /(?:^|[/_-])(?:postgres(?:ql)?|postgis|timescaledb|supabase\/postgres|mysql|mariadb|percona|mongo(?:db)?|redis|valkey|keydb|memcached|elasticsearch|opensearch|cassandra|scylla|couchdb|couchbase|neo4j|clickhouse|cockroach(?:db)?|mssql|sqlserver|influxdb|rabbitmq|nats|etcd|minio)(?:$|[:@/_-])/i;

/** Admin UIs and metrics exporters named after the store they talk to. */
const NOT_DATA_STORE_RE =
  /exporter|mongo-express|commander|insight|adminer|pgadmin|phpmyadmin|pgweb|[-_]ui(?:$|[:@/])/i;

/** Variables that set a data store's administrative password. */
const PASSWORD_VAR_RE =
  /^(?:POSTGRES_PASSWORD|PGPASSWORD|MYSQL_ROOT_PASSWORD|MYSQL_PASSWORD|MARIADB_ROOT_PASSWORD|MARIADB_PASSWORD|MONGO_INITDB_ROOT_PASSWORD|MONGODB_ROOT_PASSWORD|REDIS_PASSWORD|RABBITMQ_DEFAULT_PASS|MSSQL_SA_PASSWORD|SA_PASSWORD|ELASTIC_PASSWORD|NEO4J_AUTH|CLICKHOUSE_PASSWORD|MINIO_ROOT_PASSWORD|INFLUXDB_ADMIN_PASSWORD|DB_PASSWORD|DATABASE_PASSWORD)$/i;

/** Settings that disable authentication altogether. */
const NO_AUTH_RE =
  /^(?:POSTGRES_HOST_AUTH_METHOD=trust|MYSQL_ALLOW_EMPTY_PASSWORD=(?:yes|true|1)|MARIADB_ALLOW_EMPTY_(?:ROOT_)?PASSWORD=(?:yes|true|1)|ALLOW_EMPTY_PASSWORD=(?:yes|true|1))$/i;

/** Well-known default or trivially guessable passwords. */
const WEAK_PASSWORDS = new Set([
  "postgres",
  "postgresql",
  "password",
  "passw0rd",
  "pass",
  "root",
  "admin",
  "administrator",
  "secret",
  "mysql",
  "mariadb",
  "mongo",
  "mongodb",
  "redis",
  "rabbitmq",
  "guest",
  "neo4j",
  "default",
  "changeme",
  "change_me",
  "letmein",
  "test",
  "example",
  "dev",
  "123456",
  "12345678",
  "1234",
  "qwerty",
  "minioadmin",
  "sa",
  "user",
]);

/** `scheme://user:password@host[:port]/...` with a single-label host (`db`, `postgres`). */
const URL_CRED_RE = /\b([a-z][a-z0-9+.-]*):\/\/([^\s:@/]*):([^\s@/]+)@([^\s:/?#]+)/i;
const DB_SCHEME_RE =
  /^(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|mssql|sqlserver)$/i;

const DEV_FILE_RE = /(?:^|[./_-])(?:dev|development|local|test|ci|override)(?:[./_-]|$)/i;

function lineHasKnownSecret(line: string): boolean {
  return SECRET_PATTERNS.some((p) => matchSecretPattern(p, line) !== null);
}

function isWeakPassword(value: string, user?: string | undefined): boolean {
  const v = value.trim().toLowerCase();
  if (v === "") return false;
  if (WEAK_PASSWORDS.has(v)) return true;
  if (user !== undefined && v === user.trim().toLowerCase()) return true;
  return false;
}

/** `${VAR:-default}` / `${VAR-default}` -> the default; plain `${VAR}` -> undefined. */
function literalOrDefault(value: string): string | undefined {
  const v = value.trim();
  const m = /^\$\{[A-Za-z_][\w]*:?-([^}]*)\}$/.exec(v);
  if (m) return m[1];
  if (v.includes("$")) return undefined;
  return v;
}

/** Published on every interface: no host IP, `0.0.0.0` or `::`. Loopback or a specific IP is not. */
function isPublic(port: ComposePort): boolean {
  if (port.published === undefined || port.published === "") return false;
  const ip = (port.hostIp ?? "").trim().replace(/^\[|\]$/g, "");
  return ip === "" || ip === "0.0.0.0" || ip === "::";
}

/**
 * docker-compose rules: data stores published on every interface, default or
 * empty database passwords (including `scheme://user:pass@db` URLs with a
 * single-label service host), privileged services and Docker socket mounts.
 */
export class DockerComposeDetector implements Detector {
  id = "docker-compose-detector";
  name = "Docker Compose Security";
  category = "security_config" as const;
  description =
    "Detects databases published on all interfaces, default database passwords, privileged services and Docker socket mounts in compose files.";

  async detect(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (classifyPath(file) !== "compose") continue;
      if (isTestOrFixturePath(file) && context.config.includeTests !== true) continue;
      try {
        const text = await context.readFile(file);
        if (text.trim() === "") continue;
        const lines = text.split(/\r?\n/);
        const compose = parseCompose(text);
        const devFile = DEV_FILE_RE.test(file.replace(/\\/g, "/").split("/").pop() ?? "");
        for (const svc of compose.services) {
          const weak = this.passwordFindings(file, svc, lines);
          findings.push(...weak.findings);
          findings.push(...this.portFindings(file, svc, lines, weak.dataStoreWeak, devFile));
          findings.push(...this.privilegeFindings(file, svc, lines));
        }
      } catch {
        // Never throw from a detector.
      }
    }
    return findings;
  }

  private isDataStore(svc: ComposeService): boolean {
    const name = svc.image ? svc.image.value : svc.name;
    return DATA_STORE_RE.test(name) && !NOT_DATA_STORE_RE.test(name);
  }

  private passwordFindings(
    file: string,
    svc: ComposeService,
    lines: string[],
  ): { findings: Finding[]; dataStoreWeak: boolean } {
    const findings: Finding[] = [];
    let dataStoreWeak = false;
    const dataStore = this.isDataStore(svc);
    const userOf = (keys: string[]): string | undefined =>
      svc.environment.find((e) => keys.includes(e.key.toUpperCase()))?.value;

    for (const env of svc.environment) {
      const rawLine = lines[env.line - 1] ?? "";
      if (lineHasKnownSecret(rawLine)) continue; // reported by the secret detector
      const key = env.key.toUpperCase();

      if (NO_AUTH_RE.test(`${key}=${env.value.trim()}`)) {
        if (dataStore) dataStoreWeak = true;
        findings.push(this.passwordFinding(file, env, rawLine, "no-auth", dataStore));
        continue;
      }

      if (PASSWORD_VAR_RE.test(key)) {
        const literal = literalOrDefault(env.value);
        if (literal === undefined) continue;
        let user: string | undefined;
        if (key.startsWith("POSTGRES")) user = userOf(["POSTGRES_USER"]) ?? "postgres";
        else if (key.startsWith("MYSQL") || key.startsWith("MARIADB"))
          user = userOf(["MYSQL_USER", "MARIADB_USER"]) ?? "root";
        else if (key.startsWith("MONGO")) user = userOf(["MONGO_INITDB_ROOT_USERNAME"]);
        if (key === "NEO4J_AUTH" && literal.trim().toLowerCase() === "none") {
          if (dataStore) dataStoreWeak = true;
          findings.push(this.passwordFinding(file, env, rawLine, "no-auth", dataStore));
          continue;
        }
        // NEO4J_AUTH is `neo4j/<password>`; an empty value means "pass through from the host".
        const password =
          key === "NEO4J_AUTH" ? (/^[^/]+\/(.*)$/.exec(literal)?.[1] ?? "") : literal;
        if (password.trim() === "") continue;
        if (isWeakPassword(password, user)) {
          if (dataStore) dataStoreWeak = true;
          findings.push(this.passwordFinding(file, env, rawLine, "weak", dataStore));
        }
        continue;
      }

      // Connection strings pointing at another compose service (`@db:5432`).
      const m = URL_CRED_RE.exec(env.value);
      if (m && DB_SCHEME_RE.test(m[1] ?? "")) {
        const host = m[4] ?? "";
        const password = decodeSafe(m[3] ?? "");
        if (host.includes(".") || host.includes("$") || password.includes("$")) continue;
        if (isWeakPassword(password, decodeSafe(m[2] ?? ""))) {
          findings.push(this.passwordFinding(file, env, rawLine, "url", false));
        }
      }
    }
    return { findings, dataStoreWeak };
  }

  private passwordFinding(
    file: string,
    env: ComposeEnvVar,
    rawLine: string,
    kind: "weak" | "no-auth" | "url",
    dataStoreService: boolean,
  ): Finding {
    const title =
      kind === "no-auth"
        ? "Database authentication disabled in compose"
        : kind === "url"
          ? "Default database password in a compose connection string"
          : "Default database password in compose";
    const problem =
      kind === "no-auth"
        ? `The compose file sets ${env.key} so the database accepts connections without a password.`
        : kind === "url"
          ? `${env.key} connects to another compose service with a default or guessable password. The same credentials are what the database container is configured with, and they are committed to the repository.`
          : `${env.key} sets the database password to a well-known default (or the user name). Anyone who can reach the database port can log in with it.`;
    return makeFinding({
      category: "security_config",
      ruleId: "security_config/compose-default-db-password",
      title,
      severity: dataStoreService || kind === "no-auth" ? "high" : "medium",
      confidence: "high",
      file,
      line: env.line,
      evidence: rawLine,
      discriminator: env.key,
      plainEnglishProblem: problem,
      whyItMatters:
        "Default database credentials are the first thing automated scanners try. If this compose file is used on a server, or the port is reachable from another network, the whole database can be read, changed or deleted.",
      fixSteps: [
        "Generate a strong random password and keep it out of the compose file: reference it as `${POSTGRES_PASSWORD}` (or the image's `*_PASSWORD_FILE` with a Docker secret) and set the value in an uncommitted .env file or your secret store.",
        "Update every connection string that uses the old password to read it from the same variable.",
        "Never use trust / empty-password modes outside throwaway local containers.",
      ],
      aiFixPrompt:
        "My docker-compose file sets a database password to a default or guessable value (or disables authentication). Replace it with a variable such as ${POSTGRES_PASSWORD} loaded from an uncommitted .env file or a Docker secret (*_PASSWORD_FILE), update the app's connection string to use the same variable, and add the variable names to .env.example without values.",
    });
  }

  private portFindings(
    file: string,
    svc: ComposeService,
    lines: string[],
    weakPassword: boolean,
    devFile: boolean,
  ): Finding[] {
    if (!this.isDataStore(svc)) return [];
    const out: Finding[] = [];
    for (const port of svc.ports) {
      if (!isPublic(port)) continue;
      out.push(
        makeFinding({
          category: "security_config",
          ruleId: "security_config/compose-db-port-exposed",
          title: weakPassword
            ? "Database port published on all interfaces with a default password"
            : "Database port published on all interfaces",
          severity: weakPassword ? "high" : "medium",
          confidence: devFile ? "medium" : "high",
          file,
          line: port.line,
          evidence: lines[port.line - 1] ?? port.raw,
          discriminator: port.raw,
          plainEnglishProblem: weakPassword
            ? "This database service publishes its port without a host IP, so Docker binds it on every network interface, and the service uses a default or empty password. On any machine with a public IP the database is reachable from the internet with known credentials."
            : "This database or cache service publishes its port without a host IP, so Docker binds it on every network interface (0.0.0.0). Docker's port publishing also bypasses host firewalls such as ufw.",
          whyItMatters:
            "Exposed databases and caches are found by internet-wide scanners within minutes. Ransom and data-theft bots routinely wipe or copy exposed Postgres, MySQL, MongoDB and Redis instances.",
          fixSteps: [
            "If only other compose services need the database, remove the `ports:` entry; services reach it by service name on the compose network.",
            'If you need it from the host for local tools, bind it to loopback: `"127.0.0.1:5432:5432"`.',
            "Use a strong password from an environment variable or Docker secret, never the image default.",
          ],
          aiFixPrompt:
            'My docker-compose file publishes a database or cache port on all interfaces (for example "5432:5432"). Remove the published port if only other services need it, or bind it to 127.0.0.1 for local access, and make sure the service\'s password comes from an environment variable or Docker secret instead of a default.',
        }),
      );
    }
    return out;
  }

  private privilegeFindings(file: string, svc: ComposeService, lines: string[]): Finding[] {
    const out: Finding[] = [];
    const common = {
      category: "security_config" as const,
      ruleId: "security_config/compose-privileged-service",
      file,
      fixSteps: [
        "Remove `privileged: true`; grant only the specific capability the service needs with `cap_add` (never ALL or SYS_ADMIN).",
        "Do not mount /var/run/docker.sock into application containers. If a tool really needs the Docker API, use a filtering socket proxy with read-only access to the endpoints it needs.",
        "Run the service as a non-root user.",
      ],
      aiFixPrompt:
        "My docker-compose file gives a service host-level privileges (privileged: true, the Docker socket mounted, or cap_add ALL/SYS_ADMIN). Remove that access, grant only the specific capabilities the service needs, and if it must talk to the Docker API, put a read-only socket proxy in front of it.",
      whyItMatters:
        "A compromised service with these privileges controls the Docker host: it can start new privileged containers, mount the host filesystem and read every other container's secrets.",
    };
    if (svc.privileged && /^(?:true|yes|on)$/i.test(svc.privileged.value)) {
      out.push(
        makeFinding({
          ...common,
          title: "Service runs with privileged: true",
          severity: "high",
          confidence: "high",
          line: svc.privileged.line,
          evidence: lines[svc.privileged.line - 1] ?? "",
          discriminator: "privileged",
          plainEnglishProblem: `Service "${svc.name}" runs privileged, which disables container isolation and gives it every capability and device on the host.`,
        }),
      );
    }
    for (const vol of svc.volumes) {
      if (!/(?:^|[\s"'])\/?(?:var\/)?run\/docker\.sock(?::|$)/.test(vol.value)) continue;
      out.push(
        makeFinding({
          ...common,
          title: "Docker socket mounted into a service",
          severity: "high",
          confidence: "medium",
          line: vol.line,
          evidence: lines[vol.line - 1] ?? vol.value,
          discriminator: `sock:${vol.value}`,
          plainEnglishProblem: `Service "${svc.name}" mounts the Docker socket. Access to the socket is equivalent to root on the host, even when it is mounted read-only.`,
        }),
      );
    }
    for (const cap of svc.capAdd) {
      if (!/^(?:CAP_)?(?:ALL|SYS_ADMIN)$/i.test(cap.value.trim())) continue;
      out.push(
        makeFinding({
          ...common,
          title: `Service adds the ${cap.value.trim().toUpperCase()} capability`,
          severity: "high",
          confidence: "high",
          line: cap.line,
          evidence: lines[cap.line - 1] ?? cap.value,
          discriminator: `cap:${cap.value}`,
          plainEnglishProblem: `Service "${svc.name}" adds ${cap.value.trim()}, which is close to running privileged and allows escaping the container.`,
        }),
      );
    }
    return out;
  }
}

function decodeSafe(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
