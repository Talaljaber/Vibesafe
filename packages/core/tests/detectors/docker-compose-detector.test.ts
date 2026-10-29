import { describe, it, expect } from "vitest";
import type { Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { DockerComposeDetector } from "../../src/detectors/docker-compose-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const createContext = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake",
  projectContext: {} as ScanContext["projectContext"],
  files: Object.keys(files),
  config: { rootPath: "/fake" },
  readFile: async (f) => files[f] ?? "",
});

const run = async (files: Record<string, string>): Promise<Finding[]> => {
  const findings = await new DockerComposeDetector().detect(createContext(files));
  expectRubric(findings);
  return findings;
};

const byRule = (findings: Finding[], rule: string): Finding[] =>
  findings.filter((f) => f.ruleId === `security_config/${rule}`);

const yaml = (...lines: string[]): string => lines.join("\n") + "\n";

describe("DockerComposeDetector: compose-db-port-exposed", () => {
  it("flags data stores published on all interfaces, high with a default password", async () => {
    const findings = byRule(
      await run({
        "docker-compose.yml": yaml(
          "services:",
          "  db:",
          "    image: postgres:16",
          "    environment:",
          "      POSTGRES_PASSWORD: postgres",
          "    ports:",
          '      - "5432:5432"',
          "  cache:",
          "    image: bitnami/redis:7",
          "    ports:",
          '      - "0.0.0.0:6379:6379"',
        ),
      }),
      "compose-db-port-exposed",
    );
    expect(findings.map((f) => [f.line, f.severity, f.confidence])).toEqual([
      [7, "high", "high"],
      [11, "medium", "high"],
    ]);
  });

  it("flags long syntax and flow lists, with medium confidence in dev compose files", async () => {
    const findings = byRule(
      await run({
        "compose.dev.yaml": yaml(
          "services:",
          "  mongo:",
          "    image: mongo:7",
          '    ports: ["27017:27017"]',
          "  mysql:",
          "    image: mysql:8",
          "    ports:",
          "      - target: 3306",
          "        published: 3306",
        ),
      }),
      "compose-db-port-exposed",
    );
    expect(findings.map((f) => [f.line, f.confidence])).toEqual([
      [4, "medium"],
      [9, "medium"],
    ]);
  });

  it("ignores loopback bindings, unpublished ports, expose and app services", async () => {
    const findings = byRule(
      await run({
        "docker-compose.yml": yaml(
          "services:",
          "  db:",
          "    image: postgres:16",
          "    ports:",
          '      - "127.0.0.1:5432:5432"',
          '      - "5433"',
          "    expose:",
          '      - "5434"',
          "  redis:",
          "    image: redis:7",
          "    ports:",
          "      - target: 6379",
          "        published: 6379",
          "        host_ip: 127.0.0.1",
          "  web:",
          "    image: node:20",
          "    ports:",
          '      - "3000:3000"',
          "  metrics:",
          "    image: prometheuscommunity/postgres-exporter:v0.15.0",
          "    ports:",
          '      - "9187:9187"',
          '  # db2: { image: postgres, ports: ["5432:5432"] }',
        ),
      }),
      "compose-db-port-exposed",
    );
    expect(findings).toEqual([]);
  });
});

describe("DockerComposeDetector: compose-default-db-password", () => {
  it("flags default passwords, disabled auth and single-label-host URLs", async () => {
    const findings = byRule(
      await run({
        "docker-compose.yml": yaml(
          "services:",
          "  db:",
          "    image: postgres:16",
          "    environment:",
          "      POSTGRES_USER: app",
          "      POSTGRES_PASSWORD: app",
          "  mysql:",
          "    image: mysql:8",
          "    environment:",
          "      - MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PASSWORD:-root}",
          "      - MYSQL_ALLOW_EMPTY_PASSWORD=yes",
          "  api:",
          "    build: .",
          "    environment:",
          "      DATABASE_URL: postgres://postgres:postgres@db:5432/app",
          "      REDIS_URL: redis://default:redis@cache:6379",
        ),
      }),
      "compose-default-db-password",
    );
    expect(findings.map((f) => [f.line, f.severity])).toEqual([
      [6, "high"],
      [10, "high"],
      [11, "high"],
      [15, "medium"],
      [16, "medium"],
    ]);
    expect(findings[3]!.evidence).not.toContain(":postgres@");
  });

  it("ignores variables, strong passwords, empty pass-through and real hostnames", async () => {
    const findings = byRule(
      await run({
        "docker-compose.yml": yaml(
          "services:",
          "  db:",
          "    image: postgres:16",
          "    environment:",
          "      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}",
          "      POSTGRES_USER:",
          "  db2:",
          "    image: postgres:16",
          "    environment:",
          "      POSTGRES_PASSWORD: Zq8!vR2#kLw9",
          "      POSTGRES_PASSWORD_FILE: /run/secrets/pg",
          "  api:",
          "    build: .",
          "    environment:",
          "      DATABASE_URL: postgres://app:${DB_PASSWORD}@db:5432/app",
          "      OTHER_URL: postgres://postgres:postgres@db.example.com:5432/app",
          "      # POSTGRES_PASSWORD: postgres",
        ),
      }),
      "compose-default-db-password",
    );
    expect(findings).toEqual([]);
  });

  it("reports quoted default passwords like unquoted ones and keeps the port high", async () => {
    const findings = await run({
      "docker-compose.yml": yaml(
        "services:",
        "  db:",
        "    image: postgres:16",
        "    environment:",
        '      POSTGRES_PASSWORD: "postgres"',
        "    ports:",
        '      - "5432:5432"',
      ),
    });
    expect(findings.map((f) => [f.ruleId, f.line, f.severity])).toEqual([
      ["security_config/compose-default-db-password", 5, "high"],
      ["security_config/compose-db-port-exposed", 7, "high"],
    ]);
  });

  it("leaves lines with a specific token format to the secret detector, but keeps the weakness", async () => {
    const token = "ghp_" + "a".repeat(10) + "B".repeat(10) + "c".repeat(16);
    const findings = await run({
      "docker-compose.yml": yaml(
        "services:",
        "  db:",
        "    image: postgres:16",
        "    environment:",
        `      POSTGRES_PASSWORD: postgres # ${token}`,
        "    ports:",
        '      - "5432:5432"',
      ),
    });
    expect(findings.map((f) => [f.ruleId, f.line, f.severity])).toEqual([
      ["security_config/compose-db-port-exposed", 7, "high"],
    ]);
  });
});

describe("DockerComposeDetector: compose-privileged-service", () => {
  it("flags privileged, the Docker socket and dangerous capabilities", async () => {
    const findings = byRule(
      await run({
        "compose.yml": yaml(
          "services:",
          "  agent:",
          "    image: ci-agent:1",
          "    privileged: true",
          "    volumes:",
          "      - /var/run/docker.sock:/var/run/docker.sock:ro",
          "    cap_add:",
          "      - SYS_ADMIN",
        ),
      }),
      "compose-privileged-service",
    );
    expect(findings.map((f) => [f.line, f.severity, f.confidence])).toEqual([
      [4, "high", "high"],
      [6, "high", "medium"],
      [8, "high", "high"],
    ]);
  });

  it("ignores privileged: false, ordinary volumes and narrow capabilities", async () => {
    const findings = byRule(
      await run({
        "compose.yml": yaml(
          "services:",
          "  web:",
          "    image: node:20",
          "    privileged: false",
          "    volumes:",
          "      - ./data:/data",
          "      - docker-sock-docs:/docs",
          "    cap_add:",
          "      - NET_BIND_SERVICE",
          "    # privileged: true",
        ),
      }),
      "compose-privileged-service",
    );
    expect(findings).toEqual([]);
  });
});

describe("DockerComposeDetector: general", () => {
  it("only reads compose files, never throws and gives stable ids", async () => {
    const body = yaml(
      "services:",
      "  db:",
      "    image: postgres",
      "    ports:",
      '      - "5432:5432"',
    );
    expect(
      await run({ "config.yml": body, "k8s/db.yaml": body, "tests/docker-compose.yml": body }),
    ).toEqual([]);
    const a = await run({ "docker-compose.yml": body });
    const b = await run({ "docker-compose.yml": body });
    expect(a).toHaveLength(1);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
    await expect(
      run({ "docker-compose.yml": "services: [\n  - : :\n\t-\n" }),
    ).resolves.toBeDefined();
  });
});

describe("DockerComposeDetector: review hardening", () => {
  it("matches data stores by the leading word of the image name only", async () => {
    const findings = byRule(
      await run({
        "docker-compose.yml": yaml(
          "services:",
          "  proxy:",
          "    image: ghcr.io/acme/app-redis-proxy:1",
          "    ports:",
          '      - "6379:6379"',
          "  mymongo:",
          "    build: ./my-mongo-admin",
          "    ports:",
          '      - "8081:8081"',
          "  sql:",
          "    image: mcr.microsoft.com/mssql/server:2022-latest",
          "    ports:",
          '      - "1433:1433"',
          "  ch:",
          "    image: clickhouse/clickhouse-server:24",
          "    ports:",
          '      - "8123:8123"',
          "  redis-cache:",
          "    build: ./cache",
          "    ports:",
          '      - "6380:6379"',
        ),
      }),
      "compose-db-port-exposed",
    );
    expect(findings.map((f) => f.line)).toEqual([13, 17, 21]);
  });

  it("flags a Docker socket mounted through a variable default", async () => {
    const findings = byRule(
      await run({
        "compose.yml": yaml(
          "services:",
          "  agent:",
          "    image: ci-agent:1",
          "    volumes:",
          "      - ${DOCKER_SOCK:-/var/run/docker.sock}:/var/run/docker.sock",
          "      - ./my-run/docker.sock.md:/docs/x",
        ),
      }),
      "compose-privileged-service",
    );
    expect(findings.map((f) => f.line)).toEqual([5]);
  });

  it("keeps 25 findings per rule and file, then one summary", async () => {
    const lines = ["services:"];
    for (let i = 0; i < 300; i++) {
      lines.push(
        `  db${i}:`,
        "    image: postgres:16",
        "    ports:",
        `      - "${10000 + i}:5432"`,
      );
    }
    const findings = byRule(
      await run({ "docker-compose.yml": yaml(...lines) }),
      "compose-db-port-exposed",
    );
    expect(findings).toHaveLength(26);
    expect(findings[25]!.title).toContain("275 more in this file");
    expect(findings[25]!.confidence).toBe("medium");
  });
});
