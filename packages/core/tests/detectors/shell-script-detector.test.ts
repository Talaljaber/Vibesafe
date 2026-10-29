import { describe, it, expect } from "vitest";
import type { Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { ShellScriptDetector } from "../../src/detectors/shell-script-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const createContext = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake",
  projectContext: {} as ScanContext["projectContext"],
  files: Object.keys(files),
  config: { rootPath: "/fake" },
  readFile: async (f) => files[f] ?? "",
});

const run = async (files: Record<string, string>): Promise<Finding[]> => {
  const findings = await new ShellScriptDetector().detect(createContext(files));
  expectRubric(findings);
  return findings;
};

const byRule = (findings: Finding[], rule: string): Finding[] =>
  findings.filter((f) => f.ruleId === `security_config/${rule}`);

const sh = (...lines: string[]): string => ["#!/usr/bin/env bash", ...lines].join("\n") + "\n";

describe("ShellScriptDetector: shell-curl-pipe-sh", () => {
  it("flags plain-HTTP downloads piped into a shell", async () => {
    const findings = byRule(
      await run({
        "scripts/install.sh": sh(
          "curl -fsSL http://get.example.com/install.sh | sh",
          "wget -qO- http://example.org/setup | sudo -E bash -s -- --yes",
          "bash <(curl -s http://example.net/bootstrap)",
        ),
      }),
      "shell-curl-pipe-sh",
    );
    expect(findings.map((f) => [f.line, f.severity, f.confidence])).toEqual([
      [2, "high", "high"],
      [3, "high", "high"],
      [4, "high", "high"],
    ]);
  });

  it("ignores https, downloads to files, comments and echoed text", async () => {
    const findings = byRule(
      await run({
        "scripts/install.sh": sh(
          "curl -fsSL https://get.example.com/install.sh | sh",
          "curl -o setup.sh http://example.com/setup.sh",
          "# curl http://example.com/x | sh",
          "echo 'run: curl http://example.com/x | sh'",
          "curl http://example.com/health | grep ok",
        ),
      }),
      "shell-curl-pipe-sh",
    );
    expect(findings).toEqual([]);
  });
});

describe("ShellScriptDetector: shell-hardcoded-credential", () => {
  it("flags secret-named assignments, password flags and connection strings, redacted", async () => {
    const findings = byRule(
      await run({
        "deploy.sh": sh(
          "export DB_PASSWORD=Wq9-zz81-prod",
          "API_TOKEN=tok_8f2b9c7d1e4a",
          "mysql -u root -pS3cr3tRoot app < dump.sql",
          "curl -u admin:adminpass123 https://ci.example.com/job",
          "psql postgres://app:apppass99@localhost:5432/app -c 'select 1'",
        ),
      }),
      "shell-hardcoded-credential",
    );
    expect(findings.map((f) => [f.line, f.severity, f.confidence])).toEqual([
      [2, "high", "medium"],
      [3, "high", "medium"],
      [4, "high", "medium"],
      [5, "high", "medium"],
      [6, "high", "medium"],
    ]);
    const evidence = findings.map((f) => f.evidence).join("\n");
    for (const secret of [
      "Wq9-zz81-prod",
      "tok_8f2b9c7d1e4a",
      "S3cr3tRoot",
      "adminpass123",
      "apppass99",
    ]) {
      expect(evidence).not.toContain(secret);
    }
  });

  it("ignores env references, required-variable checks, placeholders and comments", async () => {
    const findings = byRule(
      await run({
        "deploy.sh": sh(
          ': "${STRIPE_SECRET_KEY:?STRIPE_SECRET_KEY must be set}"',
          'flyctl secrets set STRIPE_SECRET_KEY="${STRIPE_SECRET_KEY}" --app "$APP"',
          'export DB_PASSWORD="$(cat /run/secrets/db)"',
          "API_TOKEN=${API_TOKEN:-}",
          'SECRET_KEY="changeme"',
          "PASSWORD_FILE=/run/secrets/pw",
          "TOKEN_TTL=3600",
          'mysql -u root -p"$MYSQL_PWD" app',
          'docker login --password-stdin <<< "$TOKEN"',
          "# export DB_PASSWORD=Wq9-zz81-prod",
          "psql postgres://app:${PGPASS}@db:5432/app",
          "psql postgres://app:realpass@db.prod.example.com:5432/app",
        ),
      }),
      "shell-hardcoded-credential",
    );
    expect(findings).toEqual([]);
  });

  it("leaves known token formats to the secret detector", async () => {
    const token = "ghp_" + "a".repeat(10) + "B".repeat(10) + "c".repeat(16);
    const findings = byRule(
      await run({ "deploy.sh": sh(`GH_TOKEN=${token}`) }),
      "shell-hardcoded-credential",
    );
    expect(findings).toEqual([]);
  });
});

describe("ShellScriptDetector: general", () => {
  it("only reads shell scripts and skips test fixtures", async () => {
    const body = sh("curl http://x.example.com/i | sh", "API_TOKEN=tok_8f2b9c7d1e4a");
    expect(
      await run({ "scripts/install.ps1": body, Makefile: body, "tests/fixtures/a.sh": body }),
    ).toEqual([]);
  });

  it("gives stable ids and never throws", async () => {
    const files = { "a.bash": sh("curl http://x.example.com/i | sh") };
    const a = await run(files);
    const b = await run(files);
    expect(a).toHaveLength(1);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
    await expect(run({ "b.zsh": "'\"\\\n#\n`" })).resolves.toBeDefined();
  });
});

describe("ShellScriptDetector: review hardening", () => {
  it("stays linear on long lines that almost match", async () => {
    const fit = (unit: string, pre = "", post = ""): string =>
      pre + unit.repeat(Math.floor((9900 - pre.length - post.length) / unit.length)) + post;
    const body = [
      fit("http://a ", "curl "),
      fit("curl ", "", "http://x"),
      fit("bash <(curl ", "", "x"),
      fit("mysql "),
      fit("curl -u a"),
      fit("a.", "", "://x"),
      fit(" -e A=b"),
    ]
      .map((l) => `${l}\n`.repeat(20))
      .join("");
    const started = Date.now();
    const findings = await run({ "slow.sh": body });
    expect(Date.now() - started).toBeLessThan(2000);
    expect(findings).toEqual([]);
  });

  it("still finds a pipe to a shell on a long line", async () => {
    const line = `curl -fsSL http://get.example.com/${"a".repeat(5000)} | sudo env FOO=1 bash -s`;
    const findings = byRule(await run({ "i.sh": sh(line) }), "shell-curl-pipe-sh");
    expect(findings.map((f) => f.line)).toEqual([2]);
  });

  it("does not treat || or a pipe into a non-shell as a pipe to a shell", async () => {
    const findings = byRule(
      await run({
        "i.sh": sh(
          "curl -s http://example.com/x || sh fallback.sh",
          "curl -s http://example.com/x | shasum",
          "curl -s http://example.com/x; sh local.sh",
        ),
      }),
      "shell-curl-pipe-sh",
    );
    expect(findings).toEqual([]);
  });

  it("ignores configuration names that contain a credential word", async () => {
    const findings = byRule(
      await run({
        "deploy.sh": sh(
          "TOKEN_TYPE=Bearer",
          "PASSWORD_POLICY=strict",
          "SECRET_MANAGER=aws-secrets-manager",
          'API_KEY_PREFIX="sk_live"',
          "export TOKEN_ISSUER=https://auth.example.com",
          "AWS_CREDENTIALS_SOURCE=instance-metadata",
          "SECRET_KEY_BASE=development",
          "JWT_ALGORITHM=RS256",
          "GOOGLE_APPLICATION_CREDENTIALS=service-account.json",
          'docker run -e POSTGRES_PASSWORD="$PGPW" postgres:16',
        ),
      }),
      "shell-hardcoded-credential",
    );
    expect(findings).toEqual([]);
  });

  it("reports quoted values, docker -e flags and numbered names", async () => {
    const findings = byRule(
      await run({
        "deploy.sh": sh(
          'DB_PASSWORD="hunter2abc"',
          "docker run -d -e POSTGRES_PASSWORD=Sup3rS3cret99 postgres:16",
          "SECRET_KEY_BASE=8b1f0a9c3d2e7f6a5b4c",
          "ADMIN_TOKEN_2=tok_77ab91cd",
        ),
      }),
      "shell-hardcoded-credential",
    );
    expect(findings.map((f) => f.line)).toEqual([2, 3, 4, 5]);
    expect(findings.map((f) => f.evidence).join("\n")).not.toContain("Sup3rS3cret99");
  });

  it("keeps 25 findings per rule and file, then one medium-confidence summary", async () => {
    const lines = Array.from({ length: 30 }, (_, i) => `API_TOKEN_${i}=tok_8f2b9c7d1e4a${i}`);
    const findings = byRule(await run({ "many.sh": sh(...lines) }), "shell-hardcoded-credential");
    expect(findings).toHaveLength(26);
    const summary = findings[25]!;
    expect(summary).toMatchObject({ line: 27, confidence: "medium", deployBlocking: false });
    expect(summary.title).toContain("5 more in this file");
  });
});
