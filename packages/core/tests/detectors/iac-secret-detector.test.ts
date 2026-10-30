import { describe, it, expect } from "vitest";
import type { Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { IacSecretDetector } from "../../src/detectors/iac-secret-detector.js";
import { expectRubric } from "../helpers/rubric.js";

// Built from parts so the source never holds a complete token-shaped literal.
const STRIPE_LIVE = ["sk", "live", "51NqZxKbT3mLp4TrVw7YbC3dHs9JfGa"].join("_");
const AWS_KEY = ["AKIA", "QX4MZ2PLR9WD3K7A"].join("");

const createContext = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake",
  projectContext: {} as ScanContext["projectContext"],
  files: Object.keys(files),
  config: { rootPath: "/fake" },
  readFile: async (f) => files[f] ?? "",
});

const run = async (files: Record<string, string>): Promise<Finding[]> => {
  const findings = await new IacSecretDetector().detect(createContext(files));
  expectRubric(findings);
  const again = await new IacSecretDetector().detect(createContext(files));
  expect(again.map((f) => f.id)).toEqual(findings.map((f) => f.id));
  return findings;
};

const y = (...lines: string[]): string => lines.join("\n") + "\n";
const b64 = (s: string): string => Buffer.from(s, "utf8").toString("base64");
const secret = (...data: string[]): string =>
  y("apiVersion: v1", "kind: Secret", "metadata:", "  name: creds", "type: Opaque", ...data);

describe("IacSecretDetector: secret/k8s-secret-manifest", () => {
  it("flags base64 values with the key and <redacted>, never the decoded value", async () => {
    const value = "Zq8mT4vLw2Rb7YnC5dHs1";
    const f = await run({
      "k8s/secret.yaml": secret("data:", `  SESSION_PEPPER: ${b64(value)}`),
    });
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({
      ruleId: "secret/k8s-secret-manifest",
      line: 7,
      severity: "high",
      confidence: "high",
    });
    const dump = JSON.stringify(f);
    expect(dump).not.toContain(value);
    expect(dump).not.toContain(b64(value));
    expect(f[0]!.evidence).toBe("SESSION_PEPPER: <redacted>");
  });

  it("is critical for a credentialed URL and a specific secret format", async () => {
    const f = await run({
      "k8s/secret.yaml": secret(
        "data:",
        `  DATABASE_URL: ${b64("postgresql://app:Pr0dPassw0rd@db.example.com:5432/shop")}`,
        `  STRIPE: ${b64(STRIPE_LIVE)}`,
      ),
    });
    expect(f.map((x) => x.severity)).toEqual(["critical", "critical"]);
    expect(f[0]!.deployBlocking).toBe(true);
  });

  it("flags stringData literals but leaves lines the secret detector owns", async () => {
    const f = await run({
      "k8s/secret.yaml": secret(
        "stringData:",
        "  ADMIN_PASSWORD: Tr0ub4dor-and-more",
        `  STRIPE_KEY: ${STRIPE_LIVE}`,
      ),
    });
    expect(f.map((x) => x.line)).toEqual([7]);
  });

  it("reads block scalars in stringData", async () => {
    const f = await run({
      "k8s/secret.yaml": secret(
        "stringData:",
        "  config.toml: |",
        '    password = "hunter2hunter2"',
      ),
    });
    expect(f).toHaveLength(1);
  });

  it.each([
    ["empty data", ["data: {}"]],
    ["empty value", ["data:", '  TOKEN: ""']],
    ["short value", ["data:", `  PORT: ${b64("5432")}`]],
    ["placeholder", ["data:", `  PASSWORD: ${b64("changeme")}`]],
    ["not base64", ["data:", "  TOKEN: not base64 at all!"]],
    ["binary", ["data:", "  BLOB: /////////////w=="]],
    ["template", ["stringData:", "  PASSWORD: {{ .Values.password }}"]],
    ["public certificate", ["data:", `  tls.crt: ${b64("-----BEGIN CERTIFICATE-----\nMIIB...")}`]],
  ])("is silent for %s", async (_n, data) => {
    expect(await run({ "k8s/secret.yaml": secret(...data) })).toEqual([]);
  });

  it("is silent for SealedSecret, ExternalSecret and other kinds", async () => {
    const sealed = y(
      "apiVersion: bitnami.com/v1alpha1",
      "kind: SealedSecret",
      "spec:",
      "  encryptedData:",
      "    TOKEN: AgBy3i4OJSWK+PiTySYZZA9rO43cGDEq",
      "  data:",
      `    OTHER: ${b64("Zq8mT4vLw2Rb7YnC5dHs1")}`,
    );
    const external = y(
      "apiVersion: external-secrets.io/v1beta1",
      "kind: ExternalSecret",
      "spec:",
      "  data:",
      "    - secretKey: TOKEN",
    );
    const cm = y(
      "apiVersion: v1",
      "kind: ConfigMap",
      "data:",
      `  OTHER: ${b64("Zq8mT4vLw2Rb7YnC5dHs1")}`,
    );
    expect(await run({ "k8s/a.yaml": sealed, "k8s/b.yaml": external, "k8s/c.yaml": cm })).toEqual(
      [],
    );
  });

  it("ignores yaml outside manifest directories and documents without apiVersion", async () => {
    const text = secret("data:", `  SESSION_PEPPER: ${b64("Zq8mT4vLw2Rb7YnC5dHs1")}`);
    expect(await run({ "config.yml": text, "src/app.ts": text })).toEqual([]);
    expect(
      await run({
        "k8s/x.yaml": y("kind: Secret", "data:", `  A: ${b64("Zq8mT4vLw2Rb7YnC5dHs1")}`),
      }),
    ).toEqual([]);
  });
});

describe("IacSecretDetector: secret/k8s-configmap-credential", () => {
  const cm = (...data: string[]): string =>
    y("apiVersion: v1", "kind: ConfigMap", "metadata:", "  name: cfg", "data:", ...data);

  it("flags credential-named keys with literal values as high/medium", async () => {
    const f = await run({
      "k8s/cm.yaml": cm(
        "  PARTNER_AUTH_TOKEN: 8d3f1a6c92be47055e1b09d7a4c63f28",
        "  db_password: 'Zq8mT4vLw2Rb7YnC5'",
        "  QUEUE_URL: amqp://worker:Zq8mT4vLw2Rb@mq.example.com:5672",
      ),
    });
    expect(f.map((x) => [x.ruleId, x.line, x.severity, x.confidence])).toEqual([
      ["secret/k8s-configmap-credential", 6, "high", "medium"],
      ["secret/k8s-configmap-credential", 7, "high", "medium"],
      ["secret/k8s-configmap-credential", 8, "high", "medium"],
    ]);
    expect(JSON.stringify(f)).not.toContain("8d3f1a6c92be47055e1b09d7a4c63f28");
  });

  it.each([
    ["non-credential keys", ["  S3_BUCKET: shop-documents", "  TWILIO_ACCOUNT_SID: ACd29e47b6c1f"]],
    ["placeholder", ["  API_TOKEN: changeme"]],
    ["template", ["  API_TOKEN: {{ .Values.token }}"]],
    ["reference", ["  API_TOKEN: ${API_TOKEN}"]],
    ["url without a password", ["  DATABASE_URL: postgres://db.example.com:5432/shop"]],
    ["config word", ["  TOKEN_TYPE: bearer", "  PASSWORD_POLICY: strict"]],
    ["empty", ["  API_TOKEN: ''"]],
  ])("is silent for %s", async (_n, data) => {
    expect(await run({ "k8s/cm.yaml": cm(...data) })).toEqual([]);
  });
});

describe("IacSecretDetector: secret/terraform-literal-credential", () => {
  it("flags credential-named assignments in tfvars", async () => {
    const f = await run({
      "prod.tfvars": y(
        'region = "us-east-1"',
        'db_password = "Zq8mT4vLw2Rb7YnC5"',
        'api_token = "x9Kp2LmQ7vRt4Wz"',
      ),
    });
    expect(f.map((x) => [x.ruleId, x.line, x.severity, x.confidence])).toEqual([
      ["secret/terraform-literal-credential", 2, "high", "high"],
      ["secret/terraform-literal-credential", 3, "high", "high"],
    ]);
    expect(f[0]!.evidence).toBe("db_password = <redacted>");
    expect(JSON.stringify(f)).not.toContain("Zq8mT4vLw2Rb7YnC5");
  });

  it("treats KMS aliases and ARNs as references, not secrets", async () => {
    const f = await run({
      "main.tf": y(
        'resource "aws_s3_bucket_server_side_encryption_configuration" "a" {',
        '  encryption_key = "alias/aws/s3"',
        '  secret_key_ref = "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd"',
        "}",
      ),
    });
    expect(f).toEqual([]);
  });

  it("reports a non-credential key of a Secret as medium and a credential key as high", async () => {
    const f = await run({
      "k8s/secret.yaml": secret(
        "stringData:",
        "  host: db-primary.internal.example.com",
        "  password: Zq8mT4vLw2Rb7YnC5dHs1",
      ),
    });
    expect(f.map((x) => [x.line, x.severity])).toEqual([
      [7, "medium"],
      [8, "high"],
    ]);
  });

  it("flags variable defaults and resource attributes in .tf files", async () => {
    const f = await run({
      "main.tf": y(
        'variable "db_password" {',
        "  type = string",
        '  default = "Zq8mT4vLw2Rb7YnC5"',
        "}",
        'resource "aws_db_instance" "main" {',
        '  password = "Hq3nRb8YwT5vLm2Z"',
        "}",
      ),
    });
    expect(f.map((x) => x.line)).toEqual([3, 6]);
  });

  it("works for auto.tfvars too", async () => {
    const f = await run({ "env.auto.tfvars": y('secret_key = "Zq8mT4vLw2Rb7YnC5dHs"') });
    expect(f).toHaveLength(1);
  });

  it.each([
    ["variable reference", "password = var.db_password"],
    ["interpolation", 'password = "${var.db_password}"'],
    ["resource reference", "password = aws_secretsmanager_secret_version.db.secret_string"],
    ["changeme", 'password = "changeme"'],
    ["angle placeholder", 'password = "<password>"'],
    ["comment", '# password = "Zq8mT4vLw2Rb7YnC5"'],
    ["non-credential name", 'username = "Zq8mT4vLw2Rb7YnC5"'],
    ["config name", 'token_type = "Zq8mT4vLw2Rb7YnC5"'],
    ["boolean", "enable_password_policy = true"],
  ])("is silent for %s", async (_n, line) => {
    expect(
      await run({ "main.tf": y('resource "x" "y" {', `  ${line}`, "}"), "a.tfvars": y(line) }),
    ).toEqual([]);
  });

  it("is silent for sensitive variables without a default and empty defaults", async () => {
    const tf = y(
      'variable "db_password" {',
      "  type = string",
      "  sensitive = true",
      "}",
      'variable "api_token" {',
      '  default = ""',
      "}",
    );
    expect(await run({ "variables.tf": tf })).toEqual([]);
  });

  it("leaves specific token formats to the secret detector", async () => {
    const f = await run({ "prod.tfvars": y(`aws_access_key = "${AWS_KEY}"`) });
    expect(f).toEqual([]);
  });
});

describe("IacSecretDetector: robustness", () => {
  it("ignores other file kinds and never throws on junk", async () => {
    const f = await run({
      "src/app.ts": 'const password = "Zq8mT4vLw2Rb7YnC5"',
      "docker-compose.yml": y(
        "services:",
        "  db:",
        "    environment:",
        "      PASSWORD: Zq8mT4vLw2Rb7YnC5",
      ),
      "x.tf": 'password = "\n{{{{ <<EOF',
      "k8s/y.yaml": "apiVersion: v1\nkind: Secret\ndata:\n  - : :\n\t: x",
    });
    expect(f).toEqual([]);
  });
});
