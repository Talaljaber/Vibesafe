import { describe, it, expect } from "vitest";
import { SECRET_PATTERNS, matchSecretPattern } from "../../src/detectors/patterns/secret-patterns";
import { sanitizeEvidence } from "../../src/detectors/utils/sanitize-evidence";

const SECRET = "q8Zr3KpL0vNx5TdW2yBc7HsJ4mUe9AfGaR1oXiQt";
const ACCESS_ID = "AKIAQ3ZR7KPL0VNX5TDW";

const secretPattern = SECRET_PATTERNS.find((p) => p.id === "sec-aws-secret-key")!;
const idPattern = SECRET_PATTERNS.find((p) => p.id === "sec-aws-access-key")!;

const hitsSecret = (line: string) => matchSecretPattern(secretPattern, line) !== null;
const hitsId = (line: string) => matchSecretPattern(idPattern, line) !== null;

describe("AWS access key ids", () => {
  it.each(["AKIA", "ASIA", "ABIA", "ACCA"])("detects %s prefix", (prefix) => {
    expect(hitsId(`const id = "${prefix}Q3ZR7KPL0VNX5TDW";`)).toBe(true);
  });

  it("ignores documentation examples and placeholders", () => {
    expect(hitsId("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")).toBe(false);
    expect(hitsId("id: AKIAXXXXXXXXXXXXXXXX")).toBe(false);
  });

  it("ignores wrong lengths and embedded matches", () => {
    expect(hitsId("AKIAQ3ZR7KPL0VNX5TD")).toBe(false);
    expect(hitsId("AKIAQ3ZR7KPL0VNX5TDWEXTRA")).toBe(false);
    expect(hitsId("akiaq3zr7kpl0vnx5tdw")).toBe(false);
  });
});

describe("AWS secret access keys", () => {
  it.each([
    ["python assignment", `aws_secret_access_key = "${SECRET}"`],
    ["env line", `AWS_SECRET_ACCESS_KEY=${SECRET}`],
    ["exported env", `export AWS_SECRET_ACCESS_KEY='${SECRET}'`],
    ["credentials file", `aws_secret_access_key=${SECRET}`],
    ["object literal", `  secretAccessKey: "${SECRET}",`],
    ["awsSecretKey", `const awsSecretKey = '${SECRET}';`],
    ["JSON", `  "secretAccessKey": "${SECRET}"`],
    ["JSON upper", `{"AWS_SECRET_ACCESS_KEY": "${SECRET}"}`],
    ["YAML", `AWS_SECRET_ACCESS_KEY: ${SECRET}`],
    ["SDK credentials", `credentials: { accessKeyId: "${ACCESS_ID}", secretAccessKey: "${SECRET}" }`],
    ["slash and plus", `secretAccessKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYq8Zr3KpL0v"`],
  ])("detects %s", (_name, line) => {
    expect(hitsSecret(line)).toBe(true);
  });

  it("redacts only the value in evidence", () => {
    const out = sanitizeEvidence(`AWS_SECRET_ACCESS_KEY=${SECRET}`);
    expect(out).not.toContain(SECRET);
    expect(out).toContain("AWS_SECRET_ACCESS_KEY=");
  });

  it("ignores the AWS documentation example", () => {
    expect(hitsSecret("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")).toBe(false);
  });

  it.each([
    ["EXAMPLE marker", `AWS_SECRET_ACCESS_KEY=Q3zR7kPl0vNx5TdW2yBc7HsJ4mUe9AfGEXAMPLE1`],
    ["xxxx", `AWS_SECRET_ACCESS_KEY=${"x".repeat(40)}`],
    ["repeated pattern", `AWS_SECRET_ACCESS_KEY=${"xXxX".repeat(10)}`],
    ["low entropy", `AWS_SECRET_ACCESS_KEY=${"ab12".repeat(10)}`],
    ["all digits", `AWS_SECRET_ACCESS_KEY=${"1234567890".repeat(4)}`],
    ["all letters", `AWS_SECRET_ACCESS_KEY=${"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"}`],
    ["your-placeholder", `aws_secret_access_key = "your-aws-secret-access-key"`],
    ["env reference", `secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY`],
    ["too short", `AWS_SECRET_ACCESS_KEY=${SECRET.slice(0, 39)}`],
    ["too long", `AWS_SECRET_ACCESS_KEY=${SECRET}Z`],
    ["empty", `AWS_SECRET_ACCESS_KEY=`],
    ["no assignment", `// set aws_secret_access_key to ${SECRET}`],
    ["unrelated key name", `const apiKey = "${SECRET}";`],
  ])("ignores %s", (_name, line) => {
    expect(hitsSecret(line)).toBe(false);
  });
});
