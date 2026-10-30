import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { SecretDetector } from "../../src/detectors/secret-detector.js";

const createContext = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake",
  projectContext: {} as never,
  files: Object.keys(files),
  config: { rootPath: "/fake" },
  readFile: async (f) => files[f] ?? "",
});

const TEMPLATE = [
  "[auth.sms.twilio]",
  'auth_token = "env(SUPABASE_AUTH_SMS_TWILIO_AUTH_TOKEN)"',
  "[auth.external.apple]",
  'secret = "env(SUPABASE_AUTH_EXTERNAL_APPLE_SECRET)"',
  "[studio]",
  'openai_api_key = "env(OPENAI_API_KEY)"',
  'password = "env(DB_PASSWORD)"',
  "",
].join("\n");

describe("secret detector and env(...) references", () => {
  it("the Supabase template reports nothing", async () => {
    const f = await new SecretDetector().detect(
      createContext({ "supabase/config.toml": TEMPLATE }),
    );
    expect(f).toEqual([]);
  });

  it("a literal secret in the same file is still reported", async () => {
    const literal = ["Zq8mT4vLw2", "Rb7YnC5xKd"].join("");
    const f = await new SecretDetector().detect(
      createContext({
        "supabase/config.toml": `[auth.external.github]\nsecret = "${literal}"\n`,
      }),
    );
    expect(f).toHaveLength(1);
    expect(f[0]!.ruleId).toBe("secret/sec-generic-secret");
    expect(f[0]!.evidence ?? "").not.toContain(literal);
  });
});
