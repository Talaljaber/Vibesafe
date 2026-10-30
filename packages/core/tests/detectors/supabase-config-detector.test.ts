import { describe, it, expect } from "vitest";
import type { ProjectContext, ScanContext } from "@talaljaber/vibesafe-shared";
import { SupabaseConfigDetector } from "../../src/detectors/supabase-config-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const PROJECT: ProjectContext = {
  framework: "nextjs",
  language: "typescript",
  hasTypeScript: true,
  packageManager: "npm",
  dependencies: {},
  devDependencies: {},
  scripts: {},
  hasGitignore: true,
  hasEnvFile: false,
  hasEnvExample: false,
  hasReadme: true,
  hasTests: false,
};

const createContext = (
  files: Record<string, string>,
  extra: Partial<ScanContext> = {},
): ScanContext => ({
  rootPath: "/fake",
  projectContext: PROJECT,
  files: Object.keys(files),
  config: { rootPath: "/fake" },
  readFile: async (f) => files[f] ?? "",
  ...extra,
});

const FILE = "supabase/config.toml";

/** The default `supabase init` template excerpt; placeholders are replaced per test. */
function template(over: Record<string, string> = {}): string {
  const v = {
    site_url: '"http://127.0.0.1:3000"',
    jwt_expiry: "3600",
    min: "6",
    reqs: '""',
    dbl: "true",
    confirm: "false",
    secure: "false",
    ...over,
  };
  return [
    'project_id = "acme"',
    "[api]",
    "enabled = true",
    "port = 54321",
    "[auth]",
    "enabled = true",
    `site_url = ${v.site_url}`,
    `jwt_expiry = ${v.jwt_expiry}`,
    "enable_refresh_token_rotation = true",
    "enable_signup = true",
    "enable_anonymous_sign_ins = false",
    `minimum_password_length = ${v.min}`,
    `password_requirements = ${v.reqs}`,
    "# [auth.captcha]",
    "# enabled = true",
    '# provider = "hcaptcha"',
    "[auth.email]",
    "enable_signup = true",
    `double_confirm_changes = ${v.dbl}`,
    `enable_confirmations = ${v.confirm}`,
    `secure_password_change = ${v.secure}`,
    'max_frequency = "1s"',
    "[auth.sms.twilio]",
    "enabled = false",
    'auth_token = "env(SUPABASE_AUTH_SMS_TWILIO_AUTH_TOKEN)"',
    "[auth.external.apple]",
    "enabled = false",
    'client_id = ""',
    'secret = "env(SUPABASE_AUTH_EXTERNAL_APPLE_SECRET)"',
    "[studio]",
    'openai_api_key = "env(OPENAI_API_KEY)"',
    "",
  ].join("\n");
}

const HOSTED = template({ site_url: '"https://app.example.com"' });

async function scan(files: Record<string, string>) {
  const findings = await new SupabaseConfigDetector().detect(createContext(files));
  expectRubric(findings);
  return findings;
}

const rules = (fs: { ruleId: string }[]): string[] =>
  fs.map((f) => f.ruleId.replace("security_config/supabase-", "")).sort();

const GATED = ["email-confirm-off", "password-change-unsafe", "signup-no-captcha", "weak-password"];

describe("SupabaseConfigDetector", () => {
  describe("positives", () => {
    it("hosted template: the four template-default rules, naming the host", async () => {
      const f = await scan({ [FILE]: HOSTED });
      expect(rules(f)).toEqual(GATED);
      for (const x of f) {
        expect(x.plainEnglishProblem).toContain("supabase config push");
        if (x.ruleId.endsWith("weak-password")) {
          expect(x.severity).toBe("low");
          expect(x.confidence).toBe("low");
        }
        expect(x.plainEnglishProblem, x.ruleId).toContain("app.example.com");
        expect(x.autoFixAvailable).toBe(false);
      }
    });

    it("local template with a 4-character minimum: weak-password at low/medium", async () => {
      const f = await scan({ [FILE]: template({ min: "4" }) });
      expect(rules(f)).toEqual(["weak-password"]);
      expect(f[0]!.severity).toBe("low");
      expect(f[0]!.confidence).toBe("medium");
    });

    it("long jwt_expiry fires on a local config", async () => {
      const f = await scan({ [FILE]: template({ jwt_expiry: "604_800" }) });
      expect(rules(f)).toEqual(["long-jwt-expiry"]);
      expect(f[0]!.confidence).toBe("high");
      expect(f[0]!.line).toBe(8);
    });

    it("double_confirm_changes = false fires on a local config", async () => {
      const f = await scan({ [FILE]: template({ dbl: "false" }) });
      expect(rules(f)).toEqual(["email-change-unconfirmed"]);
      expect(f[0]!.confidence).toBe("medium");
    });

    it("an explicitly disabled captcha still reports", async () => {
      const f = await scan({ [FILE]: HOSTED + "[auth.captcha]\nenabled = false\n" });
      expect(rules(f)).toContain("signup-no-captcha");
    });

    it("works at a nested path", async () => {
      const f = await scan({ "apps/web/supabase/config.toml": HOSTED });
      expect(rules(f)).toEqual(GATED);
    });

    it("handles an inline comment after the value", async () => {
      const f = await scan({
        [FILE]: HOSTED.replace(
          "enable_confirmations = false",
          "enable_confirmations = false # TODO",
        ),
      });
      expect(rules(f)).toContain("email-confirm-off");
    });

    it("weak-password text mentions empty password_requirements", async () => {
      const f = await scan({ [FILE]: HOSTED });
      const w = f.find((x) => x.ruleId.endsWith("weak-password"))!;
      expect(w.plainEnglishProblem).toContain("password_requirements");
    });

    it("an env(...) site_url counts as hosted", async () => {
      const f = await scan({ [FILE]: template({ site_url: '"env(SITE_URL)"' }) });
      expect(rules(f)).toEqual(GATED);
    });

    it("a remote https additional_redirect_urls entry counts as hosted", async () => {
      const text = template().replace(
        "jwt_expiry = 3600",
        'additional_redirect_urls = [\n  "http://localhost:3000",\n  "https://app.example.com/auth/callback",\n]\njwt_expiry = 3600',
      );
      const f = await scan({ [FILE]: text });
      expect(rules(f)).toEqual(GATED);
    });

    it("minimum_password_length below 6 on hosted config reports once", async () => {
      const f = await scan({
        [FILE]: template({ site_url: '"https://app.example.com"', min: "3" }),
      });
      expect(f.filter((x) => x.ruleId.endsWith("weak-password"))).toHaveLength(1);
    });

    it("ids are stable across runs", async () => {
      const a = await scan({ [FILE]: HOSTED });
      const b = await scan({ [FILE]: HOSTED });
      expect(a.map((x) => x.id)).toEqual(b.map((x) => x.id));
    });
  });

  describe("negatives", () => {
    it("the untouched default template is silent", async () => {
      expect(await scan({ [FILE]: template() })).toEqual([]);
    });

    it("a template with a local site_url and local redirect URLs is silent", async () => {
      const text = template({ site_url: '"http://localhost:3000"' }).replace(
        "jwt_expiry = 3600",
        'additional_redirect_urls = ["https://127.0.0.1:3000", "http://localhost:3000/auth/callback"]\njwt_expiry = 3600',
      );
      expect(await scan({ [FILE]: text })).toEqual([]);
    });

    it("the hardened hosted config is silent", async () => {
      const text =
        template({
          site_url: '"https://app.example.com"',
          min: "12",
          confirm: "true",
          secure: "true",
          dbl: "true",
        }) + '[auth.captcha]\nenabled = true\nprovider = "turnstile"\n';
      expect(await scan({ [FILE]: text })).toEqual([]);
    });

    it("minimum length 8 with empty password_requirements is silent", async () => {
      expect(await scan({ [FILE]: HOSTED.replace("= 6", "= 8") })).not.toContainEqual(
        expect.objectContaining({ ruleId: "security_config/supabase-weak-password" }),
      );
    });

    it("enable_signup = false silences confirm-off and captcha", async () => {
      const f = await scan({
        [FILE]: HOSTED.replace("enable_signup = true", "enable_signup = false"),
      });
      expect(rules(f)).toEqual(["password-change-unsafe", "weak-password"]);
    });

    it("an email-only enable_signup = false also silences them", async () => {
      const text = HOSTED.replace(
        "[auth.email]\nenable_signup = true",
        "[auth.email]\nenable_signup = false",
      );
      expect(rules(await scan({ [FILE]: text }))).toEqual([
        "password-change-unsafe",
        "weak-password",
      ]);
    });

    it("jwt_expiry 3600 and 86400 are silent", async () => {
      for (const v of ["3600", "86400"]) {
        expect(await scan({ [FILE]: template({ jwt_expiry: v }) })).toEqual([]);
      }
    });

    it("commented settings and a commented captcha block do not count", async () => {
      const text = [
        "[auth]",
        'site_url = "https://app.example.com"',
        "# minimum_password_length = 3",
        "# jwt_expiry = 604800",
        "[auth.email]",
        "# enable_confirmations = false",
        "# double_confirm_changes = false",
        "enable_confirmations = true",
        "secure_password_change = true",
        "# [auth.captcha]",
        "# enabled = true",
      ].join("\n");
      expect(rules(await scan({ [FILE]: text }))).toEqual(["signup-no-captcha"]);
    });

    it("a signup flag under the wrong table does not enable email sign-up", async () => {
      const text = [
        "[auth]",
        'site_url = "https://app.example.com"',
        "enable_signup = false",
        "[auth.sms]",
        "enable_signup = true",
      ].join("\n");
      expect(await scan({ [FILE]: text })).toEqual([]);
    });

    it("other files with the same text are ignored", async () => {
      const bad = template({ min: "3", jwt_expiry: "604800", dbl: "false" });
      const f = await scan({
        "config.toml": bad,
        "pyproject.toml": bad,
        "supabase/other.toml": bad,
        "supabase/config.toml.bak": bad,
        "Supabase/config.toml": bad,
        "supabase/seed.sql": "-- enable_confirmations = false\n",
        "lib/a.ts": 'const s = "[auth]\\nenable_confirmations = false"',
      });
      expect(f).toEqual([]);
    });

    it("test paths are skipped unless includeTests", async () => {
      const files = { "tests/supabase/config.toml": template({ min: "3" }) };
      expect(await new SupabaseConfigDetector().detect(createContext(files))).toEqual([]);
      const on = await new SupabaseConfigDetector().detect(
        createContext(files, { config: { rootPath: "/fake", includeTests: true } }),
      );
      expect(on).toHaveLength(1);
    });

    it("a malformed TOML yields no findings and does not throw", async () => {
      const text =
        '[auth\nsite_url = "https://app.example\nminimum_password_length = \nenable_confirmations = [\n';
      await expect(scan({ [FILE]: text })).resolves.toEqual([]);
    });

    it("single-file targetFiles context", async () => {
      const files = { [FILE]: HOSTED, "lib/a.ts": "export {}" };
      const ctx = createContext(files, { targetFiles: [FILE] } as Partial<ScanContext>);
      const f = await new SupabaseConfigDetector().detect(ctx);
      expect(rules(f)).toEqual(GATED);
    });

    it("unparseable and non-http site_url values do not pass the gate", async () => {
      for (const v of ['""', '"ftp://app.example.com"', '"not a url"', "42"]) {
        expect(await scan({ [FILE]: template({ site_url: v }) })).toEqual([]);
      }
    });
  });
});
