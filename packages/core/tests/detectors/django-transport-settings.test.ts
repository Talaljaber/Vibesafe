import { describe, it, expect } from "vitest";
import type { ScanContext } from "@vibesafe/shared";
import { DjangoSettingsDetector } from "../../src/detectors/django-settings-detector";
import {
  joinStatement,
  pythonStatements,
  scanPythonLines,
} from "../../src/detectors/utils/python-source";

const detector = new DjangoSettingsDetector();

const ctx = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake",
  projectContext: {} as never,
  files: Object.keys(files),
  config: {} as never,
  readFile: async (f) => files[f] ?? "",
});

const run = (files: Record<string, string>) => detector.detect(ctx(files));
const ruleIds = (f: { ruleId: string }[]) => f.map((x) => x.ruleId);

/** A complete settings module with HTTPS settings, so "missing" rules stay quiet. */
const BASE = [
  "DEBUG = False",
  'ALLOWED_HOSTS = ["example.com"]',
  'INSTALLED_APPS = ["django.contrib.admin"]',
  "SECURE_SSL_REDIRECT = True",
  "SECURE_HSTS_SECONDS = 31536000",
  "",
].join("\n");

describe("Django transport and cookie settings", () => {
  it("flags SECURE_SSL_REDIRECT = False and SECURE_HSTS_SECONDS = 0", async () => {
    const f = await run({
      "mysite/settings.py": BASE + "SECURE_SSL_REDIRECT = False\nSECURE_HSTS_SECONDS = 0\n",
    });
    expect(ruleIds(f)).toEqual([
      "security_config/django-ssl-redirect-off",
      "security_config/django-hsts-off",
    ]);
    expect(f.map((x) => [x.line, x.severity])).toEqual([
      [6, "medium"],
      [7, "low"],
    ]);
  });

  it("does not flag enabled or env-driven HTTPS settings", async () => {
    const f = await run({
      "mysite/settings.py":
        BASE +
        'SECURE_SSL_REDIRECT = env.bool("SSL_REDIRECT", default=True)\n' +
        "SECURE_HSTS_SECONDS = 3600\n" +
        "SECURE_HSTS_SECONDS = 60 * 60\n" +
        'SECURE_HSTS_SECONDS = int(os.environ.get("HSTS", "0"))\n' +
        "SECURE_SSL_REDIRECT = not DEBUG\n",
    });
    expect(f).toHaveLength(0);
  });

  it("flags SESSION_COOKIE_HTTPONLY = False and ALLOW* X_FRAME_OPTIONS", async () => {
    const f = await run({
      "mysite/settings.py":
        BASE +
        "SESSION_COOKIE_HTTPONLY = False\n" +
        'X_FRAME_OPTIONS = "ALLOWALL"\n' +
        "X_FRAME_OPTIONS = 'ALLOW-FROM https://partner.example'\n" +
        "SESSION_COOKIE_HTTPONLY = True\n" +
        'X_FRAME_OPTIONS = "DENY"\n' +
        'X_FRAME_OPTIONS = "SAMEORIGIN"\n',
    });
    expect(ruleIds(f)).toEqual([
      "security_config/django-session-cookie-httponly-off",
      "security_config/django-x-frame-options-allow",
      "security_config/django-x-frame-options-allow",
    ]);
  });

  it("sanity-checks SECURE_PROXY_SSL_HEADER", async () => {
    const f = await run({
      "mysite/settings.py":
        BASE +
        'SECURE_PROXY_SSL_HEADER = ("X-Forwarded-Proto", "https")\n' +
        'SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "http")\n' +
        "SECURE_PROXY_SSL_HEADER = ('http_x_forwarded_proto', 'https')\n" +
        'SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")\n' +
        "SECURE_PROXY_SSL_HEADER = (\n    'HTTP_X_FORWARDED_PROTO',\n    'https',\n)\n" +
        "SECURE_PROXY_SSL_HEADER = None\n",
    });
    expect(f.map((x) => x.line)).toEqual([6, 7, 8]);
    expect(new Set(ruleIds(f))).toEqual(new Set(["security_config/django-proxy-ssl-header"]));
    expect(f[0]!.severity).toBe("low");
  });

  it("skips transport rules in dev/local/test settings modules", async () => {
    const bad =
      "SECURE_SSL_REDIRECT = False\nSECURE_HSTS_SECONDS = 0\nSESSION_COOKIE_HTTPONLY = False\n" +
      'X_FRAME_OPTIONS = "ALLOWALL"\nSECURE_PROXY_SSL_HEADER = ("X", "https")\n';
    const f = await run({
      "mysite/settings/dev.py": bad,
      "mysite/settings_local.py": bad,
      "mysite/settings/test.py": bad,
    });
    expect(f).toHaveLength(0);
  });

  it("skips insecure values inside a top-level `if DEBUG:` block, not in its else branch", async () => {
    const f = await run({
      "mysite/settings.py":
        BASE +
        "if DEBUG:\n" +
        "    SECURE_SSL_REDIRECT = False\n" +
        "    SESSION_COOKIE_SECURE = False\n" +
        "    CORS_ALLOW_ALL_ORIGINS = True\n" +
        "else:\n" +
        "    SECURE_SSL_REDIRECT = False\n",
    });
    expect(f.map((x) => [x.ruleId, x.line])).toEqual([
      ["security_config/django-ssl-redirect-off", 11],
    ]);
  });
});

describe("Django missing HTTPS settings", () => {
  const core = 'DEBUG = False\nALLOWED_HOSTS = ["example.com"]\nINSTALLED_APPS = []\n';

  it("reports missing SECURE_SSL_REDIRECT and SECURE_HSTS_SECONDS once, on the base module", async () => {
    const f = await run({ "mysite/settings.py": core });
    expect(ruleIds(f)).toEqual([
      "security_config/django-ssl-redirect-missing",
      "security_config/django-hsts-missing",
    ]);
    expect(f.every((x) => x.severity === "low" && x.line === undefined)).toBe(true);
    expect(f[0]!.file).toBe("mysite/settings.py");
    expect(f[0]!.id).toMatch(/^CFG-[0-9a-f]{10}$/);
  });

  it("is satisfied by any non-dev settings module, and prefers the production module", async () => {
    const split = await run({
      "mysite/settings/base.py": core,
      "mysite/settings/production.py":
        "from .base import *\nSECURE_SSL_REDIRECT = True\nSECURE_HSTS_SECONDS = 3600\n",
    });
    expect(split).toHaveLength(0);

    const prodLacks = await run({
      "mysite/settings/base.py": core,
      "mysite/settings/prod.py": "from .base import *\nDEBUG = False\n",
      "mysite/settings/dev.py": "SECURE_SSL_REDIRECT = False\nSECURE_HSTS_SECONDS = 0\n",
    });
    expect(ruleIds(prodLacks)).toEqual([
      "security_config/django-ssl-redirect-missing",
      "security_config/django-hsts-missing",
    ]);
    expect(prodLacks.every((x) => x.file === "mysite/settings/prod.py")).toBe(true);

    const inIfBlock = await run({
      "mysite/settings.py": core + "if not DEBUG:\n    SECURE_SSL_REDIRECT = True\n",
    });
    expect(ruleIds(inIfBlock)).toEqual(["security_config/django-hsts-missing"]);
  });

  it("does not report missing settings for partial or dev-only settings modules", async () => {
    expect(await run({ "mysite/settings.py": "DEBUG = False\n" })).toHaveLength(0);
    expect(
      await run({ "mysite/settings.py": 'ALLOWED_HOSTS = ["a"]\nDEBUG = False\n' }),
    ).toHaveLength(0);
    expect(await run({ "mysite/settings/local.py": core })).toHaveLength(0);
    expect(await run({ "mysite/conf.py": core })).toHaveLength(0);
  });
});

describe("Django settings: continuation lines and triple-quoted strings", () => {
  it("joins backslash-continued values", async () => {
    const f = await run({
      "a/settings.py": 'ALLOWED_HOSTS = \\\n    ["*"]\nDEBUG = \\\n    True\n',
    });
    expect(f.map((x) => [x.ruleId, x.line])).toEqual([
      ["security_config/django-allowed-hosts-wildcard", 1],
      ["security_config/django-debug-true", 3],
    ]);
  });

  it("flags a backslash-continued and a multi-line triple-quoted SECRET_KEY, redacted", async () => {
    const key = "django-insecure-abcdefghijklmnopqrstuvwxyz0123456789";
    const f = await run({
      "a/settings.py": `SECRET_KEY = \\\n    "${key}"\nSECRET_KEY = """\n${key}\n"""\nDEBUG = True\n`,
    });
    expect(f.map((x) => [x.ruleId, x.line])).toEqual([
      ["secret/django-secret-key", 1],
      ["secret/django-secret-key", 3],
      ["security_config/django-debug-true", 6],
    ]);
    for (const x of f) expect(x.evidence ?? "").not.toContain(key);
  });

  it("checks code that follows a multi-line string and ignores rule text inside it", async () => {
    const f = await run({
      "a/settings.py": 'NOTE = """\nDEBUG = True\nALLOWED_HOSTS = ["*"]\n"""\nDEBUG = True\n',
    });
    expect(f.map((x) => x.line)).toEqual([5]);
  });

  it("does not treat a blank triple-quoted SECRET_KEY as a secret", async () => {
    expect(await run({ "a/settings.py": 'SECRET_KEY = """\n   \n"""\n' })).toHaveLength(0);
  });
});

describe("python-source helpers", () => {
  it("joins brackets, backslashes and triple-quoted strings into statements", () => {
    const lines = scanPythonLines(
      'A = [\n  1,\n]\nB = 1 + \\\n  2\nC = """x\ny"""\n# comment\nD = 4  # trailing\n',
    );
    const stmts = pythonStatements(lines).map((s) => [s.start, s.end, s.stmt]);
    expect(stmts).toEqual([
      [0, 2, "A = [ 1, ]"],
      [3, 4, "B = 1 +  2"],
      [5, 6, 'C = """x\ny"""'],
      [8, 8, "D = 4  "],
    ]);
    expect(joinStatement(lines, 99)).toEqual({ stmt: "", end: 99 });
  });

  it("tracks indentation and does not treat a backslash in a comment as continuation", () => {
    const lines = scanPythonLines("if x:\n    y = 1  # path\\\nz = 2\n");
    expect(lines.map((l) => l.indent)).toEqual([0, 4, 0, 0]);
    expect(lines[1]!.backslash).toBe(false);
    expect(pythonStatements(lines).map((s) => s.start)).toEqual([0, 1, 2]);
  });
});
