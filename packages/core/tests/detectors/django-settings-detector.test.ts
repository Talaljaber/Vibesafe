import { describe, it, expect } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { DjangoSettingsDetector } from "../../src/detectors/django-settings-detector";
import { SecretDetector } from "../../src/detectors/secret-detector";
import { ProjectContextBuilder } from "../../src/scanner/project-context";
import { createDefaultRegistry } from "../../src/scanner/detector-registry";
import { ScannerPipeline } from "../../src/scanner/pipeline";
import { FileDiscovery } from "../../src/scanner/file-discovery";
import { CATEGORY_MULTIPLIERS, CATEGORY_PREFIX } from "@talaljaber/vibesafe-shared";

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

describe("DjangoSettingsDetector", () => {
  it("reports csrf_exempt in a multi-line urlpatterns list once, at the inner line", async () => {
    const f = await run({
      "app/urls.py": 'urlpatterns = [\n    path("hook/", csrf_exempt(hook_view)),\n]\n',
    });
    expect(f).toHaveLength(1);
    expect(f[0]!.ruleId).toBe("security_config/django-csrf-exempt");
    expect(f[0]!.line).toBe(2);
  });

  it("does not treat keyword arguments inside a call as settings assignments", async () => {
    const f = await run({ "mysite/settings.py": "X = foo(\n    DEBUG = True,\n)\n" });
    expect(f).toHaveLength(0);
  });
  it("flags DEBUG = True as high in a production settings file", async () => {
    const f = await run({ "mysite/settings.py": "DEBUG = True\n" });
    expect(f).toHaveLength(1);
    expect(f[0]!.ruleId).toBe("security_config/django-debug-true");
    expect(f[0]!.severity).toBe("high");
    expect(f[0]!.category).toBe("security_config");
    expect(f[0]!.line).toBe(1);
  });

  it("downgrades DEBUG = True to low in dev-only settings files", async () => {
    const f = await run({
      "mysite/settings/dev.py": "DEBUG = True",
      "mysite/settings_local.py": "DEBUG = True",
      "mysite/settings/base.py": "DEBUG = True",
    });
    const bySev = Object.fromEntries(f.map((x) => [x.file, x.severity]));
    expect(bySev["mysite/settings/dev.py"]).toBe("low");
    expect(bySev["mysite/settings_local.py"]).toBe("low");
    expect(bySev["mysite/settings/base.py"]).toBe("high");
  });

  it("does not flag DEBUG = False or env-driven DEBUG", async () => {
    const f = await run({
      "a/settings.py": `DEBUG = False\nDEBUG = os.environ.get("DEBUG") == "1"\nDEBUG = env.bool("DEBUG", default=False)\n# DEBUG = True`,
    });
    expect(f).toHaveLength(0);
  });

  it("flags a hardcoded SECRET_KEY as critical and redacts the value", async () => {
    const key = "django-insecure-abcdefghijklmnopqrstuvwxyz0123456789";
    const f = await run({ "mysite/settings.py": `SECRET_KEY = '${key}'` });
    expect(f).toHaveLength(1);
    expect(f[0]!.ruleId).toBe("secret/django-secret-key");
    expect(f[0]!.severity).toBe("critical");
    expect(f[0]!.category).toBe("secret");
    expect(f[0]!.deployBlocking).toBe(true);
    expect(f[0]!.evidence).not.toContain(key);
    expect(f[0]!.id).toMatch(/^SEC-/);
  });

  it("does not flag SECRET_KEY read from the environment or empty", async () => {
    const f = await run({
      "a/settings.py": [
        `SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]`,
        `SECRET_KEY = os.getenv("SECRET_KEY")`,
        `SECRET_KEY = env("SECRET_KEY")`,
        `SECRET_KEY = ""`,
        `SECRET_KEY_FALLBACKS = ["x"]`,
      ].join("\n"),
    });
    expect(f).toHaveLength(0);
  });

  it("does not look for SECRET_KEY outside settings modules", async () => {
    const f = await run({ "app/models.py": `SECRET_KEY = "abc123abc123"` });
    expect(f).toHaveLength(0);
  });

  it("flags ALLOWED_HOSTS wildcard but not explicit hosts", async () => {
    const f = await run({
      "a/settings.py": `ALLOWED_HOSTS = ["*"]`,
      "b/settings.py": `ALLOWED_HOSTS = ['example.com', 'www.example.com']`,
      "c/settings.py": `ALLOWED_HOSTS = ('api.example.com', '*')`,
      "d/settings.py": `ALLOWED_HOSTS = []`,
    });
    expect(f.map((x) => x.file).sort()).toEqual(["a/settings.py", "c/settings.py"]);
    expect(f.every((x) => x.severity === "medium")).toBe(true);
  });

  it("flags CORS allow-all in both spellings", async () => {
    const f = await run({
      "a/settings.py": `CORS_ALLOW_ALL_ORIGINS = True\nCORS_ORIGIN_ALLOW_ALL = True\nCORS_ALLOW_ALL_ORIGINS = False`,
    });
    expect(ruleIds(f)).toEqual([
      "security_config/django-cors-allow-all",
      "security_config/django-cors-allow-all",
    ]);
  });

  it("flags insecure cookies but not secure ones", async () => {
    const f = await run({
      "a/settings.py": `SESSION_COOKIE_SECURE = False\nCSRF_COOKIE_SECURE = False  # dev\nSESSION_COOKIE_SECURE = True\nCSRF_COOKIE_SECURE = True`,
    });
    expect(f).toHaveLength(2);
    expect(f[0]!.ruleId).toBe("security_config/django-insecure-cookie");
    expect(f[1]!.line).toBe(2);
  });

  it("flags @csrf_exempt on views in any .py file", async () => {
    const f = await run({
      "shop/views.py": [
        "from django.views.decorators.csrf import csrf_exempt",
        "",
        "@csrf_exempt",
        "def hook(request):",
        "    pass",
      ].join("\n"),
      "shop/urls.py": `urlpatterns = [path("x/", csrf_exempt(view))]`,
      "shop/api.py": `@method_decorator(csrf_exempt, name="dispatch")\nclass V(View): pass`,
    });
    expect(f).toHaveLength(3);
    expect(f.find((x) => x.file === "shop/views.py")!.line).toBe(3);
    expect(f.every((x) => x.ruleId === "security_config/django-csrf-exempt")).toBe(true);
  });

  it("ignores csrf_exempt imports, definitions and comments", async () => {
    const f = await run({
      "a/views.py": [
        "from django.views.decorators.csrf import csrf_exempt",
        "# @csrf_exempt is dangerous",
        "def csrf_exempt_helper(): pass",
        "def csrf_exempt(view): pass",
      ].join("\n"),
    });
    expect(f).toHaveLength(0);
  });

  it("does not run on non-python files and tolerates CRLF", async () => {
    const f = await run({
      "settings.js": "DEBUG = True",
      "mysite/settings.py": "DEBUG = True\r\nALLOWED_HOSTS = ['*']\r\n",
    });
    expect(f).toHaveLength(2);
  });

  it("produces stable ids", async () => {
    const a = await run({ "s/settings.py": "DEBUG = True" });
    const b = await run({ "s/settings.py": "DEBUG = True" });
    expect(a[0]!.id).toBe(b[0]!.id);
    expect(a[0]!.id).toMatch(/^CFG-/);
  });

  it("is registered by default", () => {
    const ids = createDefaultRegistry()
      .getDetectors()
      .map((d) => d.id);
    expect(ids).toContain("django-settings-detector");
  });
});

describe("secret patterns on .py files", () => {
  it("SecretDetector flags a known key in a Python file", async () => {
    const key = "sk_live_" + "a1B2c3D4e5F6g7H8i9J0k1L2";
    const f = await new SecretDetector().detect(
      ctx({ "app/payments.py": `STRIPE_KEY = "${key}"` }),
    );
    expect(f).toHaveLength(1);
    expect(f[0]!.ruleId).toBe("secret/sec-stripe-live-secret");
    expect(f[0]!.file).toBe("app/payments.py");
  });

  it("SecretDetector does not double-report a hardcoded SECRET_KEY", async () => {
    const files = {
      "mysite/settings.py": 'SECRET_KEY = "django-insecure-abcdefghijklmnopqrstuvwxyz0123456789"',
    };
    expect(await new SecretDetector().detect(ctx(files))).toHaveLength(0);
    expect(ruleIds(await run(files))).toEqual(["secret/django-secret-key"]);
  });
});

describe("Django project detection", () => {
  async function project(files: Record<string, string>) {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "vs-django-"));
    for (const [name, content] of Object.entries(files)) {
      await fs.writeFile(path.join(dir, name), content);
    }
    try {
      return await new ProjectContextBuilder(dir).build();
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  }

  it("detects manage.py", async () => {
    const c = await project({ "manage.py": "#!/usr/bin/env python" });
    expect(c.framework).toBe("django");
    expect(c.language).toBe("python");
  });

  it("detects django in requirements.txt and pyproject.toml", async () => {
    expect((await project({ "requirements.txt": "Django==4.2\npsycopg2" })).framework).toBe(
      "django",
    );
    expect(
      (await project({ "pyproject.toml": '[project]\ndependencies = ["django>=4.2"]' })).framework,
    ).toBe("django");
  });

  it("does not treat unrelated python projects as Django", async () => {
    expect(
      (await project({ "requirements.txt": "flask\ndjangorestframework-stubs" })).framework,
    ).toBe("unknown");
    expect((await project({})).framework).toBe("unknown");
  });

  it("keeps the JS framework when package.json is present", async () => {
    const c = await project({
      "package.json": JSON.stringify({ dependencies: { next: "14.0.0" } }),
      "manage.py": "",
    });
    expect(c.framework).toBe("nextjs");
  });
});

describe("DjangoSettingsDetector, real-world forms", () => {
  const key = "django-insecure-abcdefghijklmnopqrstuvwxyz0123456789";
  const secretFiles = (src: string) => run({ "mysite/settings.py": src });

  it.each([
    [`SECRET_KEY = os.environ.get("SECRET_KEY", "${key}")`],
    [`SECRET_KEY = env("SECRET_KEY", default="${key}")`],
    [`SECRET_KEY = config("SECRET_KEY", default="${key}")`],
    [`SECRET_KEY = os.getenv("SECRET_KEY", fallback="${key}")`],
    [`SECRET_KEY = os.environ.get(\n    "SECRET_KEY",\n    "${key}",\n)`],
  ])("flags a hardcoded fallback: %s", async (src) => {
    const f = await secretFiles(src);
    expect(ruleIds(f)).toEqual(["secret/django-secret-key-fallback"]);
    expect(f[0]!.severity).toBe("high");
    expect(f[0]!.evidence).not.toContain(key);
    expect(f[0]!.line).toBe(1);
  });

  it.each([
    [`SECRET_KEY = r'${key}'`],
    [`SECRET_KEY = b"${key}"`],
    [`SECRET_KEY = """${key}"""`],
    [`SECRET_KEY = (\n    "${key}"\n)`],
    [`SECRET_KEY = ('${key}'\n  'more')`],
  ])("flags a literal with prefix, triple quotes or parentheses: %s", async (src) => {
    const f = await secretFiles(src);
    expect(ruleIds(f)).toEqual(["secret/django-secret-key"]);
    expect(f[0]!.evidence).not.toContain(key);
  });

  it("does not flag env-driven keys without a literal fallback", async () => {
    const f = await secretFiles(
      `SECRET_KEY = os.environ["K"]\nSECRET_KEY = env("SECRET_KEY")\nSECRET_KEY = os.getenv("K", None)\nSECRET_KEY = config("K", default="")\nSECRET_KEY = config("K", default=get_random_secret_key())`,
    );
    expect(f).toHaveLength(0);
  });

  it("flags a multi-line ALLOWED_HOSTS wildcard, not a commented one", async () => {
    const bad = await run({
      "a/settings.py": "ALLOWED_HOSTS = [\n    'example.com',\n    '*',\n]\n",
    });
    expect(ruleIds(bad)).toEqual(["security_config/django-allowed-hosts-wildcard"]);
    expect(bad[0]!.line).toBe(1);
    const ok = await run({
      "a/settings.py": "ALLOWED_HOSTS = [\n    'example.com',\n    # '*',\n]\nX = ['*']\n",
    });
    expect(ok).toHaveLength(0);
  });

  it("ignores rule-looking lines inside triple-quoted strings", async () => {
    const f = await run({
      "a/settings.py": '"""\nExample:\nDEBUG = True\nALLOWED_HOSTS = [\'*\']\n"""\nDEBUG = False\n',
      "a/views.py": "DOC = '''\n@csrf_exempt\n'''\n",
    });
    expect(f).toHaveLength(0);
  });

  it("flags a literal True default on DEBUG", async () => {
    const f = await run({
      "a/settings.py": `DEBUG = env.bool("DEBUG", default=True)\nDEBUG = bool(os.environ.get("DEBUG", True))\n`,
    });
    expect(ruleIds(f)).toEqual(Array(2).fill("security_config/django-debug-true"));
  });

  it("flags qualified csrf_exempt calls but not definitions", async () => {
    const f = await run({
      "a/views.py":
        "v = decorators.csrf_exempt(view)\nw = csrf.csrf_exempt(view)\ndef csrf_exempt(f):\n    return f\n",
    });
    expect(f.map((x) => x.line)).toEqual([1, 2]);
  });
});

describe("Python file discovery and pipeline", () => {
  async function tree(files: Record<string, string>) {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "vs-pydisc-"));
    for (const [name, content] of Object.entries(files)) {
      const full = path.join(dir, name);
      await fs.mkdir(path.dirname(full), { recursive: true });
      await fs.writeFile(full, content);
    }
    return dir;
  }

  it("discovers app .py files but not venv, caches or Python test files", async () => {
    const dir = await tree({
      "app/settings.py": "DEBUG = True\n",
      "venv/lib/site-packages/x.py": "DEBUG = True\n",
      ".venv/a.py": "DEBUG = True\n",
      "app/__pycache__/b.py": "x = 1\n",
      ".tox/py/c.py": "x = 1\n",
      ".mypy_cache/d.py": "x = 1\n",
      ".pytest_cache/e.py": "x = 1\n",
      ".eggs/f.py": "x = 1\n",
      "app/test_views.py": "x = 1\n",
      "app/views_test.py": "x = 1\n",
      "app/conftest.py": "x = 1\n",
      "test/helper.py": "x = 1\n",
    });
    try {
      const files = await new FileDiscovery(dir).discoverFiles();
      expect(files.filter((f) => f.endsWith(".py"))).toEqual(["app/settings.py"]);
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it("reports a CFG finding end to end and counts the category", async () => {
    const dir = await tree({
      "manage.py": "",
      "app/settings.py": "DEBUG = True\n",
      "venv/lib/site-packages/x.py": "DEBUG = True\n",
    });
    try {
      const result = await new ScannerPipeline(createDefaultRegistry()).scan({ rootPath: dir });
      const cfg = result.findings.filter((x) => x.category === "security_config");
      expect(cfg).toHaveLength(1);
      expect(cfg[0]!.id).toMatch(/^CFG-/);
      expect(cfg[0]!.file).toBe("app/settings.py");
      expect(result.summary.categoryCounts.security_config).toBe(1);
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it("wires the security_config category into shared tables", () => {
    expect(CATEGORY_MULTIPLIERS.security_config).toBe(1.1);
    expect(CATEGORY_PREFIX.security_config).toBe("CFG");
  });
});

describe("Django project detection, extra cases", () => {
  async function project(files: Record<string, string>) {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "vs-django2-"));
    for (const [name, content] of Object.entries(files)) {
      const full = path.join(dir, name);
      await fs.mkdir(path.dirname(full), { recursive: true });
      await fs.writeFile(full, content);
    }
    try {
      return await new ProjectContextBuilder(dir).build();
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  }

  it("detects Pipfile and requirements-dev.txt", async () => {
    expect((await project({ Pipfile: '[packages]\ndjango = "*"' })).framework).toBe("django");
    expect((await project({ "requirements-dev.txt": "django>=4" })).framework).toBe("django");
  });

  it("ignores django mentioned only in a comment", async () => {
    expect((await project({ "requirements.txt": "# django is not used\nflask" })).framework).toBe(
      "unknown",
    );
  });

  it("uses language python for Django, even next to a non-TS package.json", async () => {
    expect((await project({ "manage.py": "" })).language).toBe("python");
    const withPkg = await project({ "manage.py": "", "package.json": "{}" });
    expect(withPkg.framework).toBe("django");
    expect(withPkg.language).toBe("python");
    const ts = await project({ "manage.py": "", "tsconfig.json": "{}" });
    expect(ts.language).toBe("typescript");
  });

  it("keeps the JS language for a JS framework next to manage.py", async () => {
    const c = await project({
      "package.json": JSON.stringify({ dependencies: { express: "4.0.0" } }),
      "manage.py": "",
    });
    expect(c.framework).toBe("express");
    expect(c.language).toBe("javascript");
  });

  it("detects Python tests for Django projects", async () => {
    expect((await project({ "manage.py": "" })).hasTests).toBe(false);
    expect((await project({ "manage.py": "", "pytest.ini": "" })).hasTests).toBe(true);
    expect((await project({ "manage.py": "", "conftest.py": "" })).hasTests).toBe(true);
    expect((await project({ "manage.py": "", "blog/tests.py": "" })).hasTests).toBe(true);
    expect((await project({ "manage.py": "", "blog/tests/test_a.py": "" })).hasTests).toBe(true);
    expect((await project({ "manage.py": "", "test_x.py": "" })).hasTests).toBe(true);
    expect((await project({ "manage.py": "", "venv/tests/a.py": "" })).hasTests).toBe(false);
  });
});
