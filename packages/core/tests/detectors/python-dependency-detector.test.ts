import { describe, it, expect } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { ScanContext } from "@vibesafe/shared";
import { isPythonRequirementsFile } from "@vibesafe/shared";
import {
  PythonDependencyDetector,
  PYTHON_INSECURE_VERSIONS,
  analyzeSpecs,
} from "../../src/detectors/python-dependency-detector";
import { createDefaultRegistry } from "../../src/scanner/detector-registry";
import { FileDiscovery } from "../../src/scanner/file-discovery";

const detector = new PythonDependencyDetector();

const ctx = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake",
  projectContext: {} as never,
  files: Object.keys(files),
  config: {} as never,
  readFile: async (f) => files[f] ?? "",
});

const run = (files: Record<string, string>) => detector.detect(ctx(files));
const summary = (f: { ruleId: string; line?: number | undefined }[]) =>
  f.map((x) => `${x.line}:${x.ruleId.replace("dependency/python-", "")}`);

describe("PythonDependencyDetector: requirements files", () => {
  it("flags unpinned security-critical packages but not pinned or bounded ones", async () => {
    const f = await run({
      "requirements.txt": [
        "Django>=4.2",
        "djangorestframework",
        "PyJWT>=2.8.0",
        "cryptography==42.0.5",
        "django-cors-headers~=4.3",
        "djangorestframework-simplejwt>=5.3,<6",
        "requests",
        "gunicorn>=21",
      ].join("\n"),
    });
    expect(summary(f)).toEqual(["1:unpinned", "2:unpinned", "3:unpinned"]);
    expect(f[0]!.severity).toBe("low");
    expect(f[0]!.category).toBe("dependency");
    expect(f[0]!.id).toMatch(/^DEP-[0-9a-f]{10}$/);
    expect(f[0]!.evidence).toBe("Django>=4.2");
    expect(f[0]!.title).toContain("django");
  });

  it("flags end-of-life and insecure versions", async () => {
    const f = await run({
      "requirements.txt": [
        "django==3.2.18",
        "djangorestframework==3.14.0",
        "PyJWT==2.3.0",
        "pycrypto==2.6.1",
        "",
        "django==4.2.11",
        "djangorestframework==3.15.2",
        "pyjwt==2.8.0",
      ].join("\n"),
    });
    expect(summary(f)).toEqual([
      "1:insecure-version",
      "2:insecure-version",
      "3:insecure-version",
      "4:insecure-version",
    ]);
    expect(f[0]!.severity).toBe("medium");
    expect(f[0]!.plainEnglishProblem).toMatch(/end of life/);
    expect(f[3]!.fixSteps[0]).toMatch(/maintained alternative/);
  });

  it("uses upper bounds and wildcards to decide whether every allowed version is too old", async () => {
    const f = await run({
      "requirements.txt": [
        "Django~=3.2", // < 4.0
        "Django<4.2",
        "Django==3.2.*",
        "Django>=3.2,<4.3", // 4.2 is allowed
        "Django<=4.1.9",
        "Django>=3.0", // unbounded: unpinned, not insecure
      ].join("\n"),
    });
    expect(summary(f)).toEqual([
      "1:insecure-version",
      "2:insecure-version",
      "3:insecure-version",
      "5:insecure-version",
      "6:unpinned",
    ]);
  });

  it("skips comments, options, URLs and direct references, and handles markers, extras and hashes", async () => {
    const f = await run({
      "requirements/prod.txt": [
        "# django",
        "-r base.txt",
        "-e git+https://github.com/django/django.git#egg=django",
        "--index-url https://pypi.org/simple",
        "django @ https://example.com/django-3.2.tar.gz",
        "https://example.com/pkg.whl",
        "Django[argon2]==3.2.1 ; python_version >= '3.8'  # pinned",
        "djangorestframework==3.15.1 \\",
        "    --hash=sha256:abc \\",
        "    --hash=sha256:def",
        "pyjwt  # no version",
      ].join("\n"),
    });
    expect(summary(f)).toEqual(["7:insecure-version", "11:unpinned"]);
  });

  it("tolerates CRLF and empty files and produces stable ids", async () => {
    const files = { "requirements-dev.txt": "django\r\npycrypto\r\n", "requirements.txt": "" };
    const one = await run(files);
    const two = await run(files);
    expect(summary(one)).toEqual(["1:unpinned", "2:insecure-version"]);
    expect(one.map((x) => x.id)).toEqual(two.map((x) => x.id));
  });

  it("ignores other text files", async () => {
    const f = await run({ "notes.txt": "django\n", "docs/requirements.md": "django\n" });
    expect(f).toHaveLength(0);
  });
});

describe("PythonDependencyDetector: pyproject.toml and Pipfile", () => {
  it("reads PEP 621 dependencies, optional dependencies and dependency groups", async () => {
    const f = await run({
      "pyproject.toml": [
        "[project]",
        'name = "shop"',
        "dependencies = [",
        '    "Django>=4.2",',
        '    "djangorestframework==3.14.0",  # old',
        '    "requests",',
        "]",
        "",
        "[project.optional-dependencies]",
        'auth = ["pyjwt==2.1.0", "django-allauth"]',
        "",
        "[dependency-groups]",
        'dev = ["django-cors-headers>=4"]',
        "",
        "[tool.ruff]",
        'dependencies = ["django"]',
      ].join("\n"),
    });
    expect(summary(f)).toEqual([
      "4:unpinned",
      "5:insecure-version",
      "10:insecure-version",
      "10:unpinned",
      "13:unpinned",
    ]);
  });

  it("reads Poetry constraints (caret, tilde, exact, inline tables) and skips python", async () => {
    const f = await run({
      "pyproject.toml": [
        "[tool.poetry.dependencies]",
        'python = "^3.8"',
        'django = "^3.2"', // < 4.0
        'djangorestframework = "~3.14"', // < 3.15
        'pyjwt = { version = "2.3.0", extras = ["crypto"] }',
        'cryptography = "*"',
        '"django-cors-headers" = ">=3"',
        'django-allauth = { git = "https://github.com/pennersr/django-allauth.git" }',
        "",
        "[tool.poetry.group.dev.dependencies]",
        'djangorestframework-simplejwt = "^5.3"',
      ].join("\n"),
    });
    expect(summary(f)).toEqual([
      "3:insecure-version",
      "4:insecure-version",
      "5:insecure-version",
      "6:unpinned",
      "7:unpinned",
    ]);
  });

  it("reads Pipfile packages", async () => {
    const f = await run({
      Pipfile: [
        "[[source]]",
        'url = "https://pypi.org/simple"',
        "",
        "[packages]",
        'django = "*"',
        'djangorestframework = "==3.12.4"',
        'requests = "*"',
        "",
        "[dev-packages]",
        'pyjwt = {version = ">=2.4"}',
      ].join("\n"),
    });
    expect(summary(f)).toEqual(["5:unpinned", "6:insecure-version", "10:unpinned"]);
  });

  it("does not report unpinned packages when a lock file sits next to the manifest", async () => {
    const pyproject = '[project]\ndependencies = ["django>=4.2", "djangorestframework==3.14"]\n';
    for (const lock of ["poetry.lock", "uv.lock", "pdm.lock"]) {
      const f = await run({ "pyproject.toml": pyproject, [lock]: "# lock\n" });
      expect(summary(f), lock).toEqual(["2:insecure-version"]);
    }
    const pip = await run({ Pipfile: '[packages]\ndjango = "*"\n', "Pipfile.lock": "{}" });
    expect(pip).toHaveLength(0);
    // A lock in another directory does not count; requirements files are always checked.
    const other = await run({
      "svc/pyproject.toml": pyproject,
      "uv.lock": "x",
      "requirements.txt": "django",
      "poetry.lock": "x",
    });
    expect(summary(other)).toEqual(["2:unpinned", "2:insecure-version", "1:unpinned"]);
  });
});

describe("PythonDependencyDetector: helpers and wiring", () => {
  it("analyzes version specifiers", () => {
    expect(analyzeSpecs("", "pep440")).toEqual({ bounded: false });
    expect(analyzeSpecs(">=4.2", "pep440").bounded).toBe(false);
    expect(analyzeSpecs("!=4.0", "pep440").bounded).toBe(false);
    expect(analyzeSpecs("==4.2.1", "pep440").upperInclusive).toEqual([4, 2, 1]);
    expect(analyzeSpecs("~=4.2", "pep440").upperExclusive).toEqual([5]);
    expect(analyzeSpecs("~=4.2.1", "pep440").upperExclusive).toEqual([4, 3]);
    expect(analyzeSpecs("==4.*", "pep440").upperExclusive).toEqual([5]);
    expect(analyzeSpecs(">=3,<4.1,<4", "pep440").upperExclusive).toEqual([4]);
    expect(analyzeSpecs("^0.3.1", "poetry").upperExclusive).toEqual([0, 4]);
    expect(analyzeSpecs("~1", "poetry").upperExclusive).toEqual([2]);
    expect(analyzeSpecs("4.2", "poetry").upperInclusive).toEqual([4, 2]);
    expect(analyzeSpecs("4.2", "pep440").bounded).toBe(false);
    expect(analyzeSpecs("^3.2 || ^4.0", "poetry")).toEqual({ bounded: true });
    expect(analyzeSpecs("*", "pipfile").bounded).toBe(false);
  });

  it("keeps the static insecure-version list short and documented", async () => {
    expect(PYTHON_INSECURE_VERSIONS.map((e) => e.name)).toEqual([
      "django",
      "djangorestframework",
      "pyjwt",
      "pycrypto",
    ]);
    expect(PYTHON_INSECURE_VERSIONS.find((e) => e.name === "django")!.below).toEqual([4, 2]);
    const src = await fs.readFile(
      path.join(
        path.dirname(fileURLToPath(import.meta.url)),
        "../../src/detectors/python-dependency-detector.ts",
      ),
      "utf8",
    );
    expect(src).toMatch(/Written \d{4}-\d{2}-\d{2}/);
  });

  it("matches requirements file names", () => {
    for (const p of [
      "requirements.txt",
      "requirements-dev.txt",
      "requirements_prod.txt",
      "svc/requirements.in.txt",
      "requirements/base.txt",
      "app\\requirements\\prod.txt",
    ]) {
      expect(isPythonRequirementsFile(p), p).toBe(true);
    }
    for (const p of [
      "notes.txt",
      "requirements.md",
      "my-requirements.txt",
      "requirements/README.md",
    ]) {
      expect(isPythonRequirementsFile(p), p).toBe(false);
    }
  });

  it("discovers requirements files and Pipfile", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "vs-pydeps-"));
    try {
      for (const name of [
        "requirements.txt",
        "requirements-dev.txt",
        "requirements/prod.txt",
        "Pipfile",
        "notes.txt",
        "venv/requirements.txt",
      ]) {
        await fs.mkdir(path.dirname(path.join(dir, name)), { recursive: true });
        await fs.writeFile(path.join(dir, name), "django\n");
      }
      const files = (await new FileDiscovery(dir).discoverFiles()).map((f) =>
        f.replace(/\\/g, "/"),
      );
      expect(files.sort()).toEqual(
        ["Pipfile", "requirements-dev.txt", "requirements.txt", "requirements/prod.txt"].sort(),
      );
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it("never throws on unreadable files and is registered by default", async () => {
    const throwing: ScanContext = {
      ...ctx({ "requirements.txt": "", "pyproject.toml": "" }),
      readFile: async () => {
        throw new Error("boom");
      },
    };
    await expect(detector.detect(throwing)).resolves.toEqual([]);
    const ids = createDefaultRegistry()
      .getDetectors()
      .map((d) => d.id);
    expect(ids).toContain("python-dependency-detector");
  });
});
