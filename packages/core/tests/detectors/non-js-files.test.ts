import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { FileDiscovery } from "../../src/scanner/file-discovery.js";
import { SecretDetector } from "../../src/detectors/secret-detector.js";
import { DangerousHtmlDetector } from "../../src/detectors/dangerous-html-detector.js";
import { HardcodedLocalhostDetector } from "../../src/detectors/hardcoded-localhost-detector.js";
import { FrontendExposureDetector } from "../../src/detectors/frontend-exposure-detector.js";
import { MissingAuthDetector } from "../../src/detectors/missing-auth-detector.js";
import { MissingAuthorizationDetector } from "../../src/detectors/missing-authorization-detector.js";
import { MissingValidationDetector } from "../../src/detectors/missing-validation-detector.js";
import { ErrorBoundaryDetector } from "../../src/detectors/error-boundary-detector.js";
import { CodebaseMessDetector } from "../../src/detectors/codebase-mess-detector.js";
import { CorsDetector } from "../../src/detectors/cors-detector.js";
import { RateLimitDetector } from "../../src/detectors/rate-limit-detector.js";
import { SecurityHeadersDetector } from "../../src/detectors/security-headers-detector.js";
import { StripeWebhookDetector } from "../../src/detectors/stripe-webhook-detector.js";
import { DependencyDetector } from "../../src/detectors/dependency-detector.js";

const createContext = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake/path",
  projectContext: { framework: "unknown", routes: [] } as any,
  files: Object.keys(files),
  config: {} as any,
  readFile: async (file) => files[file] || "",
});

const PY = [
  "import os",
  "import requests",
  "url = 'http://localhost:8000/api'",
  "def handler(request):",
  "    console.log('x')",
  "    return request.json()",
  "<div dangerouslySetInnerHTML={{ __html: x }} />",
  "process.env.NEXT_PUBLIC_SECRET_KEY",
].join("\n");

/** A Django REST view that would trip JS route detectors if they read Python. */
const DJANGO_VIEWS = [
  "from rest_framework.views import APIView",
  "import stripe",
  "from openai import OpenAI",
  "class Login(APIView):",
  "    def post(self, request):",
  "        event = stripe.Webhook.construct_event(request.body, sig, secret)",
  "        res = fetch('http://localhost:3000/api/login', { method: 'POST' })",
  "        app.use(cors({ origin: '*', credentials: true }))",
  "        return Response(request.data)",
].join("\n");

const SQL = "SELECT * FROM users WHERE name = 'http://localhost:3000';\n-- console.log\n";

describe("non-JS files", () => {
  describe("JS detectors ignore .py and .sql", () => {
    const detectors = [
      new DangerousHtmlDetector(),
      new HardcodedLocalhostDetector(),
      new FrontendExposureDetector(),
      new MissingAuthDetector(),
      new MissingAuthorizationDetector(),
      new MissingValidationDetector(),
      new ErrorBoundaryDetector(),
      new CodebaseMessDetector(),
      new CorsDetector(),
      new RateLimitDetector(),
      new SecurityHeadersDetector(),
      new StripeWebhookDetector(),
      new DependencyDetector(),
    ];

    for (const detector of detectors) {
      it(`${detector.constructor.name} produces no findings`, async () => {
        const findings = await detector.detect(
          createContext({
            "server/app.py": PY,
            "db/schema.sql": SQL,
            "api/views.py": DJANGO_VIEWS,
            "app/api/login/views.py": DJANGO_VIEWS,
            "requirements.txt": "django\nexpress\n",
            Pipfile: '[packages]\nnext = "*"\n',
          }),
        );
        expect(findings).toEqual([]);
      });
    }
  });

  describe("SecretDetector", () => {
    const key = "sk-123456789012345678901234567890123456789012345678";

    it("finds a secret in a .py file and redacts evidence", async () => {
      const findings = await new SecretDetector().detect(
        createContext({ "server/settings.py": `OPENAI_KEY = '${key}'\n` }),
      );
      expect(findings).toHaveLength(1);
      expect(findings[0]!.ruleId).toBe("secret/sec-openai-key");
      expect(findings[0]!.evidence ?? "").not.toContain(key);
    });

    it("finds a secret in a .sql file", async () => {
      const findings = await new SecretDetector().detect(
        createContext({ "db/seed.sql": `-- key\nINSERT INTO t VALUES ('${key}');\n` }),
      );
      expect(findings).toHaveLength(1);
      expect(findings[0]!.ruleId).toBe("secret/sec-openai-key");
    });
  });

  describe("file discovery", () => {
    let root: string;

    beforeAll(async () => {
      root = await fs.mkdtemp(path.join(os.tmpdir(), "vibesafe-py-"));
      const files = [
        "app.py",
        "manage.py",
        "requirements.txt",
        "pyproject.toml",
        "db/schema.sql",
        "venv/lib/x.py",
        ".venv/lib/x.py",
        "a/__pycache__/x.py",
        "lib/site-packages/pkg/x.py",
        ".tox/py/x.py",
        ".mypy_cache/x.py",
        ".pytest_cache/x.py",
        ".ruff_cache/x.py",
        ".eggs/x.py",
        "deep/nested/venv/y.py",
        "deep/nested/.venv/y.py",
      ];
      for (const f of files) {
        const full = path.join(root, f);
        await fs.mkdir(path.dirname(full), { recursive: true });
        await fs.writeFile(full, "x = 1\n");
      }
    });

    afterAll(async () => {
      await fs.rm(root, { recursive: true, force: true });
    });

    it("discovers python/sql files and excludes tooling dirs", async () => {
      const found = (await new FileDiscovery(root).discoverFiles())
        .map((f) => f.replace(/\\/g, "/"))
        .sort();
      expect(found).toEqual(
        ["app.py", "db/schema.sql", "manage.py", "pyproject.toml", "requirements.txt"].sort(),
      );
    });
  });
});
