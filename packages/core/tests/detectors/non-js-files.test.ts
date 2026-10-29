import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { ProjectContext, ScanContext } from "@talaljaber/vibesafe-shared";
import { FileDiscovery } from "../../src/scanner/file-discovery.js";
import { createDefaultRegistry } from "../../src/scanner/detector-registry.js";
import { SecretDetector } from "../../src/detectors/secret-detector.js";
import { classifyPath, type FileKind } from "../../src/detectors/utils/file-kind.js";
import { infraNonJsExempt } from "../../src/detectors/groups/infra.js";
import { injectionNonJsExempt } from "../../src/detectors/groups/injection.js";
import { clientNonJsExempt } from "../../src/detectors/groups/client.js";
import { authzNonJsExempt } from "../../src/detectors/groups/authz.js";
import { cryptoNonJsExempt } from "../../src/detectors/groups/crypto.js";
import { supabaseNonJsExempt } from "../../src/detectors/groups/supabase.js";
import { depsNonJsExempt } from "../../src/detectors/groups/deps.js";
import { toolingNonJsExempt } from "../../src/detectors/groups/tooling.js";

const PROJECT: ProjectContext = {
  framework: "unknown",
  language: "mixed",
  hasTypeScript: false,
  packageManager: "unknown",
  dependencies: {},
  devDependencies: {},
  scripts: {},
  hasGitignore: true,
  hasEnvFile: false,
  hasEnvExample: false,
  hasReadme: true,
  hasTests: true,
};

const createContext = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake/path",
  projectContext: PROJECT,
  files: Object.keys(files),
  config: { rootPath: "/fake/path" },
  readFile: async (file) => files[file] ?? "",
});

/**
 * Legacy detectors that read non-JS files by design (secrets everywhere, manifests,
 * Python, SQL, project shape). New detectors are never added here: a group lists the
 * non-JS kinds its detectors report on in `<group>NonJsExempt` instead.
 */
const LEGACY_DENYLIST = (id: string): boolean =>
  [
    "secret-detector",
    "git-history-detector",
    "dependency-detector",
    "python-dependency-detector",
    "supabase-rls-detector",
    "project-structure-detector",
  ].includes(id) || id.startsWith("django-");

const EXEMPT: Record<string, Readonly<Record<string, readonly FileKind[]>>> = {
  infra: infraNonJsExempt,
  injection: injectionNonJsExempt,
  client: clientNonJsExempt,
  authz: authzNonJsExempt,
  crypto: cryptoNonJsExempt,
  supabase: supabaseNonJsExempt,
  deps: depsNonJsExempt,
  tooling: toolingNonJsExempt,
};

/** Detector ids exempted for a file kind by any group. */
function exemptFor(kind: FileKind): Set<string> {
  const ids = new Set<string>();
  for (const map of Object.values(EXEMPT)) {
    for (const [id, kinds] of Object.entries(map)) if (kinds.includes(kind)) ids.add(id);
  }
  return ids;
}

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

/** JS-looking lines every non-JS sample carries, to tempt JS detectors. */
const JS_BAIT = [
  "const app = express(); app.use(cors({ origin: '*', credentials: true }))",
  "export async function POST(req) { const body = await req.json(); await db.user.delete(body) }",
  "console.log(user); fetch('http://localhost:3000/api')",
  "<div dangerouslySetInnerHTML={{ __html: html }} />",
  "eval(req.query.code); exec(`ls ${req.body.dir}`)",
];

const DOCKERFILE = [
  "FROM node:20-alpine",
  "WORKDIR /app",
  "ENV API_URL=http://localhost:3000",
  "COPY . .",
  "RUN npm ci && npm run build",
  ...JS_BAIT.map((l) => `# ${l}`),
  'CMD ["node", "server.js"]',
].join("\n");

const COMPOSE = [
  "services:",
  "  web:",
  "    build: .",
  "    command: node -e \"console.log('http://localhost:3000')\"",
  "    ports:",
  '      - "3000:3000"',
  ...JS_BAIT.map((l) => `# ${l}`),
].join("\n");

const WORKFLOW = [
  "name: ci",
  "on: [push]",
  "jobs:",
  "  build:",
  "    runs-on: ubuntu-latest",
  "    steps:",
  "      - uses: actions/checkout@v4",
  "      - run: |",
  ...JS_BAIT.map((l) => `          ${l}`),
].join("\n");

const SHELL = ["#!/bin/sh", "set -e", ...JS_BAIT.map((l) => `echo "${l}"`)].join("\n");

const ENV = [
  "NODE_ENV=staging",
  "NEXT_PUBLIC_API_URL=http://localhost:3000",
  "LOG_LEVEL=debug",
  ...JS_BAIT.map((l) => `# ${l}`),
].join("\n");

const SAMPLES: { kind: FileKind; files: Record<string, string> }[] = [
  {
    kind: "python",
    files: {
      "server/app.py": PY,
      "api/views.py": DJANGO_VIEWS,
      "app/api/login/views.py": DJANGO_VIEWS,
    },
  },
  { kind: "sql", files: { "db/schema.sql": SQL, "supabase/migrations/001.sql": SQL } },
  { kind: "dockerfile", files: { Dockerfile: DOCKERFILE, "app/api/Dockerfile.dev": DOCKERFILE } },
  { kind: "compose", files: { "docker-compose.yml": COMPOSE } },
  { kind: "workflow", files: { ".github/workflows/ci.yml": WORKFLOW } },
  { kind: "shell", files: { "scripts/deploy.sh": SHELL, "app/api/run.sh": SHELL } },
  { kind: "env", files: { ".env.staging2": ENV } },
];

describe("non-JS files", () => {
  const detectors = createDefaultRegistry()
    .getDetectors()
    .filter((d) => !LEGACY_DENYLIST(d.id));

  it("the samples have the kinds they claim", () => {
    for (const { kind, files } of SAMPLES) {
      for (const file of Object.keys(files)) expect(classifyPath(file), file).toBe(kind);
    }
  });

  it("exemptions only name non-JS kinds", () => {
    const jsKinds = new Set(["app/api/x/route.ts", "lib/a.ts"].map(classifyPath));
    for (const map of Object.values(EXEMPT)) {
      for (const kinds of Object.values(map)) {
        for (const k of kinds) expect(jsKinds.has(k), k).toBe(false);
      }
    }
  });

  for (const { kind, files } of SAMPLES) {
    describe(`${kind} samples`, () => {
      const exempt = exemptFor(kind);
      for (const detector of detectors) {
        if (exempt.has(detector.id)) continue;
        it(`${detector.id} produces no findings`, async () => {
          const findings = await detector.detect(createContext(files));
          expect(findings).toEqual([]);
        });
      }
    });
  }

  it("python manifests do not trip JS detectors", async () => {
    const files = { "requirements.txt": "django\nexpress\n", Pipfile: '[packages]\nnext = "*"\n' };
    for (const detector of detectors) {
      expect(await detector.detect(createContext(files)), detector.id).toEqual([]);
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
