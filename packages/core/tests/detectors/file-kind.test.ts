import { describe, it, expect } from "vitest";
import {
  classifyFile,
  classifyPath,
  isClientScope,
  isGenerated,
  isJsLike,
  isServerScope,
  isTestOrFixturePath,
  runtimeOfKind,
  type FileKind,
} from "../../src/detectors/utils/file-kind.js";

const PATHS: [string, FileKind][] = [
  // Next.js App Router
  ["app/api/users/route.ts", "next-app-route"],
  ["src/app/api/users/[id]/route.js", "next-app-route"],
  ["app\\api\\orders\\route.ts", "next-app-route"],
  ["apps/web/app/(group)/api/x/route.mts", "next-app-route"],
  ["app/route.ts", "next-app-route"],
  ["app/page.tsx", "next-server-component"],
  ["app/dashboard/layout.tsx", "next-server-component"],
  ["app/dashboard/loading.jsx", "next-server-component"],
  ["app/not-found.tsx", "next-server-component"],
  ["app/error.tsx", "next-error-boundary"],
  ["app/global-error.tsx", "next-error-boundary"],
  ["src\\app\\settings\\error.jsx", "next-error-boundary"],
  ["app/dashboard/components/Chart.tsx", "js-module"],
  // Pages Router
  ["pages/api/login.ts", "next-pages-api"],
  ["src/pages/api/users/[id].js", "next-pages-api"],
  ["pages/index.tsx", "next-pages-page"],
  ["src/pages/_app.tsx", "next-pages-page"],
  // Middleware
  ["middleware.ts", "next-middleware"],
  ["src/middleware.js", "next-middleware"],
  ["proxy.ts", "next-middleware"],
  ["apps/web/middleware.ts", "next-middleware"],
  ["lib/middleware.ts", "js-module"],
  ["server/middleware/auth.js", "server-module"],
  // Config
  ["next.config.js", "next-config"],
  ["next.config.mjs", "next-config"],
  ["next.config.mts", "next-config"],
  ["apps/web/next.config.ts", "next-config"],
  ["vite.config.ts", "build-config"],
  ["tailwind.config.js", "build-config"],
  ["postcss.config.cjs", "build-config"],
  [".eslintrc.js", "build-config"],
  // Scripts and server modules
  ["scripts/seed.ts", "script"],
  ["bin/cli.js", "script"],
  ["prisma/seed.ts", "script"],
  ["db/seeds/users.js", "script"],
  ["server/index.ts", "server-module"],
  ["src/server/db.ts", "server-module"],
  ["lib/auth.server.ts", "server-module"],
  ["backend/app.js", "server-module"],
  ["lib/db.ts", "js-module"],
  ["src/utils/format.ts", "js-module"],
  ["types/index.d.ts", "js-module"],
  // Non-JS
  ["manage.py", "python"],
  ["app/views.py", "python"],
  ["supabase/migrations/001_init.sql", "sql"],
  ["Dockerfile", "dockerfile"],
  ["docker/Dockerfile.prod", "dockerfile"],
  ["api.Dockerfile", "dockerfile"],
  ["Containerfile", "dockerfile"],
  ["Dockerfile.json", "json"],
  [".dockerignore", "dockerignore"],
  ["docker-compose.yml", "compose"],
  ["docker-compose.override.yaml", "compose"],
  ["compose.yaml", "compose"],
  [".github/workflows/ci.yml", "workflow"],
  [".github\\workflows\\deploy.yaml", "workflow"],
  [".github/ISSUE_TEMPLATE/bug.yml", "other"],
  ["action.yml", "gh-action"],
  ["config.yml", "other"],
  ["infra/main.tf", "terraform"],
  ["prod.tfvars", "tfvars"],
  ["infra/k8s/app.yaml", "k8s-manifest"],
  ["deploy/kustomization.yml", "k8s-manifest"],
  ["openapi.yaml", "other"],
  ["scripts/deploy.sh", "shell"],
  ["tools/setup.bash", "shell"],
  [".env", "env"],
  [".env.local", "env"],
  [".env.staging2", "env"],
  [".env.example", "env-example"],
  [".env.production.sample", "env-example"],
  [".env.dist", "env-example"],
  [".env.vault", "env-vault"],
  [".envrc", "other"],
  ["package.json", "package-manifest"],
  ["pnpm-lock.yaml", "lockfile"],
  ["packages/a/package-lock.json", "lockfile"],
  ["yarn.lock", "lockfile"],
  ["requirements.txt", "python-manifest"],
  ["requirements/prod.txt", "python-manifest"],
  ["pyproject.toml", "python-manifest"],
  ["Pipfile", "python-manifest"],
  [".gitignore", "gitignore"],
  ["tsconfig.json", "json"],
  ["README.md", "other"],
];

describe("classifyPath", () => {
  it.each(PATHS)("%s -> %s", (p, kind) => {
    expect(classifyPath(p)).toBe(kind);
  });

  it("the samples cover every runtime", () => {
    const runtimes = new Set<string>(PATHS.map(([, k]) => runtimeOfKind(k)));
    expect([...runtimes].sort()).toEqual(
      ["build", "client", "edge", "infra", "script", "server", "unknown"].sort(),
    );
  });
});

describe("runtimeOfKind", () => {
  it("maps kinds to runtimes", () => {
    expect(runtimeOfKind("next-client-component")).toBe("client");
    expect(runtimeOfKind("client-module")).toBe("client");
    expect(runtimeOfKind("next-pages-page")).toBe("client");
    expect(runtimeOfKind("next-error-boundary")).toBe("client");
    expect(runtimeOfKind("next-app-route")).toBe("server");
    expect(runtimeOfKind("next-pages-api")).toBe("server");
    expect(runtimeOfKind("next-server-action")).toBe("server");
    expect(runtimeOfKind("next-server-component")).toBe("server");
    expect(runtimeOfKind("server-module")).toBe("server");
    expect(runtimeOfKind("express-server")).toBe("server");
    expect(runtimeOfKind("next-middleware")).toBe("edge");
    expect(runtimeOfKind("next-config")).toBe("build");
    expect(runtimeOfKind("build-config")).toBe("build");
    expect(runtimeOfKind("script")).toBe("script");
    expect(runtimeOfKind("dockerfile")).toBe("infra");
    expect(runtimeOfKind("env")).toBe("infra");
    expect(runtimeOfKind("terraform")).toBe("infra");
    expect(runtimeOfKind("tfvars")).toBe("infra");
    expect(runtimeOfKind("k8s-manifest")).toBe("infra");
    expect(runtimeOfKind("js-module")).toBe("unknown");
    expect(runtimeOfKind("python")).toBe("unknown");
  });
});

describe("classifyFile (content refinements)", () => {
  const kind = (p: string, content: string, framework?: "vite" | "nextjs") =>
    classifyFile(p, content, framework ? { framework } : undefined).kind;

  it('"use client" makes a client component, also for app pages', () => {
    expect(kind("components/Button.tsx", '"use client";\nexport function B() {}')).toBe(
      "next-client-component",
    );
    expect(kind("app/page.tsx", "// c\n'use client'\nexport default function P() {}")).toBe(
      "next-client-component",
    );
  });

  it('"use server" makes a server action', () => {
    expect(kind("app/actions.ts", '"use server";\nexport async function save() {}')).toBe(
      "next-server-action",
    );
    expect(kind("lib/actions/user.ts", "'use server'\n")).toBe("next-server-action");
  });

  it("path-decided kinds are not overridden by content", () => {
    expect(kind("app/api/x/route.ts", '"use client";')).toBe("next-app-route");
    expect(kind("pages/api/x.ts", "window.location")).toBe("next-pages-api");
    expect(kind("middleware.ts", "import express from 'express'")).toBe("next-middleware");
    expect(kind("scripts/x.ts", "document.title = 'a'")).toBe("script");
    expect(kind("app/error.tsx", "export default function E() {}")).toBe("next-error-boundary");
  });

  it("detects Express-style servers", () => {
    expect(kind("src/index.ts", 'import express from "express";\nconst app = express();')).toBe(
      "express-server",
    );
    expect(kind("api/app.js", "const fastify = require('fastify')();")).toBe("express-server");
    expect(kind("main.mjs", "http.createServer((req, res) => {})")).toBe("express-server");
  });

  it("detects server-only modules and shebang scripts", () => {
    expect(kind("lib/db.ts", 'import "server-only";\nexport const db = 1;')).toBe("server-module");
    expect(kind("tools/run.js", "#!/usr/bin/env node\nconsole.log(1)")).toBe("script");
  });

  it("detects client modules from browser globals and hooks", () => {
    expect(kind("lib/storage.ts", "export const t = () => localStorage.getItem('t');")).toBe(
      "client-module",
    );
    expect(kind("hooks/useAuth.ts", "const [u, setU] = useState(null);")).toBe("client-module");
    expect(kind("lib/nav.ts", "window.location.href = next;")).toBe("client-module");
    expect(kind("lib/q.ts", "const p = useSearchParams();")).toBe("client-module");
  });

  it("detects Vite client code through isClientFile", () => {
    expect(kind("src/lib/api.ts", "export const x = 1;", "vite")).toBe("client-module");
    expect(kind("src/lib/api.ts", "export const x = 1;", "nextjs")).toBe("js-module");
  });

  it("ignores browser globals in comments and strings", () => {
    expect(kind("lib/db.ts", "// window.location\nconst s = 'document.cookie';")).toBe("js-module");
    expect(kind("lib/mail.ts", "/* useState( */ export const html = `<p>window.x</p>`;")).toBe(
      "js-module",
    );
  });

  it("plain modules stay unknown", () => {
    const c = classifyFile(
      "lib/db.ts",
      "import { Pool } from 'pg';\nexport const pool = new Pool();",
    );
    expect(c).toEqual({
      kind: "js-module",
      runtime: "unknown",
      jsLike: true,
      testOrFixture: false,
      generated: false,
    });
  });

  it("reports non-JS kinds and flags", () => {
    expect(classifyFile("Dockerfile", "FROM node:20")).toMatchObject({
      kind: "dockerfile",
      runtime: "infra",
      jsLike: false,
    });
    expect(classifyFile("tests/a.test.ts", "").testOrFixture).toBe(true);
    expect(classifyFile("lib/x.ts", "// @generated by tool\n").generated).toBe(true);
  });
});

describe("partition between server-side and client-side JS rules", () => {
  const samples: [string, string][] = [
    ["app/api/x/route.ts", "export async function POST() {}"],
    ["pages/api/x.ts", "export default function h() {}"],
    ["app/page.tsx", "export default function P() {}"],
    ["app/page.tsx", '"use client";\nexport default function P() {}'],
    ["app/error.tsx", '"use client";'],
    ["pages/index.tsx", "export default function H() {}"],
    ["middleware.ts", "export function middleware() {}"],
    ["next.config.mts", "export default {}"],
    ["scripts/seed.ts", "await db.insert()"],
    ["lib/db.ts", "export const pool = 1"],
    ["lib/storage.ts", "localStorage.setItem('a', 'b')"],
    ["server.js", "const app = require('express')()"],
    ["app/actions.ts", '"use server";'],
    ["components/Nav.jsx", "export const N = () => null"],
    ["src/main.tsx", "createRoot(document.getElementById('root'))"],
  ];

  it.each(samples)("%s is in exactly one scope", (p, content) => {
    const c = classifyFile(p, content);
    expect(c.jsLike).toBe(true);
    expect(Number(isServerScope(c)) + Number(isClientScope(c))).toBe(1);
  });

  it("non-JS files are in neither scope", () => {
    for (const p of ["Dockerfile", "a.py", "a.sql", ".env", "deploy.sh"]) {
      const c = classifyFile(p, "");
      expect(isServerScope(c) || isClientScope(c), p).toBe(false);
    }
  });
});

describe("isJsLike / isTestOrFixturePath / isGenerated", () => {
  it("isJsLike", () => {
    for (const p of [
      "a.ts",
      "a.tsx",
      "a.js",
      "a.jsx",
      "a.mjs",
      "a.cjs",
      "a.mts",
      "a.cts",
      "a.d.ts",
    ]) {
      expect(isJsLike(p), p).toBe(true);
    }
    for (const p of ["a.json", "a.py", "a.sql", "a.sh", "Dockerfile", "a.tsx.bak"]) {
      expect(isJsLike(p), p).toBe(false);
    }
  });

  it("isTestOrFixturePath", () => {
    for (const p of [
      "tests/a.ts",
      "src/__tests__/a.ts",
      "test/a.js",
      "lib/a.test.ts",
      "lib/a.spec.tsx",
      "fixtures/app/route.ts",
      "packages/x/fixtures/a.ts",
      "src/__mocks__/fs.ts",
      "e2e/login.ts",
      "cypress/e2e/a.cy.ts",
      "app/test_views.py",
      "app/views_test.py",
      "conftest.py",
      "lib\\__tests__\\x.ts",
    ]) {
      expect(isTestOrFixturePath(p), p).toBe(true);
    }
    for (const p of [
      "src/testing-utils.ts",
      "lib/attest.ts",
      "app/api/tests-api/route.ts",
      "contest.py",
    ]) {
      expect(isTestOrFixturePath(p), p).toBe(false);
    }
  });

  it("isGenerated", () => {
    for (const p of [
      "types/db.d.ts",
      "public/app.min.js",
      "dist-like/vendor-bundle.js",
      "src/schema.generated.ts",
      "src/__generated__/gql.ts",
      "src/generated/client.ts",
    ]) {
      expect(isGenerated(p), p).toBe(true);
    }
    expect(isGenerated("lib/db.ts")).toBe(false);
    expect(
      isGenerated("lib/db.ts", "/* eslint-disable */\n// Code generated by x. DO NOT EDIT.\n"),
    ).toBe(true);
    expect(isGenerated("lib/db.ts", "// This file is auto-generated\n")).toBe(true);
    expect(isGenerated("lib/db.ts", `${"x".repeat(600)}\n// @generated`)).toBe(false);
  });
});
