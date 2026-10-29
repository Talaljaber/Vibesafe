import { describe, it, expect } from "vitest";
import type { Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { DockerfileDetector } from "../../src/detectors/dockerfile-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const createContext = (
  files: Record<string, string>,
  extra: Partial<ScanContext["config"]> = {},
): ScanContext => ({
  rootPath: "/fake",
  projectContext: {} as ScanContext["projectContext"],
  files: Object.keys(files),
  config: { rootPath: "/fake", ...extra },
  readFile: async (f) => files[f] ?? "",
});

const run = async (
  files: Record<string, string>,
  extra: Partial<ScanContext["config"]> = {},
): Promise<Finding[]> => {
  const findings = await new DockerfileDetector().detect(createContext(files, extra));
  expectRubric(findings);
  return findings;
};

const byRule = (findings: Finding[], rule: string): Finding[] =>
  findings.filter((f) => f.ruleId === `security_config/${rule}`);

const GOOD_IGNORE = ".git\n.env\n.env.*\n!.env.example\nnode_modules\n";

describe("DockerfileDetector: docker-secret-in-env", () => {
  it("flags secret-named ENV and ARG values and redacts them", async () => {
    const findings = byRule(
      await run({
        Dockerfile: [
          "FROM node:20-alpine",
          "ENV JWT_SECRET=4f9a8c1e2b7d6f3a9e0c",
          "ARG DB_PASSWORD=hunter22",
          "ENV ADMIN_TOKEN prod-admin-token-value",
          "USER node",
        ].join("\n"),
        ".dockerignore": GOOD_IGNORE,
      }),
      "docker-secret-in-env",
    );
    expect(findings.map((f) => f.line)).toEqual([2, 3, 4]);
    expect(findings[0]!.severity).toBe("high");
    expect(findings[0]!.confidence).toBe("high");
    for (const f of findings) {
      expect(f.evidence).not.toContain("4f9a8c1e2b7d6f3a9e0c");
      expect(f.evidence).not.toContain("hunter22");
      expect(f.evidence).not.toContain("prod-admin-token-value");
    }
  });

  it("flags a connection string with a password, on the right continuation line", async () => {
    const findings = byRule(
      await run({
        Dockerfile: [
          "FROM node:20",
          "ENV NODE_ENV=production \\",
          "    DATABASE_URL=postgres://app:s3cretpass@db.internal:5432/app",
        ].join("\n"),
      }),
      "docker-secret-in-env",
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.line).toBe(3);
    expect(findings[0]!.evidence).not.toContain("s3cretpass");
  });

  it("ignores safe look-alikes: references, placeholders, public and non-secret names", async () => {
    const findings = byRule(
      await run({
        Dockerfile: [
          "FROM node:20",
          "ENV NODE_ENV=production",
          "ENV API_TOKEN=$API_TOKEN",
          "ENV SECRET_KEY=${SECRET_KEY}",
          "ARG NPM_TOKEN",
          "ENV NEXT_PUBLIC_SUPABASE_ANON_KEY=public-anon-value-123",
          "ENV PASSWORD_MIN_LENGTH=12",
          "ENV DB_PASSWORD_FILE=/run/secrets/db_password",
          "ENV API_KEY=changeme",
          "ENV DATABASE_URL=postgres://db:5432/app",
          "# ENV JWT_SECRET=4f9a8c1e2b7d6f3a9e0c",
          'RUN echo "ENV JWT_SECRET=4f9a8c1e2b7d6f3a9e0c"',
        ].join("\n"),
      }),
      "docker-secret-in-env",
    );
    expect(findings).toEqual([]);
  });

  it("leaves known token formats to the secret detector", async () => {
    const key = "sk_live_" + "a1B2c3D4e5F6g7H8i9J0k1L2";
    const findings = byRule(
      await run({ Dockerfile: `FROM node:20\nENV STRIPE_SECRET_KEY=${key}\n` }),
      "docker-secret-in-env",
    );
    expect(findings).toEqual([]);
  });

  it("ignores files that are not Dockerfiles", async () => {
    const findings = await run({
      "Dockerfile.ts": "ENV JWT_SECRET=4f9a8c1e2b7d6f3a9e0c\n",
      "docs/notes.md": "ENV JWT_SECRET=4f9a8c1e2b7d6f3a9e0c\n",
    });
    expect(findings).toEqual([]);
  });
});

describe("DockerfileDetector: docker-copy-without-dockerignore", () => {
  const DOCKERFILE = "FROM node:20\nWORKDIR /app\nCOPY . .\nUSER node\n";

  it("flags COPY . . when no .dockerignore can be read (medium confidence)", async () => {
    const findings = byRule(
      await run({ Dockerfile: DOCKERFILE }),
      "docker-copy-without-dockerignore",
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!).toMatchObject({ line: 3, severity: "high", confidence: "medium" });
  });

  it("flags an incomplete .dockerignore with high confidence", async () => {
    const findings = byRule(
      await run({
        Dockerfile: DOCKERFILE.replace("COPY . .", "ADD ./ /app/"),
        ".dockerignore": "node_modules\n",
        ".env.local": "A=1\n",
      }),
      "docker-copy-without-dockerignore",
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.confidence).toBe("high");
    expect(findings[0]!.plainEnglishProblem).toContain(".env files");
    expect(findings[0]!.plainEnglishProblem).toContain(".git");
  });

  it("reads .dockerignore through readFile even when it is not in context.files", async () => {
    const context = createContext({ Dockerfile: DOCKERFILE });
    context.readFile = async (f) =>
      f === ".dockerignore" ? GOOD_IGNORE : f === "Dockerfile" ? DOCKERFILE : "";
    const findings = await new DockerfileDetector().detect(context);
    expect(byRule(findings, "docker-copy-without-dockerignore")).toEqual([]);
  });

  it("accepts an adequate .dockerignore, a Dockerfile-specific one and an allowlist", async () => {
    expect(
      byRule(
        await run({ Dockerfile: DOCKERFILE, ".dockerignore": GOOD_IGNORE }),
        "docker-copy-without-dockerignore",
      ),
    ).toEqual([]);
    expect(
      byRule(
        await run({ "api/Dockerfile": DOCKERFILE, "api/Dockerfile.dockerignore": GOOD_IGNORE }),
        "docker-copy-without-dockerignore",
      ),
    ).toEqual([]);
    expect(
      byRule(
        await run({ Dockerfile: DOCKERFILE, ".dockerignore": "*\n!src\n!package.json\n" }),
        "docker-copy-without-dockerignore",
      ),
    ).toEqual([]);
  });

  it("ignores targeted copies, --from copies and commented lines", async () => {
    const findings = byRule(
      await run({
        Dockerfile: [
          "FROM node:20 AS build",
          "COPY package.json package-lock.json ./",
          "COPY src ./src",
          "# COPY . .",
          "FROM node:20-slim",
          "COPY --from=build . .",
          "USER node",
        ].join("\n"),
      }),
      "docker-copy-without-dockerignore",
    );
    expect(findings).toEqual([]);
  });
});

describe("DockerfileDetector: docker-runs-as-root", () => {
  it("flags a final stage without USER, anchored on its FROM", async () => {
    const findings = byRule(
      await run({ Dockerfile: 'FROM node:20\nRUN npm ci\nCMD ["node", "a.js"]\n' }),
      "docker-runs-as-root",
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!).toMatchObject({ line: 1, severity: "medium", confidence: "medium" });
  });

  it("flags an explicit USER root in the final stage", async () => {
    const findings = byRule(
      await run({
        Dockerfile: "FROM node:20 AS build\nUSER node\nFROM node:20-slim\nUSER root\n",
      }),
      "docker-runs-as-root",
    );
    expect(findings.map((f) => f.line)).toEqual([4]);
  });

  it("ignores non-root users, stage inheritance, non-root bases and privilege drops", async () => {
    const cases = [
      "FROM node:20\nUSER node\n",
      'FROM node:20 AS base\nUSER 1001:1001\nFROM base\nCMD ["node"]\n',
      'FROM gcr.io/distroless/nodejs20-debian12:nonroot\nCMD ["a.js"]\n',
      "FROM scratch\nCOPY app /app\n",
      'FROM node:20\nENTRYPOINT ["gosu", "app", "node", "a.js"]\n',
      "FROM node:20\n# USER root\nUSER app\n",
    ];
    for (const Dockerfile of cases) {
      expect(byRule(await run({ Dockerfile }), "docker-runs-as-root"), Dockerfile).toEqual([]);
    }
  });
});

describe("DockerfileDetector: docker-unpinned-base-image", () => {
  it("flags untagged and :latest base images", async () => {
    const findings = byRule(
      await run({ Dockerfile: "FROM node AS build\nFROM nginx:latest\nUSER nginx\n" }),
      "docker-unpinned-base-image",
    );
    expect(findings.map((f) => [f.line, f.severity])).toEqual([
      [1, "low"],
      [2, "low"],
    ]);
  });

  it("ignores tags, digests, stage aliases, build args and scratch", async () => {
    const findings = byRule(
      await run({
        Dockerfile: [
          "ARG BASE=node:20",
          "FROM node:20-alpine AS build",
          "FROM build",
          "FROM ${BASE}",
          "FROM python@sha256:0123",
          "FROM scratch",
          "FROM localhost:5000/app:1.0",
          "USER app",
        ].join("\n"),
      }),
      "docker-unpinned-base-image",
    );
    expect(findings).toEqual([]);
  });
});

describe("DockerfileDetector: general", () => {
  it("produces stable ids and skips test fixtures unless includeTests", async () => {
    const files = { Dockerfile: "FROM node\nENV API_KEY=abcdef123456\nCOPY . .\n" };
    const a = await run(files);
    const b = await run(files);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
    expect(a.length).toBe(4);
    const fixture = { "tests/fixtures/Dockerfile": files.Dockerfile };
    expect(await run(fixture)).toEqual([]);
    expect((await run(fixture, { includeTests: true })).length).toBe(4);
  });

  it("never throws on odd input", async () => {
    await expect(
      run({ Dockerfile: "\\\n\\\nFROM\nRUN <<EOF\nCOPY\n", Containerfile: "\u0000\u0001" }),
    ).resolves.toBeDefined();
  });
});

describe("DockerfileDetector: review hardening", () => {
  it("ignores configuration names and values that are not credentials", async () => {
    const findings = byRule(
      await run({
        Dockerfile: [
          "FROM node:20",
          "ENV TOKEN_ISSUER=https://auth.example.com",
          "ENV TOKEN_TYPE=Bearer",
          "ENV PASSWORD_HASHER=argon2id",
          "ENV AWS_CREDENTIALS_SOURCE=instance-metadata",
          "ENV CREDENTIALS_PROVIDER=workload-identity",
          "ENV SECRET_KEY_BASE=development",
          "ENV JWT_AUDIENCE=api.example.com SECRET_ROTATION_DAYS=30",
          "ENV API_TOKEN=https://tokens.example.com/issue",
          "ENV GOOGLE_APPLICATION_CREDENTIALS=./keys/sa.json",
          "USER node",
        ].join("\n"),
      }),
      "docker-secret-in-env",
    );
    expect(findings).toEqual([]);
  });

  it("reports quoted secrets the same way as unquoted ones", async () => {
    const findings = byRule(
      await run({
        Dockerfile: [
          "FROM node:20",
          'ENV JWT_SECRET="4f9a8c1e2b7d6f3a9e0c"',
          "ENV JWT_SECRET2=4f9a8c1e2b7d6f3a9e0c",
          "ENV SECRET_KEY_BASE=8b1f0a9c3d2e7f6a5b4c",
          'ARG DB_PASSWORD="hunter22"',
          "USER node",
        ].join("\n"),
      }),
      "docker-secret-in-env",
    );
    expect(findings.map((f) => [f.line, f.severity, f.confidence])).toEqual([
      [2, "high", "high"],
      [3, "high", "high"],
      [4, "high", "high"],
      [5, "high", "medium"],
    ]);
    expect(findings.map((f) => f.evidence).join("\n")).not.toContain("4f9a8c1e2b7d6f3a9e0c");
  });

  it("does not flag official database images that drop privileges in their entrypoint", async () => {
    const cases = [
      "FROM postgres:16\nCOPY init.sql /docker-entrypoint-initdb.d/\n",
      'FROM redis:7-alpine\nCOPY redis.conf /usr/local/etc/redis/\nCMD ["redis-server", "/usr/local/etc/redis/redis.conf"]\n',
      "FROM mysql:8.4\nCOPY schema.sql /docker-entrypoint-initdb.d/\n",
      "FROM docker.io/library/mongo:7\n",
      "FROM bitnami/postgresql:16\n",
    ];
    for (const Dockerfile of cases) {
      expect(byRule(await run({ Dockerfile }), "docker-runs-as-root"), Dockerfile).toEqual([]);
    }
  });

  it("still flags web servers and database images whose entrypoint is replaced", async () => {
    const cases = [
      "FROM nginx:1.27\nCOPY dist /usr/share/nginx/html\n",
      'FROM postgres:16\nENTRYPOINT ["postgres"]\n',
      "FROM acme/postgres-tools:1\n",
      "FROM redis:7\nUSER root\n",
    ];
    for (const Dockerfile of cases) {
      expect(byRule(await run({ Dockerfile }), "docker-runs-as-root"), Dockerfile).toHaveLength(1);
    }
  });
});
