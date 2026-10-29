import { describe, it, expect } from "vitest";
import { MissingAuthDetector } from "../../src/detectors/missing-auth-detector";
import type { ScanContext } from "@talaljaber/vibesafe-shared";

describe("MissingAuthDetector", () => {
  const detector = new MissingAuthDetector();

  const createContext = (files: Record<string, string>): ScanContext => ({
    rootPath: "/fake/path",
    projectContext: {} as any,
    files: Object.keys(files),
    config: {} as any,
    readFile: async (file) => files[file] || "",
  });

  it("should detect missing auth in mutating route", async () => {
    const context = createContext({
      "app/api/users/route.ts": `
        export async function POST(req: Request) {
          await db.users.create();
          return Response.json({ success: true });
        }
      `,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("auth/missing-route-auth");
  });

  it("should not detect if auth check exists", async () => {
    const context = createContext({
      "app/api/users/route.ts": `
        import { getServerSession } from "next-auth";
        export async function POST(req: Request) {
          const session = await getServerSession();
          if (!session) return new Response("Unauthorized");
          return Response.json({ success: true });
        }
      `,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(0);
  });
  it("should detect if only generic getUser is used", async () => {
    const context = createContext({
      "app/api/users/route.ts": `
        export async function POST(req: Request) {
          const user = getUser(); // generic, should not count as auth
          return Response.json({ success: true });
        }
      `,
    });
    const findings = await detector.detect(context);
    expect(findings).toHaveLength(1);
  });
});

describe("MissingAuthDetector: cron secret checks (review round 2)", () => {
  const detect = (body: string) =>
    new MissingAuthDetector().detect({
      rootPath: "/fake/path",
      projectContext: {} as any,
      files: ["app/api/cron/route.ts"],
      config: {} as any,
      readFile: async () =>
        [
          'import { createClient } from "@supabase/supabase-js";',
          "export async function POST(request: Request) {",
          body,
          "  const db = createClient(process.env.URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);",
          '  await db.from("jobs").delete().neq("id", 0);',
          "  return Response.json({ ok: true });",
          "}",
        ].join("\n"),
    });
  const secretRule = (f: { ruleId: string }[]) =>
    f.filter((x) => x.ruleId === "auth/missing-route-auth");

  it("accepts a boolean local, a multi-line return, a 404 and a throw", async () => {
    const bodies = [
      '  const isAuthorized = request.headers.get("authorization") === `Bearer ${process.env.CRON_SECRET}`;\n  if (!isAuthorized) return new Response("no", { status: 401 });',
      '  if (request.headers.get("authorization") !== `Bearer ${process.env.CRON_SECRET}`) {\n    return new Response(\n      "nope",\n      { status: 401 },\n    );\n  }',
      '  if (request.headers.get("authorization") !== `Bearer ${process.env.CRON_SECRET}`) {\n    return new Response("Not found", { status: 404 });\n  }',
      '  if (request.headers.get("authorization") !== `Bearer ${process.env.CRON_SECRET}`) {\n    throw new Error("Invalid cron secret");\n  }',
    ];
    for (const b of bodies) expect(secretRule(await detect(b))).toEqual([]);
  });

  it("still reports a cron route with no check", async () => {
    expect(secretRule(await detect("  // run"))).toHaveLength(1);
  });
});
