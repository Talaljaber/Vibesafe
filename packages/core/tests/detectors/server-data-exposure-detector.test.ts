import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { ServerDataExposureDetector } from "../../src/detectors/server-data-exposure-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const detector = new ServerDataExposureDetector();

const CLIENT = `"use client";\nexport default function C(props: any) { return <div />; }\n`;
const SERVER_COMP = `export default function C(props: any) { return <div />; }\n`;

async function run(files: Record<string, string>, only?: string[]) {
  const ctx = {
    rootPath: "/fake",
    projectContext: { framework: "nextjs", dependencies: {}, devDependencies: {} },
    files: only ?? Object.keys(files),
    config: { rootPath: "/fake" },
    readFile: async (f: string) => files[f] ?? "",
  } as unknown as ScanContext;
  const findings = await detector.detect(ctx);
  expectRubric(findings);
  return findings;
}

const page = (body: string, imp = 'import ProfileCard from "@/components/ProfileCard";'): string =>
  `${imp}\nexport default async function Page() {\n${body}\n}\n`;

const withCard = (pageSrc: string, card = CLIENT): Record<string, string> => ({
  "app/settings/page.tsx": pageSrc,
  "components/ProfileCard.tsx": card,
});

describe("ServerDataExposureDetector positives", () => {
  it("flags supabase select('*') on profiles passed to a client component", async () => {
    const files = withCard(
      page(
        `  const { data: profile } = await supabase.from("profiles").select("*").eq("id", id).single();\n  return <ProfileCard profile={profile} />;`,
      ),
    );
    const f = await run(files, ["app/settings/page.tsx"]);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({
      ruleId: "frontend_exposure/full-row-client-prop",
      severity: "medium",
      confidence: "medium",
      line: 3,
    });
    const again = await run(files, ["app/settings/page.tsx"]);
    expect(again[0]?.id).toBe(f[0]?.id);
  });

  it("flags a nested sensitive relation inside Promise.all, but not a non-sensitive one", async () => {
    const mk = (rel: string): Record<string, string> =>
      withCard(
        page(
          `  const [{ data: me }, { data: items }] = await Promise.all([\n    supabase.from("users").select("id, name, ${rel}(*)").single(),\n    supabase.from("things").select("id"),\n  ]);\n  return <ProfileCard profile={me} items={items} />;`,
        ),
      );
    expect(await run(mk("teams"))).toEqual([]);
    const f = await run(mk("organizations"));
    expect(f).toHaveLength(1);
    expect(f[0]?.line).toBe(4);
  });

  it("flags a prisma findUnique without select", async () => {
    const files = withCard(
      page(
        `  const user = await prisma.user.findUnique({ where: { id } });\n  return <ProfileCard user={user} />;`,
      ),
    );
    expect(await run(files)).toHaveLength(1);
  });

  it("flags a spread of a no-argument select", async () => {
    const files = withCard(
      page(
        `  const { data: member } = await supabase.from("members").select().single();\n  return <ProfileCard {...member} />;`,
      ),
    );
    expect(await run(files)).toHaveLength(1);
  });

  it("flags Pages Router props from getServerSideProps", async () => {
    const files = {
      "pages/account.tsx": `export async function getServerSideProps() {\n  const user = await prisma.user.findFirst({ include: { posts: true } });\n  return { props: { user } };\n}\nexport default function P({ user }: any) { return <div>{user.name}</div>; }\n`,
    };
    const f = await run(files);
    expect(f).toHaveLength(1);
    expect(f[0]?.line).toBe(2);
  });

  it("resolves @/ to src/components", async () => {
    const files = {
      "app/settings/page.tsx": page(
        `  const user = await prisma.user.findMany();\n  return <ProfileCard user={user} />;`,
      ),
      "src/components/ProfileCard.tsx": CLIENT,
    };
    expect(await run(files)).toHaveLength(1);
  });

  it("works for a single-file scan of the page", async () => {
    const files = withCard(
      page(
        `  const user = await prisma.account.findFirst();\n  return <ProfileCard user={user} />;`,
      ),
    );
    expect(await run(files, ["app/settings/page.tsx"])).toHaveLength(1);
  });
});

describe("ServerDataExposureDetector negatives", () => {
  const cases: Array<[string, string, Record<string, string>?]> = [
    [
      "explicit columns",
      `  const { data: u } = await supabase.from("profiles").select("id, email, full_name").single();\n  return <ProfileCard profile={u} />;`,
    ],
    [
      "non-sensitive table",
      `  const { data: u } = await supabase.from("products").select("*");\n  return <ProfileCard profile={u} />;`,
    ],
    [
      "only fields passed",
      `  const user = await prisma.user.findUnique({ where: { id } });\n  return <ProfileCard email={user.email} />;`,
    ],
    [
      "dto passed",
      `  const user = await prisma.user.findUnique({ where: { id } });\n  return <ProfileCard user={toPublicUser(user)} />;`,
    ],
    [
      "prisma select",
      `  const user = await prisma.user.findUnique({ where: { id }, select: { id: true } });\n  return <ProfileCard user={user} />;`,
    ],
    [
      "prisma omit",
      `  const user = await prisma.user.findUnique({ where: { id }, omit: { password: true } });\n  return <ProfileCard user={user} />;`,
    ],
    [
      "drizzle columns",
      `  const user = await db.query.users.findFirst({ columns: { id: true } });\n  return <ProfileCard user={user} />;`,
    ],
    [
      "native tag",
      `  const user = await prisma.user.findUnique({ where: { id } });\n  return <pre data-x={user} />;`,
    ],
    [
      "query only in a comment",
      `  // const user = await prisma.user.findUnique({ where: { id } });\n  const s = "const u = await prisma.user.findMany()";\n  return <ProfileCard user={s} />;`,
    ],
  ];
  it.each(cases)("is silent for %s", async (_n, body) => {
    expect(await run(withCard(page(body)))).toEqual([]);
  });

  const full = `  const user = await prisma.user.findUnique({ where: { id } });\n  return <ProfileCard user={user} />;`;
  it("is silent when the child is not a client component", async () => {
    expect(await run(withCard(page(full), SERVER_COMP))).toEqual([]);
  });
  it("is silent when the page itself is a client component", async () => {
    const files = withCard(`"use client";\n${page(full)}`);
    expect(await run(files)).toEqual([]);
  });
  it("is silent for package imports", async () => {
    const files = withCard(page(full, 'import ProfileCard from "ui-lib";'));
    expect(await run(files)).toEqual([]);
  });
  it("is silent for a python file with the same text", async () => {
    expect(await run({ "app/page.py": page(full) })).toEqual([]);
  });
  it("is silent when Pages props carry only a derived object", async () => {
    const files = {
      "pages/account.tsx": `export async function getServerSideProps() {\n  const user = await prisma.user.findFirst();\n  return { props: { user: { id: user.id } } };\n}\n`,
    };
    expect(await run(files)).toEqual([]);
  });
});
