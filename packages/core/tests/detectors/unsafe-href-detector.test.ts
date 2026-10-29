import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { UnsafeHrefDetector } from "../../src/detectors/unsafe-href-detector";
import { expectRubric } from "../helpers/rubric";

const createContext = (files: Record<string, string>, react = "18.2.0"): ScanContext => ({
  rootPath: "/fake/path",
  projectContext: { framework: "nextjs", dependencies: { react } } as any,
  files: Object.keys(files),
  config: {} as any,
  readFile: async (file) => files[file] ?? "",
});

async function run(files: Record<string, string>, react?: string) {
  const findings = await new UnsafeHrefDetector().detect(createContext(files, react));
  expectRubric(findings);
  return findings;
}

const RULE = "xss/javascript-url-href";

const STORE_PAGE = `import { notFound } from "next/navigation";
import { createClient } from "@/lib/server/supabase";

export default async function StorePage({ params }: { params: { slug: string } }) {
  const supabase = createClient();
  const { data: store } = await supabase.from("stores").select("*").eq("slug", params.slug).single();
  if (!store) notFound();
  return (
    <header>
      <h1>{store.name}</h1>
      {store.website_url && (
        <a href={store.website_url} target="_blank">Website</a>
      )}
    </header>
  );
}
`;

describe("UnsafeHrefDetector", () => {
  it("flags a profile-style URL field rendered as href (medium below React 19)", async () => {
    const findings = await run({ "app/s/[slug]/page.tsx": STORE_PAGE });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe(RULE);
    expect(findings[0]!.category).toBe("xss");
    expect(findings[0]!.line).toBe(12);
    expect(findings[0]!.severity).toBe("medium");
    expect(findings[0]!.confidence).toBe("low");
  });

  it("drops to low severity on React 19, which blocks javascript: URLs", async () => {
    const findings = await run({ "app/s/[slug]/page.tsx": STORE_PAGE }, "^19.0.0");
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("low");
  });

  it("flags href and iframe src fed by the page URL in a client component", async () => {
    const findings = await run({
      "components/Preview.tsx": `"use client";
import { useSearchParams } from "next/navigation";
export function Preview() {
  const params = useSearchParams();
  const target = params.get("link");
  return (
    <div>
      <a href={target ?? "#"}>Open</a>
      <iframe src={params.get("embed") ?? undefined} />
    </div>
  );
}
`,
    });
    expect(findings.map((f) => f.line)).toEqual([8, 9]);
    expect(findings.every((f) => f.ruleId === RULE && f.confidence === "high")).toBe(true);
  });

  it("accepts scheme checks, literal prefixes and local link lists", async () => {
    const findings = await run({
      "components/Profile.tsx": `"use client";
const LINKS = [{ url: "https://docs.example.com" }, { url: "/pricing" }];
export function Profile({ user }: { user: { website: string; handle: string } }) {
  const team = { website: "https://team.example.com" };
  const safe = /^https?:\\/\\//.test(user.website) ? user.website : undefined;
  return (
    <div>
      {LINKS.map((l) => <a key={l.url} href={l.url}>x</a>)}
      <a href={"https://x.com/" + user.handle}>X</a>
      <a href={safe}>Site</a>
      <a href={team.website}>Team</a>
      {user.website.startsWith("https://") && <a href={user.website}>Site</a>}
      <a href="javascript:void(0)">noop</a>
    </div>
  );
}
`,
    });
    expect(findings).toEqual([]);
  });

  it("ignores comments, API routes and Python files", async () => {
    const findings = await run({
      "components/Card.tsx": `"use client";
// <a href={user.website}>old</a>
export function Card() { return <p>{"<a href={user.website}>"}</p>; }
`,
      "app/api/users/route.ts": `export async function GET() {
  const user = await db.user.findFirst();
  return Response.json({ href: user.website });
}
`,
      "app/views.py": `html = f'<a href={user.website}>site</a>'\n`,
    });
    expect(findings).toEqual([]);
  });

  it("produces stable ids across runs", async () => {
    const a = await run({ "app/s/[slug]/page.tsx": STORE_PAGE });
    const b = await run({ "app/s/[slug]/page.tsx": STORE_PAGE });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });
});
