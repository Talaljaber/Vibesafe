import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { ClientRoleCheckDetector } from "../../src/detectors/client-role-check-detector";
import { expectRubric } from "../helpers/rubric";

const createContext = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake/path",
  projectContext: { framework: "nextjs" } as any,
  files: Object.keys(files),
  config: {} as any,
  readFile: async (file) => files[file] ?? "",
});

async function run(files: Record<string, string>) {
  const findings = await new ClientRoleCheckDetector().detect(createContext(files));
  expectRubric(findings);
  return findings;
}

const RULE = "authorization/client-side-role-check";

const ADMIN_PAGE = `"use client";
import { useEffect, useState } from "react";
import AdminPanel from "@/components/AdminPanel";

export default function AdminPage() {
  const [role, setRole] = useState<string | null>(null);

  useEffect(() => {
    setRole(localStorage.getItem("role"));
  }, []);

  if (role !== "owner" && role !== "admin") {
    return <p>Not allowed</p>;
  }
  return <AdminPanel />;
}
`;

describe("ClientRoleCheckDetector", () => {
  it("flags a role copied from localStorage into state and compared to admin roles", async () => {
    const findings = await run({ "app/admin/page.tsx": ADMIN_PAGE });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe(RULE);
    expect(findings[0]!.category).toBe("authorization");
    expect(findings[0]!.severity).toBe("high");
    expect(findings[0]!.confidence).toBe("medium");
    expect(findings[0]!.line).toBe(9);
  });

  it("flags direct comparisons of stored flags and stored user roles (high confidence)", async () => {
    const findings = await run({
      "src/components/Nav.tsx": `export function Nav() {
  const showAdmin = localStorage.getItem("isAdmin") === "true";
  const isOwner = JSON.parse(localStorage.getItem("user") ?? "{}").role === "owner";
  return showAdmin || isOwner ? <a href="/admin">Admin</a> : null;
}
`,
    });
    expect(findings.map((f) => [f.line, f.confidence])).toEqual([
      [2, "high"],
      [3, "high"],
    ]);
  });

  it("flags a binding read from sessionStorage that gates routing", async () => {
    const findings = await run({
      "components/Guard.tsx": `"use client";
export function Guard({ children }: any) {
  const router = useRouter();
  const role = sessionStorage.getItem("userRole") ?? "member";
  if (["admin", "owner"].includes(role)) return children;
  router.replace("/");
  return null;
}
`,
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.line).toBe(4);
  });

  it("ignores writes, removals, display-only reads and unrelated keys", async () => {
    const findings = await run({
      "components/Header.tsx": `"use client";
export function Header({ membership }: any) {
  localStorage.setItem("role", membership.role);
  localStorage.removeItem("isAdmin");
  localStorage.role = "admin";
  const role = localStorage.getItem("role");
  const dark = localStorage.getItem("theme") === "dark";
  // if (localStorage.getItem("role") === "admin") showAdmin();
  return <span className={dark ? "dark" : ""}>{role}</span>;
}
`,
    });
    expect(findings).toEqual([]);
  });

  it("never reports server or Python files", async () => {
    const findings = await run({
      "app/api/admin/route.ts": `export async function GET() {
  if (localStorage.getItem("role") === "admin") return Response.json({ ok: true });
  return new Response(null, { status: 403 });
}
`,
      "app/admin.py": `if localStorage.getItem("role") == "admin":\n    pass\n`,
    });
    expect(findings).toEqual([]);
  });

  it("produces stable ids across runs", async () => {
    const a = await run({ "app/admin/page.tsx": ADMIN_PAGE });
    const b = await run({ "app/admin/page.tsx": ADMIN_PAGE });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });
});
