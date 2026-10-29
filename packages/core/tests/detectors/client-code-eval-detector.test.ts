import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { ClientCodeEvalDetector } from "../../src/detectors/client-code-eval-detector";
import { expectRubric } from "../helpers/rubric";

const createContext = (files: Record<string, string>, targets?: string[]): ScanContext => ({
  rootPath: "/fake/path",
  projectContext: { framework: "nextjs", dependencies: { react: "18.2.0" } } as any,
  files: targets ?? Object.keys(files),
  config: {} as any,
  readFile: async (file) => files[file] ?? "",
});

async function run(files: Record<string, string>, targets?: string[]) {
  const findings = await new ClientCodeEvalDetector().detect(createContext(files, targets));
  expectRubric(findings);
  return findings;
}

const DYNAMIC = "injection/client-dynamic-code";
const REDIRECT = "injection/client-open-redirect";

describe("ClientCodeEvalDetector: injection/client-dynamic-code", () => {
  it("flags eval of a search param in a client component (high confidence)", async () => {
    const findings = await run({
      "app/tools/page.tsx": `"use client";
import { useSearchParams } from "next/navigation";
export default function Tools() {
  const params = useSearchParams();
  const result = eval(params.get("expr") ?? "0");
  return <p>{String(result)}</p>;
}
`,
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe(DYNAMIC);
    expect(findings[0]!.severity).toBe("high");
    expect(findings[0]!.confidence).toBe("high");
    expect(findings[0]!.line).toBe(5);
    expect(findings[0]!.category).toBe("injection");
  });

  it("follows a same-file helper that evals its parameter (medium confidence)", async () => {
    const findings = await run({
      "app/orders/page.tsx": `"use client";
import { useMemo } from "react";
import { useSearchParams } from "next/navigation";

function decodeQuery(raw: string | null) {
  if (!raw) return {};
  try {
    return eval("(" + raw + ")");
  } catch {
    return {};
  }
}

export default function Orders() {
  const searchParams = useSearchParams();
  const filters = useMemo(() => decodeQuery(searchParams.get("filters")), [searchParams]);
  return <pre>{JSON.stringify(filters)}</pre>;
}
`,
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe(DYNAMIC);
    expect(findings[0]!.line).toBe(8);
    expect(findings[0]!.confidence).toBe("medium");
  });

  it("flags new Function and string timers fed by location.hash in a Vite client module", async () => {
    const findings = await run({
      "src/widgets/run.ts": `const code = window.location.hash.slice(1);
export function start() {
  new Function(code)();
}
setTimeout(location.hash.slice(1), 10);
`,
    });
    expect(findings.map((f) => f.line).sort()).toEqual([3, 5]);
    expect(findings.every((f) => f.ruleId === DYNAMIC)).toBe(true);
  });

  it("ignores constant code, function timers and JSON.parse", async () => {
    const findings = await run({
      "app/safe/page.tsx": `"use client";
import { useSearchParams } from "next/navigation";
export default function Safe() {
  const sp = useSearchParams();
  const g = new Function("return this")();
  setTimeout(() => console.info(sp.get("q")), 10);
  const filters = JSON.parse(sp.get("filters") ?? "{}");
  // eval(sp.get("expr"))
  const note = "eval(location.hash)";
  return <p>{filters.a}{note}{String(g)}</p>;
}
`,
    });
    expect(findings).toEqual([]);
  });

  it("never reports server, Python or test files", async () => {
    const findings = await run({
      "app/api/calc/route.ts": `export async function GET(req: Request) {
  const url = new URL(req.url);
  return Response.json(eval(url.searchParams.get("expr") ?? "0"));
}
`,
      "tools/calc.py": `expr = request.args.get("expr")\nresult = eval(location.hash)\n`,
      "app/tools/page.test.tsx": `"use client";
const params = useSearchParams();
eval(params.get("expr"));
`,
    });
    expect(findings).toEqual([]);
  });

  it("produces stable ids across runs", async () => {
    const files = {
      "src/run.ts": `const code = window.location.hash.slice(1);\neval(code);\n`,
    };
    const a = await run(files);
    const b = await run(files);
    expect(a).toHaveLength(1);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });
});

describe("ClientCodeEvalDetector: injection/client-open-redirect", () => {
  it("flags location.href assigned from ?next= after login", async () => {
    const findings = await run({
      "app/login/page.tsx": `"use client";
import { useSearchParams } from "next/navigation";
export default function Login() {
  const searchParams = useSearchParams();
  async function onSubmit() {
    await signIn();
    const next = searchParams.get("next") || "/dashboard";
    window.location.href = next;
  }
  return <form onSubmit={onSubmit} />;
}
`,
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe(REDIRECT);
    expect(findings[0]!.severity).toBe("medium");
    expect(findings[0]!.line).toBe(8);
  });

  it("flags router.push of a returnTo parameter", async () => {
    const findings = await run({
      "components/AfterAuth.tsx": `"use client";
import { useRouter, useSearchParams } from "next/navigation";
export function AfterAuth() {
  const router = useRouter();
  const params = useSearchParams();
  return <button onClick={() => router.push(params.get("returnTo") ?? "/")}>Go</button>;
}
`,
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe(REDIRECT);
    expect(findings[0]!.line).toBe(6);
  });

  it("accepts a relative-path check, literal prefixes and non-redirect params", async () => {
    const findings = await run({
      "app/login/page.tsx": `"use client";
import { useRouter, useSearchParams } from "next/navigation";
export default function Login() {
  const router = useRouter();
  const searchParams = useSearchParams();
  function done() {
    const next = searchParams.get("next") ?? "/";
    if (!next.startsWith("/") || next.startsWith("//")) return router.push("/");
    router.push(next);
  }
  function search() {
    router.push("/search?q=" + searchParams.get("q"));
    router.push(searchParams.get("tab") ?? "overview");
  }
  return <div onClick={() => { done(); search(); }} />;
}
`,
    });
    expect(findings).toEqual([]);
  });

  it("never reports server redirects or Python files", async () => {
    const findings = await run({
      "app/api/auth/callback/route.ts": `import { redirect } from "next/navigation";
export async function GET(req: Request) {
  const next = new URL(req.url).searchParams.get("next") ?? "/";
  window.location.href = next;
  return redirect(next);
}
`,
      "app/views.py": `next = request.args.get("next")\nlocation.href = next\n`,
    });
    expect(findings).toEqual([]);
  });
});
