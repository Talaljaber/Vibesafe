import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import {
  callArgs,
  findDeclaration,
  leadingOperands,
  loadClientFile,
  memberChain,
  parseImports,
  reactMajor,
  resolveImport,
  wholeLiteral,
} from "../../src/detectors/utils/client-source";
import { createJsSource } from "../../src/detectors/utils/js-source";

const createContext = (files: Record<string, string>, targets?: string[]): ScanContext => ({
  rootPath: "/fake/path",
  projectContext: { framework: "nextjs" } as any,
  files: targets ?? Object.keys(files),
  config: {} as any,
  readFile: async (file) => files[file] ?? "",
});

const js = (text: string) => createJsSource(text, { jsx: true });

describe("client-source: imports", () => {
  it("parses value imports and skips import type and type specifiers", () => {
    const src = js(`import type { Session } from "@/lib/server/auth";
import { type User, getUser as loadUser } from "@/lib/client/user";
import React, * as Things from "./things";
import { createBrowserClient } from "@supabase/ssr";
`);
    const imports = parseImports(src);
    expect(imports.map((i) => i.spec)).toEqual(["@/lib/client/user", "./things", "@supabase/ssr"]);
    expect([...imports[0]!.names]).toEqual([["loadUser", "getUser"]]);
    expect(imports[1]!.names.get("React")).toBe("default");
    expect(imports[1]!.names.get("Things")).toBe("*");
  });

  it("resolves @/ to the project root or src/, and relative paths, via readFile", async () => {
    const ctx = createContext(
      {
        "lib/client/api.ts": "export const a = 1;",
        "src/hooks/index.tsx": "export const b = 1;",
        "app/orders/helpers.js": "export const c = 1;",
      },
      ["app/orders/page.tsx"],
    );
    expect(await resolveImport(ctx, "app/orders/page.tsx", "@/lib/client/api")).toBe(
      "lib/client/api.ts",
    );
    expect(await resolveImport(ctx, "app/orders/page.tsx", "@/hooks")).toBe("src/hooks/index.tsx");
    expect(await resolveImport(ctx, "app\\orders\\page.tsx", "./helpers")).toBe(
      "app/orders/helpers.js",
    );
    expect(await resolveImport(ctx, "app/orders/page.tsx", "react")).toBeUndefined();
    expect(await resolveImport(ctx, "app/orders/page.tsx", "../../../outside")).toBeUndefined();
  });
});

describe("client-source: declarations and expressions", () => {
  it("finds the nearest plain or destructuring declaration before an offset", () => {
    const text = `const user = { website: "https://a.example" };
function f(user) { return user; }
const { data: store } = await db.from("stores").single();
let user = getUser();
use(user, store);
`;
    const src = js(text);
    const at = text.lastIndexOf("use(");
    const user = findDeclaration(src, "user", at)!;
    expect(text.slice(user.initStart, user.initEnd)).toBe("getUser()");
    const store = findDeclaration(src, "store", at)!;
    expect(store.destructured).toBe(true);
    expect(text.slice(store.initStart, store.initEnd)).toContain("await db.from");
    expect(findDeclaration(src, "missing", at)).toBeUndefined();
  });

  it("returns the operands that decide where a URL value starts", () => {
    const text = `x(a + "/b", "lit" + c, \`\${d}/e\`, \`/f/\${g}\`, cond ? h : "/", i || "/home")`;
    const src = js(text);
    const args = callArgs(src, text.indexOf("("));
    const lead = (k: number) =>
      leadingOperands(src, args[k]!.start, args[k]!.end).map((r) => text.slice(r.start, r.end));
    expect(args).toHaveLength(6);
    expect(lead(0)).toEqual(["a"]);
    expect(lead(1)).toEqual([]);
    expect(lead(2)).toEqual(["d"]);
    expect(lead(3)).toEqual([]);
    expect(lead(4)).toEqual(["h"]);
    expect(lead(5)).toEqual(["i"]);
  });

  it("reads member chains and whole string literals", () => {
    const text = `a.b?.c; "theme"; 'x' + y`;
    const src = js(text);
    expect(memberChain(src.code, 0, 6)).toEqual(["a", "b", "c"]);
    expect(wholeLiteral(src, 8, 15)).toBe("theme");
    expect(wholeLiteral(src, 17, text.length)).toBeUndefined();
  });

  it("reads the React major version from package dependencies", () => {
    expect(reactMajor({ dependencies: { react: "^18.2.0" } } as any)).toBe(18);
    expect(reactMajor({ dependencies: {}, devDependencies: { react: "19.0.0-rc.1" } } as any)).toBe(
      19,
    );
    expect(reactMajor({ dependencies: {} } as any)).toBeUndefined();
    expect(reactMajor(undefined)).toBeUndefined();
  });
});

describe("client-source: loadClientFile", () => {
  it("loads only client-runtime JS and skips server, Python, generated and test files", async () => {
    const files = {
      "components/A.tsx": `"use client";\nexport const A = () => null;\n`,
      "app/api/x/route.ts": `export async function GET() { window.location.href = "/"; }\n`,
      "app/page.tsx": `export default function P() { return null; }\n`,
      "app/x.py": `window.location.href = "/"\n`,
      "components/A.test.tsx": `"use client";\n`,
      "src/gen.generated.ts": `window.alert(1);\n`,
    };
    const ctx = createContext(files);
    const loaded = await Promise.all(Object.keys(files).map((f) => loadClientFile(ctx, f)));
    expect(loaded.map((l) => l?.file)).toEqual([
      "components/A.tsx",
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
    ]);
    const server = await loadClientFile(ctx, "app/page.tsx", { allowServerComponents: true });
    expect(server?.classification.kind).toBe("next-server-component");
  });
});
