import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { BrowserStorageDetector } from "../../src/detectors/browser-storage-detector";
import { CodebaseMessDetector } from "../../src/detectors/codebase-mess-detector";
import { clientPrecedence } from "../../src/detectors/groups/client";
import { expectRubric } from "../helpers/rubric";

const createContext = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake/path",
  projectContext: { framework: "nextjs" } as any,
  files: Object.keys(files),
  config: {} as any,
  readFile: async (file) => files[file] ?? "",
});

async function run(files: Record<string, string>) {
  const findings = await new BrowserStorageDetector().detect(createContext(files));
  expectRubric(findings);
  return findings;
}

const STORAGE = "frontend_exposure/secret-in-web-storage";
const LOG = "frontend_exposure/sensitive-data-console-log";

describe("BrowserStorageDetector: frontend_exposure/secret-in-web-storage", () => {
  it("flags an API secret and a token written to web storage", async () => {
    const findings = await run({
      "app/settings/keys/page.tsx": `"use client";
export default function Keys() {
  async function create() {
    const res = await fetch("/api/keys", { method: "POST" });
    const data = await res.json();
    localStorage.setItem("api_key_secret", data.secret);
    sessionStorage.setItem("auth", accessToken);
    localStorage.jwt = data.token;
  }
  return <button onClick={create}>Create</button>;
}
`,
    });
    expect(findings.map((f) => [f.line, f.confidence])).toEqual([
      [6, "high"],
      [7, "medium"],
      [8, "high"],
    ]);
    expect(findings.every((f) => f.ruleId === STORAGE && f.severity === "medium")).toBe(true);
    expect(findings[0]!.category).toBe("frontend_exposure");
  });

  it("ignores non-secret keys, generated ids, literals, reads and removals", async () => {
    const findings = await run({
      "components/Shop.tsx": `"use client";
export function Shop({ cart, theme, org }: any) {
  localStorage.setItem("cart", JSON.stringify(cart));
  localStorage.setItem("theme", theme);
  localStorage.setItem("orgId", org.id);
  localStorage.setItem("deviceId", crypto.randomUUID());
  localStorage.setItem("token", "");
  localStorage.setItem("tokenExpiresAt", String(expiresAt));
  localStorage.removeItem("token");
  const saved = localStorage.getItem("token");
  // localStorage.setItem("token", session.access_token);
  return <p>{saved}</p>;
}
`,
    });
    expect(findings).toEqual([]);
  });

  it("never reports server or Python files", async () => {
    const findings = await run({
      "app/api/login/route.ts": `export async function POST() {
  const token = await issue();
  localStorage.setItem("token", token);
  return Response.json({ ok: true });
}
`,
      "app/store.py": `localStorage.setItem("token", token)\n`,
      "lib/storage.ts": `export const save = (token: string) => storage.setItem("token", token);\n`,
    });
    expect(findings).toEqual([]);
  });
});

describe("BrowserStorageDetector: frontend_exposure/sensitive-data-console-log", () => {
  const LOGIN = `"use client";
import { getBrowserClient } from "@/lib/client/supabase";
export default function Login() {
  async function onSubmit(email: string, password: string) {
    const supabase = getBrowserClient();
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) return;
    console.log("signed in", data.session);
  }
  return <form />;
}
`;

  it("flags a whole auth session object (high/high)", async () => {
    const findings = await run({ "app/login/page.tsx": LOGIN });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe(LOG);
    expect(findings[0]!.severity).toBe("high");
    expect(findings[0]!.confidence).toBe("high");
    expect(findings[0]!.line).toBe(8);
  });

  it("flags tokens and the signed-in user object, and card numbers at medium", async () => {
    const findings = await run({
      "components/Debug.tsx": `"use client";
export function Debug({ accessToken, cardNumber }: any) {
  useEffect(() => {
    console.debug(accessToken);
    supabase.auth.getUser().then(() => {});
  }, []);
  const { data: { user } } = useAuthUser();
  console.log(user);
  console.info("card", cardNumber);
  return null;
}
`,
    });
    expect(findings.map((f) => [f.line, f.severity])).toEqual([
      [4, "high"],
      [8, "high"],
      [9, "medium"],
    ]);
  });

  it("ignores ids, plain messages and non-auth objects", async () => {
    const findings = await run({
      "components/Quiet.tsx": `"use client";
export function Quiet({ user, session, tokenCount }: any) {
  console.log("token refreshed");
  console.log(session.user.id);
  console.log(user.email === "a@b.c");
  console.log(tokenCount);
  // console.log(accessToken);
  return null;
}
`,
    });
    expect(findings).toEqual([]);
  });

  it("coexists with code_quality/console-log so the auto-fix stays reachable", async () => {
    const files = { "app/login/page.tsx": LOGIN };
    const mine = await run(files);
    const generic = await new CodebaseMessDetector().detect(createContext(files));
    const genericLog = generic.filter((f) => f.ruleId === "code_quality/console-log");
    expect(mine.map((f) => f.line)).toEqual([8]);
    expect(genericLog.map((f) => f.line)).toContain(8);
    expect(clientPrecedence).toEqual([]);
  });

  it("produces stable ids across runs", async () => {
    const a = await run({ "app/login/page.tsx": LOGIN });
    const b = await run({ "app/login/page.tsx": LOGIN });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });
});

describe("BrowserStorageDetector: precision", () => {
  it("ignores boolean names and keys that only mention a credential", async () => {
    const findings = await run({
      "components/Ui.tsx": `"use client";
export function Ui({ showPassword, hasToken, step }: any) {
  console.log(showPassword);
  console.log(hasToken);
  localStorage.setItem("onboardingSessionStep", step);
  localStorage.setItem("checkoutSession", step);
  localStorage.setItem("showTokenBanner", step);
  return null;
}
`,
    });
    expect(findings).toHaveLength(0);
  });

  it("still flags a credential key and a logged token", async () => {
    const findings = await run({
      "components/Auth.tsx": `"use client";
export function save(accessToken: string) {
  localStorage.setItem("auth_token", accessToken);
  console.log(accessToken);
}
`,
    });
    expect(findings.map((f) => f.ruleId).sort()).toEqual([STORAGE, LOG]);
  });
});

describe("round 2: CSRF tokens", () => {
  it("does not flag a CSRF token in session storage", async () => {
    const findings = await run({
      "components/Form.tsx": `"use client";
export function save(csrfToken: string) {
  sessionStorage.setItem("csrf_token", csrfToken);
}
`,
    });
    expect(findings.filter((f) => f.ruleId === STORAGE)).toHaveLength(0);
  });
});