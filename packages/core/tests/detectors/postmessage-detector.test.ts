import { describe, it, expect } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { PostMessageDetector } from "../../src/detectors/postmessage-detector";
import { expectRubric } from "../helpers/rubric";

const createContext = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake/path",
  projectContext: { framework: "nextjs" } as any,
  files: Object.keys(files),
  config: {} as any,
  readFile: async (file) => files[file] ?? "",
});

async function run(files: Record<string, string>) {
  const findings = await new PostMessageDetector().detect(createContext(files));
  expectRubric(findings);
  return findings;
}

const RULE = "xss/postmessage-no-origin-check";

describe("PostMessageDetector", () => {
  it("flags a named handler that navigates to message data (high)", async () => {
    const findings = await run({
      "components/WidgetFrame.tsx": `"use client";
import { useEffect } from "react";

export function WidgetFrame({ onAdd }: { onAdd: (id: string) => void }) {
  useEffect(() => {
    function onMessage(event: MessageEvent) {
      const msg = event.data;
      if (msg?.type === "navigate") {
        window.location.href = msg.url;
      } else if (msg?.type === "add") {
        onAdd(msg.productId);
      }
    }
    window.addEventListener("message", onMessage);
    return () => window.removeEventListener("message", onMessage);
  }, [onAdd]);
  return null;
}
`,
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe(RULE);
    expect(findings[0]!.category).toBe("xss");
    expect(findings[0]!.severity).toBe("high");
    expect(findings[0]!.confidence).toBe("high");
    expect(findings[0]!.line).toBe(14);
  });

  it("flags an inline handler writing HTML (high) and one that only acts on data (medium)", async () => {
    const findings = await run({
      "src/bridge.ts": `window.addEventListener("message", (e) => {
  document.getElementById("out")!.innerHTML = e.data.html;
});
window.onmessage = handleCart;
function handleCart({ data }: MessageEvent) {
  cart.add(data.productId);
}
`,
    });
    expect(findings.map((f) => [f.line, f.severity])).toEqual([
      [1, "high"],
      [4, "medium"],
    ]);
  });

  it("accepts handlers that check event.origin or event.source", async () => {
    const findings = await run({
      "src/safe.ts": `const TRUSTED = ["https://app.example.com"];
window.addEventListener("message", (event) => {
  if (!TRUSTED.includes(event.origin)) return;
  window.location.href = event.data.url;
});
window.addEventListener("message", (event) => {
  if (event.source !== iframe.contentWindow) return;
  render(event.data);
});
`,
    });
    expect(findings).toEqual([]);
  });

  it("ignores non-window targets, handlers that ignore the data and other events", async () => {
    const findings = await run({
      "src/worker-client.ts": `const worker = new Worker("w.js");
worker.addEventListener("message", (e) => { window.location.href = e.data.url; });
window.addEventListener("message", () => { console.info("ping"); });
window.addEventListener("resize", (e) => { document.title = e.data; });
// window.addEventListener("message", (e) => eval(e.data));
`,
    });
    expect(findings).toEqual([]);
  });

  it("never reports server or Python files", async () => {
    const findings = await run({
      "app/api/hook/route.ts": `export async function POST(req: Request) {
  addEventListener("message", (e) => { eval(e.data); });
  return new Response("ok");
}
`,
      "app/listener.py": `window.addEventListener("message", lambda e: eval(e.data))\n`,
    });
    expect(findings).toEqual([]);
  });

  it("produces stable ids across runs", async () => {
    const files = {
      "src/b.ts": `window.addEventListener("message", (e) => { location.assign(e.data); });\n`,
    };
    const a = await run(files);
    const b = await run(files);
    expect(a).toHaveLength(1);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });
});

describe("PostMessageDetector: origin matching and delegation", () => {
  it("flags a handler whose only origin mention is window.location.origin", async () => {
    const findings = await run({
      "components/Frame.tsx": `"use client";
import { useEffect } from "react";
export function Frame() {
  useEffect(() => {
    window.addEventListener("message", (e) => {
      window.location.href = window.location.origin + e.data.path;
    });
  }, []);
  return null;
}
`,
    });
    expect(findings.filter((f) => f.ruleId === RULE)).toHaveLength(1);
  });

  it("follows a delegating handler into the named function", async () => {
    const findings = await run({
      "components/Frame.tsx": `"use client";
import { useEffect } from "react";
function handleMessage(e: MessageEvent) {
  window.location.href = e.data.url;
}
export function Frame() {
  useEffect(() => {
    window.addEventListener("message", (e) => handleMessage(e));
  }, []);
  return null;
}
`,
    });
    expect(findings.filter((f) => f.ruleId === RULE)).toHaveLength(1);
  });

  it("accepts a delegated handler that checks e.origin", async () => {
    const findings = await run({
      "components/Frame.tsx": `"use client";
import { useEffect } from "react";
function handleMessage(e: MessageEvent) {
  if (e.origin !== "https://pay.example.com") return;
  window.location.href = e.data.url;
}
export function Frame() {
  useEffect(() => {
    window.addEventListener("message", (e) => handleMessage(e));
  }, []);
  return null;
}
`,
    });
    expect(findings.filter((f) => f.ruleId === RULE)).toHaveLength(0);
  });
});

describe("round 2: origin checks", () => {
  const wrap = (fn: string) => ({
    "components/W.tsx": `"use client";
import { useEffect } from "react";
${fn}
export function W() {
  useEffect(() => {
    window.addEventListener("message", onMessage);
    return () => window.removeEventListener("message", onMessage);
  }, []);
  return null;
}
`,
  });
  it("accepts a helper named after the origin", async () => {
    const findings = await run(
      wrap(`function onMessage(event: MessageEvent) {
  if (!isTrustedOrigin(event)) return;
  window.location.href = event.data.url;
}`),
    );
    expect(findings).toHaveLength(0);
  });
  it("accepts a same-file helper that reads the origin", async () => {
    const findings = await run(
      wrap(`function isValidMessage(ev: MessageEvent) {
  return ev.origin === "https://app.example.com";
}
function onMessage(event: MessageEvent) {
  if (!isValidMessage(event)) return;
  window.location.href = event.data.url;
}`),
    );
    expect(findings).toHaveLength(0);
  });
  it("accepts an allowlist membership check", async () => {
    const findings = await run(
      wrap(`function onMessage(event: MessageEvent) {
  if (!ALLOWED.includes(event.origin)) return;
  window.location.href = event.data.url;
}`),
    );
    expect(findings).toHaveLength(0);
  });
  it("still flags a handler that only logs the origin", async () => {
    const findings = await run(
      wrap(`function onMessage(event: MessageEvent) {
  console.log(event.origin);
  window.location.href = event.data.url;
}`),
    );
    expect(findings).toHaveLength(1);
  });
});

describe("round 3: origin checks and bare listeners", () => {
  const handler = (body: string, head = "") => ({
    "components/W.tsx": `"use client";
${head}
export function W() {
  useEffect(() => {
    window.addEventListener("message", (e) => {
${body}
      window.location.href = e.data.url;
    });
  }, []);
  return null;
}
`,
  });
  const clean: [string, string, string?][] = [
    ["local origin compared", "const origin = e.origin;\nif (origin !== TRUSTED) return;"],
    ["helper call", "if (!isTrustedOrigin(e.origin)) return;"],
    ["helper call 2", "if (!isAllowed(e.origin)) return;"],
    ["computed lookup", "if (!TRUSTED[e.origin]) return;"],
    ["switch", "switch (e.origin) { case A: break; default: return; }"],
    ["URL parse", "if (new URL(e.origin).hostname !== HOST) return;"],
  ];
  for (const [name, body] of clean) {
    it(`does not flag: ${name}`, async () => {
      expect(await run(handler(body))).toHaveLength(0);
    });
  }
  it("still flags console.log(e.origin)", async () => {
    const f = await run(handler("console.log(e.origin);"));
    expect(f).toHaveLength(1);
  });
  it("flags a bare addEventListener in a tsx component", async () => {
    const f = await run({
      "components/B.tsx": `"use client";
export function B() {
  useEffect(() => {
    addEventListener("message", (e) => eval(e.data.code));
  }, []);
  return null;
}
`,
    });
    expect(f).toHaveLength(1);
  });
});
