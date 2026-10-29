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
