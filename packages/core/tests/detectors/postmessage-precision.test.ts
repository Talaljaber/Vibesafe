import { describe, it, expect } from "vitest";
import { PostMessageDetector } from "../../src/detectors/postmessage-detector.js";
import { run } from "../helpers/injection.js";

const page = (body: string): Record<string, string> => ({
  "components/Frame.tsx": `"use client";
import { useEffect, useState } from "react";
export function Frame() {
  const [origin, setOrigin] = useState("");
  useEffect(() => {
    function onMessage(event: MessageEvent) {
${body}
      localStorage.setItem("x", event.data.value);
    }
    window.addEventListener("message", onMessage);
    return () => window.removeEventListener("message", onMessage);
  }, []);
  return null;
}`,
});

describe("postMessage uses of event.origin that are not checks", () => {
  const notChecks: Record<string, string> = {
    "reply to the sender": `      event.source.postMessage({ ok: true }, event.origin);`,
    "react setter": `      setOrigin(event.origin);`,
    "JSON.stringify": `      console.debug(JSON.stringify(event.origin));
      const s = JSON.stringify(event.origin);`,
    "String()": `      const s = String(event.origin);`,
    "analytics track": `      analytics.track("msg", event.origin);`,
    "analytics capture": `      posthog.capture("msg", { from: event.origin });`,
    "array literal": `      const seen = [event.origin];`,
  };
  for (const [n, body] of Object.entries(notChecks))
    it(`still flags: ${n}`, async () => {
      expect(await run(new PostMessageDetector(), page(body))).toHaveLength(1);
    });

  const checks: Record<string, string> = {
    "strict comparison": `      if (event.origin !== "https://trusted.example") return;`,
    "computed allowlist lookup": `      if (!TRUSTED[event.origin]) return;`,
    "allowlist includes": `      if (!ALLOWED.includes(event.origin)) return;`,
    "helper call": `      if (!isTrustedOrigin(event.origin)) return;`,
  };
  for (const [n, body] of Object.entries(checks))
    it(`does not flag: ${n}`, async () => {
      expect(await run(new PostMessageDetector(), page(body))).toHaveLength(0);
    });
});
