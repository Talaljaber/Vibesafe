import { describe, it, expect } from "vitest";
import { OpenRedirectDetector } from "../../src/detectors/open-redirect-detector.js";
import { run } from "../helpers/injection.js";

const detector = new OpenRedirectDetector();

const wrap = (body: string): Record<string, string> => ({
  "server.js": `const express = require("express");
const app = express();
app.get("/go", (req, res) => {
  const v = req.query.next;
${body}
});`,
});

describe("OpenRedirectDetector same-site checks", () => {
  const safe: Record<string, string> = {
    "binding check": `  const safe = v.startsWith("/") && !v.startsWith("//") && !v.includes("\\\\");
  res.redirect(safe ? v : "/");`,
    "inline ternary": `  res.redirect(v.startsWith("/") && !v.startsWith("//") ? v : "/");`,
    "origin comparison": `  const t = new URL(v, "https://app.example.com");
  res.redirect(new URL(v, "https://app.example.com").origin === expectedOrigin ? v : "/");`,
    allowlist: `  res.redirect(allowlist.includes(v) ? v : "/");`,
    "isSafe helper": `  res.redirect(isSafeRedirect(v) ? v : "/");`,
    "isInternal helper": `  res.redirect(isInternalPath(v) ? v : "/");`,
  };
  for (const [name, body] of Object.entries(safe)) {
    it(`does not flag: ${name}`, async () => {
      expect(await run(detector, wrap(body))).toHaveLength(0);
    });
  }

  const bad: Record<string, string> = {
    "single slash only": `  res.redirect(v.startsWith("/") ? v : "/");`,
    "startsWith http": `  res.redirect(v.startsWith("http") ? v : "/");`,
    "isUrl helper": `  res.redirect(isUrl(v) ? v : "/");`,
  };
  for (const [name, body] of Object.entries(bad)) {
    it(`still flags: ${name}`, async () => {
      expect(await run(detector, wrap(body))).toHaveLength(1);
    });
  }
});
