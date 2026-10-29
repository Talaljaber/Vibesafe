import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ScanContext } from "@talaljaber/vibesafe-shared";

vi.mock("../../src/detectors/utils/strip-comments", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/detectors/utils/strip-comments")>();
  return { ...actual, stripComments: vi.fn(actual.stripComments) };
});

import { stripComments } from "../../src/detectors/utils/strip-comments";
import { MissingAuthDetector } from "../../src/detectors/missing-auth-detector";
import { MissingValidationDetector } from "../../src/detectors/missing-validation-detector";
import {
  isStripeWebhookRoute,
  mayBeStripeWebhookFile,
} from "../../src/detectors/stripe-webhook-detector";

const strip = vi.mocked(stripComments);

const ctx = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake",
  projectContext: { dependencies: { express: "^4.0.0" } } as never,
  files: Object.keys(files),
  config: {} as never,
  readFile: async (f) => files[f] ?? "",
});

/** True when stripComments ever received exactly this file content. */
const stripped = (content: string): boolean => strip.mock.calls.some(([c]) => c === content);

const nextRoute = `export async function POST(req: Request) {
  const body = await req.json();
  return Response.json({ id: body.id });
}`;
const expressRoute = `const express = require("express");
const app = express();
app.post("/orders", (req, res) => res.json({ total: req.body.total }));`;

describe("Stripe webhook raw-text pre-filter", () => {
  beforeEach(() => {
    strip.mockClear();
  });

  it("only passes files whose path or content mention stripe or webhook", () => {
    expect(mayBeStripeWebhookFile("app/api/users/route.ts", nextRoute)).toBe(false);
    expect(mayBeStripeWebhookFile("app/api/webhooks/route.ts", nextRoute)).toBe(true);
    expect(mayBeStripeWebhookFile("app/api/pay/route.ts", `import Stripe from "stripe";`)).toBe(
      true,
    );
  });

  it("never strips comments for a file without stripe or webhook text", () => {
    expect(isStripeWebhookRoute("app/api/users/route.ts", nextRoute)).toBe(false);
    expect(stripped(nextRoute)).toBe(false);
  });

  it("still strips comments when the pre-filter passes", () => {
    const src = `import Stripe from "stripe";\n${nextRoute}`;
    isStripeWebhookRoute("app/api/pay/route.ts", src);
    expect(stripped(src)).toBe(true);
  });

  it("keeps auth and validation results on Next and Express routes without the expensive path", async () => {
    const files = { "app/api/users/route.ts": nextRoute, "server.js": expressRoute };
    const authFindings = await new MissingAuthDetector().detect(ctx(files));
    const validationFindings = await new MissingValidationDetector().detect(ctx(files));
    expect(authFindings.map((f) => f.file).sort()).toEqual(["app/api/users/route.ts", "server.js"]);
    expect(validationFindings.map((f) => f.file).sort()).toEqual([
      "app/api/users/route.ts",
      "server.js",
    ]);
    expect(stripped(nextRoute)).toBe(false);
    expect(stripped(expressRoute)).toBe(false);
  });
});
