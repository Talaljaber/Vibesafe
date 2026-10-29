import { describe, it, expect } from "vitest";
import { isServerOnlyPublicName } from "../../src/detectors/patterns/public-env-names.js";

describe("isServerOnlyPublicName", () => {
  it.each([
    "NEXT_PUBLIC_OPENAI_API_KEY",
    "VITE_ANTHROPIC_KEY",
    "REACT_APP_RESEND_API_KEY",
    "EXPO_PUBLIC_GITHUB_TOKEN",
    "NEXT_PUBLIC_DATABASE_URL",
    "NEXT_PUBLIC_ALGOLIA_ADMIN_KEY",
    "NEXT_PUBLIC_ADMIN_KEY",
    "VITE_ADMIN_API_KEY",
    "NEXT_PUBLIC_MASTER_KEY",
    "NEXT_PUBLIC_SERVICE_KEY",
    "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_ANON",
  ])("flags %s", (name) => {
    expect(isServerOnlyPublicName(name)).toBe(true);
  });

  it.each([
    "NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY",
    "NEXT_PUBLIC_SUPABASE_ANON_KEY",
    "NEXT_PUBLIC_SUPABASE_URL",
    "NEXT_PUBLIC_OPENAI_MODEL",
    "NEXT_PUBLIC_GITHUB_CLIENT_ID",
    "NEXT_PUBLIC_SENTRY_DSN",
    "NEXT_PUBLIC_RECAPTCHA_SITE_KEY",
    "NEXT_PUBLIC_MAPBOX_ACCESS_TOKEN",
    "OPENAI_API_KEY",
    "NEXT_PUBLIC_FIREBASE_DATABASE_URL",
    "VITE_FIREBASE_DATABASE_URL",
    "REACT_APP_FIREBASE_DATABASE_URL",
    "NEXT_PUBLIC_WEBSERVICE_KEY",
    "NEXT_PUBLIC_BADMIN_KEY",
  ])("ignores %s", (name) => {
    expect(isServerOnlyPublicName(name)).toBe(false);
  });
});
