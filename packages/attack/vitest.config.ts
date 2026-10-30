import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    // Live-probe tests start a local harness server; allow slow runners
    testTimeout: 60000,
    hookTimeout: 60000,
    // Package tests live in tests/ (chokepoint test guards the network gate)
    passWithNoTests: true,
    include: ["src/**/*.test.ts", "tests/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "lcov"],
      include: ["src/**/*.ts"],
    },
  },
});
