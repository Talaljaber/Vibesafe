import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    passWithNoTests: true,
    include: ["src/**/*.test.ts", "tests/**/*.test.ts"],
    // The smoke and deep-scan tests take about 10 s alone and over 20 s while the full gate
    // runs in parallel with other builds.
    testTimeout: 60000,
    hookTimeout: 60000,
    coverage: {
      provider: "v8",
      reporter: ["text", "lcov"],
      include: ["src/**/*.ts"],
    },
  },
});
