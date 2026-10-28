import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    // Git-history tests spawn real git processes; allow slow CI/Windows runners
    testTimeout: 30000,
    hookTimeout: 30000,
    // Passes when no test files exist — tests are added in Phase 3+
    passWithNoTests: true,
    include: ["src/**/*.test.ts", "tests/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "lcov"],
      include: ["src/**/*.ts"],
    },
  },
});
