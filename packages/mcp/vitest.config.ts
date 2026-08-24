import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    passWithNoTests: true,
    include: ["src/**/*.test.ts", "tests/**/*.test.ts"],
    testTimeout: 20000,
    coverage: {
      provider: "v8",
      reporter: ["text", "lcov"],
      include: ["src/**/*.ts"],
    },
  },
});
