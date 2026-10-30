// @ts-check
import tseslint from "@typescript-eslint/eslint-plugin";
import tsparser from "@typescript-eslint/parser";

/** @type {import("eslint").Linter.FlatConfig[]} */
export default [
  {
    ignores: [
      "**/dist/**",
      "**/node_modules/**",
      "**/.turbo/**",
      "**/coverage/**",
      "**/*.js",
      "fixtures/**",
    ],
  },
  {
    files: ["**/*.ts", "**/*.tsx"],
    languageOptions: {
      parser: tsparser,
      parserOptions: {
        project: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: {
      "@typescript-eslint": tseslint,
    },
    rules: {
      // TypeScript strict rules
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      "@typescript-eslint/consistent-type-imports": [
        "error",
        { prefer: "type-imports", fixStyle: "inline-type-imports" },
      ],
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/await-thenable": "error",
      "@typescript-eslint/no-misused-promises": "error",

      // General rules
      "no-console": "warn",
      "prefer-const": "error",
      "no-var": "error",
    },
  },
  {
    files: ["packages/attack/src/**/*.ts"],
    ignores: ["packages/attack/src/http/**"],
    rules: {
      "no-restricted-globals": ["error", "fetch", "WebSocket", "XMLHttpRequest"],
      "no-restricted-imports": [
        "error",
        {
          paths: [
            "http",
            "https",
            "http2",
            "net",
            "tls",
            "dgram",
            "dns",
            "child_process",
            "undici",
            "node:http",
            "node:https",
            "node:http2",
            "node:net",
            "node:tls",
            "node:dgram",
            "node:dns",
            "node:child_process",
            "axios",
            "got",
            "node-fetch",
            "ws",
          ],
        },
      ],
      "no-restricted-syntax": [
        "error",
        "ImportExpression",
        "CallExpression[callee.name='require']",
      ],
    },
  },
];
