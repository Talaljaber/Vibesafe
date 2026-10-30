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
    // Code evaluation is forbidden everywhere in the attack package, src/http included.
    files: ["packages/attack/src/**/*.{ts,tsx,mts,cts}"],
    rules: {
      "no-eval": "error",
      "no-new-func": "error",
      // Belt and braces only: core no-implied-eval needs declared globals to resolve setTimeout.
      "no-implied-eval": "error",
    },
  },
  {
    files: ["packages/attack/src/**/*.{ts,tsx,mts,cts}"],
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
            "module",
            "node:module",
            "worker_threads",
            "node:worker_threads",
            "vm",
            "node:vm",
            "inspector",
            "node:inspector",
            "cluster",
            "node:cluster",
          ],
          patterns: [
            {
              group: [
                "http/*",
                "https/*",
                "http2/*",
                "dns/*",
                "node:http/*",
                "node:https/*",
                "node:http2/*",
                "node:dns/*",
                "inspector/*",
                "node:inspector/*",
              ],
              message: "Network modules are only allowed in packages/attack/src/http.",
            },
          ],
        },
      ],
      "no-restricted-properties": [
        "error",
        { object: "process", property: "getBuiltinModule" },
        { object: "process", property: "binding" },
        { object: "globalThis", property: "fetch" },
        { object: "global", property: "fetch" },
      ],
      "no-restricted-syntax": [
        "error",
        "ImportExpression",
        "CallExpression[callee.name='require']",
      ],
    },
  },
];
