// ─────────────────────────────────────────────────────────────────────────────
// Curated offline advisories for popular npm packages
//
// A deliberately small, hand-checked list: one well-known CVE per package, with the
// affected range exactly as published in the GitHub/npm advisory and a comment naming
// the first fixed version(s). It is a floor, not a vulnerability database: anything
// newer than DATASET_DATE, or any package not listed, is out of scope offline (use
// `--online` for an OSV lookup). Matching is by exact package name only.
//
// Severity is ours (rubric): `critical` only where the flaw is directly exploitable
// in a typical deployment (Next.js middleware bypass); library flaws that need a
// specific usage pattern are `high` or `medium`.
// ─────────────────────────────────────────────────────────────────────────────

import type { Severity } from "@talaljaber/vibesafe-shared";

/** Date the entries below were last reviewed. */
export const DATASET_DATE = "2026-10-29";

export interface NpmAdvisory {
  /** Exact npm package name. */
  name: string;
  /** CVE identifier. */
  cve: string;
  /** Affected versions as an npm range (see utils/semver.ts). */
  affected: string;
  /** First fixed versions, lowest major line first (shown in fix steps). */
  fixed: string[];
  severity: Severity;
  /** One-line plain-English summary of the flaw. */
  summary: string;
  /** Build/dev-server tooling: a devDependency is not a reason to lower the severity. */
  buildTool?: boolean | undefined;
}

export const NPM_ADVISORIES: readonly NpmAdvisory[] = [
  {
    // Fixed in 12.3.5, 13.5.9, 14.2.25 and 15.2.3.
    name: "next",
    cve: "CVE-2025-29927",
    affected: ">=11.1.4 <12.3.5 || >=13.0.0 <13.5.9 || >=14.0.0 <14.2.25 || >=15.0.0 <15.2.3",
    fixed: ["12.3.5", "13.5.9", "14.2.25", "15.2.3"],
    severity: "critical",
    summary:
      "a request carrying the internal x-middleware-subrequest header skips middleware entirely, so any authentication or authorization enforced in middleware can be bypassed",
  },
  {
    // Fixed in 0.21.2.
    name: "axios",
    cve: "CVE-2021-3749",
    affected: "<0.21.2",
    fixed: ["0.21.2"],
    severity: "high",
    summary:
      "a regular expression in its header trimming can be driven into catastrophic backtracking (ReDoS), letting crafted responses stall the process",
  },
  {
    // Fixed in 9.0.0.
    name: "jsonwebtoken",
    cve: "CVE-2022-23540",
    affected: "<9.0.0",
    fixed: ["9.0.0"],
    severity: "high",
    summary:
      "jwt.verify() without an explicit algorithms list falls back to accepting the 'none' algorithm when no secret is supplied, so unsigned tokens can pass verification",
  },
  {
    // Fixed in 4.17.21.
    name: "lodash",
    cve: "CVE-2021-23337",
    affected: "<4.17.21",
    fixed: ["4.17.21"],
    severity: "high",
    summary:
      "_.template() can be made to execute arbitrary code when an attacker controls the template options (command injection)",
  },
  {
    // Fixed in 0.2.4 and 1.2.6.
    name: "minimist",
    cve: "CVE-2021-44906",
    affected: "<0.2.4 || >=1.0.0 <1.2.6",
    fixed: ["0.2.4", "1.2.6"],
    severity: "high",
    summary:
      "crafted arguments can write to Object.prototype (prototype pollution), changing behaviour across the whole process",
  },
  {
    // Fixed in 2.6.7 and 3.1.1.
    name: "node-fetch",
    cve: "CVE-2022-0235",
    affected: "<2.6.7 || >=3.0.0 <3.1.1",
    fixed: ["2.6.7", "3.1.1"],
    severity: "high",
    summary:
      "cookies and Authorization headers are forwarded to a different host when a response redirects there, leaking credentials to third parties",
  },
  {
    // Fixed in 4.19.2 (and 5.0.0-beta.3).
    name: "express",
    cve: "CVE-2024-29041",
    affected: "<4.19.2 || >=5.0.0-alpha.1 <5.0.0-beta.3",
    fixed: ["4.19.2"],
    severity: "medium",
    summary:
      "res.redirect() and res.location() mis-encode some malformed URLs, so allow-listed redirects can be steered to an attacker's site (open redirect)",
  },
  {
    // Fixed in 5.2.4, 6.2.3, 7.5.10 and 8.17.1.
    name: "ws",
    cve: "CVE-2024-37890",
    affected: ">=2.1.0 <5.2.4 || >=6.0.0 <6.2.3 || >=7.0.0 <7.5.10 || >=8.0.0 <8.17.1",
    fixed: ["5.2.4", "6.2.3", "7.5.10", "8.17.1"],
    severity: "high",
    summary:
      "an upgrade request with more headers than the server's limit crashes the WebSocket server (denial of service)",
  },
  {
    // Fixed in 1.15.6.
    name: "follow-redirects",
    cve: "CVE-2024-28849",
    affected: "<1.15.6",
    fixed: ["1.15.6"],
    severity: "medium",
    summary:
      "the Proxy-Authorization header is kept when a request is redirected to another host, leaking proxy credentials",
  },
  {
    // Fixed in 1.0.2 and 2.2.2.
    name: "json5",
    cve: "CVE-2022-46175",
    affected: "<1.0.2 || >=2.0.0 <2.2.2",
    fixed: ["1.0.2", "2.2.2"],
    severity: "high",
    summary:
      "JSON5.parse() lets a crafted __proto__ key set properties on the returned object's prototype (prototype pollution)",
  },
  {
    // Fixed in 6.2.4, 6.3.3, 6.4.1, 6.5.3, 6.6.1, 6.7.3, 6.8.3, 6.9.7 and 6.10.3.
    name: "qs",
    cve: "CVE-2022-24999",
    affected:
      "<6.2.4 || >=6.3.0 <6.3.3 || >=6.4.0 <6.4.1 || >=6.5.0 <6.5.3 || >=6.6.0 <6.6.1 || >=6.7.0 <6.7.3 || >=6.8.0 <6.8.3 || >=6.9.0 <6.9.7 || >=6.10.0 <6.10.3",
    fixed: ["6.2.4", "6.3.3", "6.4.1", "6.5.3", "6.6.1", "6.7.3", "6.8.3", "6.9.7", "6.10.3"],
    severity: "high",
    summary:
      "a query string with a crafted __proto__ key pollutes object prototypes and can hang the Node process (denial of service)",
  },
  {
    // Fixed in 3.1.7.
    name: "ejs",
    cve: "CVE-2022-29078",
    affected: "<3.1.7",
    fixed: ["3.1.7"],
    severity: "high",
    summary:
      "the outputFunctionName render option is inserted into generated code, so passing request data as render options leads to remote code execution",
  },
  {
    // Fixed in 4.7.7.
    name: "handlebars",
    cve: "CVE-2021-23369",
    affected: "<4.7.7",
    fixed: ["4.7.7"],
    severity: "high",
    summary:
      "compiling a template from an untrusted source can execute arbitrary code (remote code execution)",
  },
  {
    // Fixed in 7.23.2 (and 8.0.0-alpha.4).
    name: "@babel/traverse",
    cve: "CVE-2023-45133",
    affected: "<7.23.2 || >=8.0.0-alpha.0 <8.0.0-alpha.4",
    fixed: ["7.23.2"],
    severity: "high",
    summary:
      "compiling specially crafted source code with a plugin that evaluates code paths runs attacker code on the build machine",
    buildTool: true,
  },
  {
    // Fixed in 2.29.4.
    name: "moment",
    cve: "CVE-2022-31129",
    affected: ">=2.18.0 <2.29.4",
    fixed: ["2.29.4"],
    severity: "high",
    summary:
      "parsing a long user-supplied date string takes quadratic time, so one request can block the event loop (ReDoS)",
  },
];
