#!/usr/bin/env node
/**
 * Pre-warms a local dev server before an Attack Mode demo (spec 14): GETs `/` and every
 * discovered Next.js route once, so `next dev` compiles each route before the attack runs
 * (attack probes time out after 10 s; a cold compile on a slow laptop can take longer).
 *
 *   node scripts/attack-prewarm.mjs [projectDir=.] [--target http://127.0.0.1:3000]
 *
 * Safety: every request goes through Attack Mode's safe client
 * (packages/attack/dist/http/safe-client.js), so the same gate applies: loopback only
 * (127.0.0.1, ::1, localhost), GET only, no bodies, no cookies, rate limited. Each request
 * gets the 30 s pre-warm timeout. Requires `pnpm build`.
 *
 * Exit code 0 when every route answered (any HTTP status counts: a 401 or 404 still means the
 * route compiled), 1 when the server never answered or a route timed out, 2 on usage errors.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const clientPath = path.join(repoRoot, "packages", "attack", "dist", "http", "safe-client.js");

const LOOPBACK = new Set(["127.0.0.1", "[::1]", "localhost"]);
const ROUTE_FILE_RE = /^app\/(?:(.*)\/)?route\.(?:js|mjs|ts)$/;
/** How long to keep retrying `/` while the dev server is still starting. */
const STARTUP_WAIT_MS = 30_000;

function usage(message) {
  console.error(`attack-prewarm: ${message}`);
  console.error("usage: node scripts/attack-prewarm.mjs [projectDir] [--target <loopback url>]");
  process.exit(2);
}

function parseArgs(argv) {
  let target = "http://127.0.0.1:3000";
  let dir = ".";
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--target") {
      target = argv[++i] ?? usage("--target needs a URL");
    } else if (a.startsWith("--")) {
      usage(`unknown flag ${a}`);
    } else {
      dir = a;
    }
  }
  return { target, dir: path.resolve(dir) };
}

/** Loopback-only check up front, for a clear message (the safe client's gate enforces it too). */
export function checkTarget(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, reason: `not a URL: ${raw}` };
  }
  if (url.protocol !== "http:") return { ok: false, reason: "only http:// is allowed" };
  if (!LOOPBACK.has(url.hostname)) {
    return { ok: false, reason: "loopback only (127.0.0.1, ::1, localhost)" };
  }
  return { ok: true, base: `${url.protocol}//${url.host}` };
}

function walk(dir) {
  const out = [];
  if (!fs.existsSync(dir)) return out;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === "node_modules" || e.name.startsWith(".")) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

function readResources(root) {
  try {
    const raw = JSON.parse(fs.readFileSync(path.join(root, ".vibesafe", "sessions.json"), "utf8"));
    const resources = {};
    for (const s of raw.sessions ?? []) {
      for (const [k, v] of Object.entries(s.resources ?? {})) {
        if (typeof v === "string" && !(k in resources)) resources[k] = v;
      }
    }
    return resources;
  } catch {
    return {};
  }
}

/**
 * Concrete paths for every app router route.{js,mjs,ts}: (group) and @slot segments dropped,
 * dynamic segments filled from sessions.json resources, else with a harmless placeholder (the
 * point is the compile, not the record).
 */
export function discoverPaths(root) {
  const resources = readResources(root);
  const paths = new Set(["/"]);
  for (const abs of walk(path.join(root, "app"))) {
    const rel = path.relative(root, abs).split(path.sep).join("/");
    const m = ROUTE_FILE_RE.exec(rel);
    if (!m) continue;
    const segs = (m[1] ?? "")
      .split("/")
      .filter((s) => s !== "" && !/^\(.*\)$/.test(s) && !s.startsWith("@"));
    const pattern = `/${segs.join("/")}`;
    const concrete = segs.map((s) => {
      if (!/^\[.*\]$/.test(s)) return s;
      const id = resources[pattern];
      return encodeURIComponent(id ?? "prewarm");
    });
    paths.add(`/${concrete.join("/")}`);
  }
  return [...paths];
}

async function main() {
  const { target, dir } = parseArgs(process.argv.slice(2));
  const t = checkTarget(target);
  if (!t.ok) usage(t.reason);
  if (!fs.existsSync(path.join(dir, "app"))) usage(`${dir} has no app/ directory`);
  if (!fs.existsSync(clientPath)) usage("packages/attack is not built; run `pnpm build` first");

  const { SafeHttpClient } = await import(pathToFileURL(clientPath).href);
  const client = new SafeHttpClient({ rate: 5 });
  const paths = discoverPaths(dir);
  console.log(`Pre-warming ${paths.length} routes on ${t.base} (GET only, 30 s timeout each)`);

  // Wait for the server to come up: retry `/` on connection errors for up to 30 s.
  const deadline = Date.now() + STARTUP_WAIT_MS;
  let first = await client.request({ url: `${t.base}/`, prewarm: true });
  while (first.status === 0 && !first.blocked && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 1000));
    first = await client.request({ url: `${t.base}/`, prewarm: true });
  }
  if (first.status === 0) {
    console.error(
      `FAIL  ${t.base} did not answer (${first.error ?? "no response"}). Is the dev server running?`,
    );
    process.exit(1);
  }
  console.log(`  ${String(first.status).padEnd(4)} ${String(first.ms).padStart(6)} ms  GET /`);

  let failed = 0;
  for (const p of paths.filter((x) => x !== "/")) {
    const res = await client.request({ url: `${t.base}${p}`, prewarm: true });
    const status = res.status === 0 ? "ERR " : String(res.status).padEnd(4);
    console.log(`  ${status} ${String(res.ms).padStart(6)} ms  GET ${p}`);
    if (res.status === 0) failed++;
  }
  if (failed > 0) {
    console.error(`FAIL  ${failed} route(s) did not answer. Run the pre-warm again.`);
    process.exit(1);
  }
  console.log("Warm. Every route answered; the attack will not hit a cold compile.");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
