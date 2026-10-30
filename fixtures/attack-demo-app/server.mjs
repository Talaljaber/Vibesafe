// Zero-dependency harness: serves app/**/route.{js,mjs} and public/ on 127.0.0.1.
// vibesafe-disable-file code_quality/hardcoded-localhost
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const baseRoot = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const argVal = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const port = Number(argVal("--port") ?? 3000);
if (!Number.isInteger(port) || port < 0 || port > 65535) {
  console.error("invalid --port");
  process.exit(2);
}
const overlayArg = argVal("--overlay");

// The overlay holds changed files only, and its routes import ../lib/*. So serve a merged temp
// copy (base, then overlay on top) and let the overlay files win by being copied last.
let root = baseRoot;
let mergedDir;
if (overlayArg) {
  // Windows kill() skips exit handlers: sweep dirs whose owning harness is dead, and announce ours.
  const pidAlive = (pid) => {
    try {
      process.kill(pid, 0);
      return true;
    } catch (e) {
      return e.code === "EPERM";
    }
  };
  try {
    for (const d of fs.readdirSync(os.tmpdir())) {
      const p = path.join(os.tmpdir(), d);
      const m = /^vibesafe-harness-(\d+)-/.exec(d);
      if (m && !pidAlive(Number(m[1]))) fs.rmSync(p, { recursive: true, force: true });
    }
  } catch {
    // best effort
  }
  mergedDir = fs.mkdtempSync(path.join(os.tmpdir(), `vibesafe-harness-${process.pid}-`));
  console.log(`MERGED ${mergedDir}`);
  const skip = (src) => !src.split(path.sep).includes("node_modules");
  fs.cpSync(baseRoot, mergedDir, { recursive: true, filter: skip });
  fs.cpSync(path.resolve(overlayArg), mergedDir, { recursive: true, filter: skip });
  root = mergedDir;
  const cleanup = () => {
    try {
      fs.rmSync(mergedDir, { recursive: true, force: true });
    } catch {
      // best effort
    }
  };
  process.on("exit", cleanup);
  for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => process.exit(0));
}

function walk(dir) {
  const out = [];
  if (!fs.existsSync(dir)) return out;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

// Same rules as nextRoutePath: strip (groups) and @slots.
function routeSegments(rel) {
  const m = /^app\/(?:(.*)\/)?route\.(?:js|mjs)$/.exec(rel);
  if (!m) return undefined;
  return (m[1] ?? "")
    .split("/")
    .filter((s) => s !== "" && !/^\(.*\)$/.test(s) && !s.startsWith("@"));
}

const routes = [];
for (const abs of walk(path.join(root, "app"))) {
  const segs = routeSegments(path.relative(root, abs).split(path.sep).join("/"));
  if (segs) routes.push({ segs, file: abs });
}

function match(segs, parts) {
  const params = {};
  for (let i = 0; i < segs.length; i++) {
    const s = segs[i];
    const catchAll = /^\[\[?\.\.\.(\w+)\]\]?$/.exec(s);
    if (catchAll) {
      params[catchAll[1]] = parts.slice(i);
      return params;
    }
    const dyn = /^\[(\w+)\]$/.exec(s);
    if (dyn) {
      if (parts[i] === undefined) return undefined;
      params[dyn[1]] = parts[i];
    } else if (s !== parts[i]) {
      return undefined;
    }
  }
  return parts.length === segs.length ? params : undefined;
}

const TYPES = { ".json": "application/json", ".html": "text/html", ".txt": "text/plain" };

function send(res, status, body, type = "application/json") {
  res.writeHead(status, { "content-type": type, "x-vibesafe-harness": "1" });
  res.end(body);
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const rawParts = url.pathname.split("/").filter(Boolean);
    let parts;
    try {
      parts = rawParts.map((p) => decodeURIComponent(p));
    } catch {
      return send(res, 400, JSON.stringify({ error: "bad request" }));
    }
    if (parts.some((p) => p === ".." || p.includes("/") || p.includes("\\") || p.includes("\0"))) {
      return send(res, 400, JSON.stringify({ error: "bad request" }));
    }
    for (const r of routes) {
      const params = match(r.segs, parts);
      if (!params) continue;
      const mod = await import(pathToFileURL(r.file).href);
      const handler = mod[req.method ?? "GET"];
      if (typeof handler !== "function") {
        return send(res, 405, JSON.stringify({ error: "method not allowed" }));
      }
      const chunks = [];
      for await (const c of req) chunks.push(c);
      const init = { method: req.method, headers: req.headers };
      if (!["GET", "HEAD"].includes(req.method ?? "GET")) init.body = Buffer.concat(chunks);
      const response = await handler(new Request(url, init), { params: Promise.resolve(params) });
      const headers = { "x-vibesafe-harness": "1" };
      response.headers.forEach((v, k) => {
        headers[k] = v;
      });
      res.writeHead(response.status, headers);
      return res.end(Buffer.from(await response.arrayBuffer()));
    }
    if ((req.method === "GET" || req.method === "HEAD") && parts.length > 0) {
      const pub = path.join(root, "public");
      const abs = path.join(pub, ...parts);
      if (abs.startsWith(pub + path.sep) && fs.existsSync(abs) && fs.statSync(abs).isFile()) {
        const type = TYPES[path.extname(abs)] ?? "application/octet-stream";
        return send(res, 200, fs.readFileSync(abs), type);
      }
    }
    return send(res, 404, JSON.stringify({ error: "not found" }));
  } catch (err) {
    console.error(err);
    if (res.headersSent) return res.destroy();
    return send(res, 500, JSON.stringify({ error: "internal error" }));
  }
});

server.listen(port, "127.0.0.1", () => {
  console.log(`LISTENING ${server.address().port}`);
});
