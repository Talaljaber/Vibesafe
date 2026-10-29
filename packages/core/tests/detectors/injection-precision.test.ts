import { describe, it, expect } from "vitest";
import { PathTraversalDetector } from "../../src/detectors/path-traversal-detector.js";
import { SsrfDetector } from "../../src/detectors/ssrf-detector.js";
import { SqlInjectionDetector } from "../../src/detectors/sql-injection-detector.js";
import { run } from "../helpers/injection.js";

const route = (body: string, imports = ""): Record<string, string> => ({
  "server.js": `const express = require("express");
const fs = require("fs");
const path = require("path");
${imports}
const app = express();
app.get("/x", async (req, res) => {
  const name = req.query.name;
${body}
});`,
});

describe("path guard on a resolved binding", () => {
  const d = new PathTraversalDetector();
  const safe: Record<string, string> = {
    "resolve + startsWith": `  const full = path.resolve("/srv/uploads", name);
  if (!full.startsWith("/srv/uploads/")) return res.sendStatus(400);
  res.send(fs.readFileSync(full));`,
    "normalize + startsWith": `  const full = path.normalize("/srv/uploads/" + name);
  if (!full.startsWith("/srv/uploads/")) return res.sendStatus(400);
  res.send(fs.readFileSync(full));`,
    "startsWith with path.sep": `  const full = path.resolve("/app/public", name);
  if (!full.startsWith("/app/public" + path.sep)) return res.sendStatus(400);
  res.send(fs.readFileSync(full));`,
  };
  for (const [n, body] of Object.entries(safe))
    it(`does not flag: ${n}`, async () => {
      expect(await run(d, route(body))).toHaveLength(0);
    });
  it("still flags a literal startsWith on a raw (un-normalized) value", async () => {
    const body = `  const full = "/srv/uploads/" + name;
  if (!full.startsWith("/srv/uploads/")) return res.sendStatus(400);
  res.send(fs.readFileSync(full));`;
    expect(await run(d, route(body))).toHaveLength(1);
  });
  it("still flags when resolve appears only elsewhere in the condition", async () => {
    const body = `  const full = "/srv/uploads/" + name;
  if (!full.startsWith("/srv/uploads/") || path.resolve("x") === "") return res.sendStatus(400);
  res.send(fs.readFileSync(full));`;
    expect(await run(d, route(body))).toHaveLength(1);
  });
});

describe("axios baseURL and url", () => {
  const d = new SsrfDetector();
  const ax = (call: string): Record<string, string> => ({
    "server.js": `const express = require("express");
const axios = require("axios");
const app = express();
app.get("/x", async (req, res) => {
  const u = req.query.u;
  ${call}
});`,
  });
  it("flags a tainted url beside a fixed baseURL", async () => {
    expect(
      await run(d, ax(`await axios({ baseURL: "https://api.example.com", url: u });`)),
    ).toHaveLength(1);
  });
  it("flags a tainted url beside an env baseURL", async () => {
    expect(
      await run(d, ax(`await axios.request({ url: u, baseURL: process.env.API_URL });`)),
    ).toHaveLength(1);
  });
  it("flags a tainted baseURL", async () => {
    expect(await run(d, ax(`await axios({ baseURL: u, url: "/ping" });`))).toHaveLength(1);
  });
  it("does not flag a url with a literal slash prefix and a fixed baseURL", async () => {
    expect(
      await run(d, ax('await axios({ baseURL: "https://api.example.com", url: `/items/${u}` });')),
    ).toHaveLength(0);
  });
});

describe("placeholder lists built with Array.from", () => {
  const d = new SqlInjectionDetector();
  const q = (body: string): Record<string, string> => ({
    "server.js": `const express = require("express");
const app = express();
app.post("/x", async (req, res) => {
  const ids = req.body.ids;
${body}
});`,
  });
  it("does not flag an inline indexed placeholder list", async () => {
    const body =
      '  await db.query(`SELECT * FROM t WHERE id IN (${Array.from(ids, (_, i) => `$${i + 1}`).join(",")})`, ids);';
    expect(await run(d, q(body))).toHaveLength(0);
  });
  it("does not flag a bound length-based placeholder list", async () => {
    const body = `  const ph = Array.from({ length: ids.length }, () => "?").join(",");
  await db.query(\`SELECT * FROM t WHERE id IN (\${ph})\`, ids);`;
    expect(await run(d, q(body))).toHaveLength(0);
  });
  it("still flags a list that interpolates the element", async () => {
    const body = `  const ph = Array.from(ids, (x) => \`'\${x}'\`).join(",");
  await db.query(\`SELECT * FROM t WHERE id IN (\${ph})\`);`;
    expect(await run(d, q(body))).toHaveLength(1);
  });
});
