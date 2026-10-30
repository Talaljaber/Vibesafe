import { afterAll, beforeAll, describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, type ChildProcess } from "node:child_process";
import { fileURLToPath } from "node:url";
import { ScannerPipeline, createDefaultRegistry } from "@talaljaber/vibesafe-core";
import { idor } from "../../src/checks/idor.js";
import { buildControlSet, fingerprintResponse, planControlRequests } from "../../src/controls.js";
import { SafeHttpClient } from "../../src/http/safe-client.js";
import { buildRouteMap } from "../../src/target/route-map.js";
import type { ProbeRequest, ProbeResponse, SessionsFile } from "../../src/types.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = path.resolve(here, "../../../../fixtures/attack-demo-app");

function listFiles(root: string, dir = ""): string[] {
  const out: string[] = [];
  for (const e of fs.readdirSync(path.join(root, dir), { withFileTypes: true })) {
    const rel = dir ? `${dir}/${e.name}` : e.name;
    if (e.isDirectory()) out.push(...listFiles(root, rel));
    else out.push(rel);
  }
  return out;
}

let child: ChildProcess;
let tmp: string;
let base = "";

beforeAll(async () => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vs-idor-demo-"));
  const root = path.join(tmp, "app");
  fs.cpSync(fixture, root, { recursive: true });
  child = spawn(process.execPath, [path.join(root, "server.mjs"), "--port", "0"], {
    stdio: ["ignore", "pipe", "inherit"],
  });
  base = await new Promise<string>((resolve, reject) => {
    let buf = "";
    const timer = setTimeout(() => reject(new Error("harness did not start")), 15000);
    child.stdout?.on("data", (d: Buffer) => {
      buf += d.toString();
      const m = /LISTENING (\d+)/.exec(buf);
      if (m) {
        clearTimeout(timer);
        resolve(`http://127.0.0.1:${m[1]}`);
      }
    });
    child.on("error", reject);
  });
}, 30000);

afterAll(() => {
  child?.kill();
  try {
    fs.rmSync(tmp, { recursive: true, force: true });
  } catch {
    // the harness may still hold a handle on Windows; the OS temp dir is swept later
  }
});

describe("idor check against the demo app harness", () => {
  it("notes GET CONFIRMED, notes PATCH INCONCLUSIVE, invoices NOT_REPRODUCED", async () => {
    const root = path.join(tmp, "app");
    const scan = await new ScannerPipeline(createDefaultRegistry()).scan({
      rootPath: root,
      online: false,
    });
    const read = (f: string): string | undefined => {
      try {
        return fs.readFileSync(path.join(root, f), "utf-8");
      } catch {
        return undefined;
      }
    };
    const routes = buildRouteMap(listFiles(root), read, scan.findings);
    const sessions = (
      JSON.parse(
        fs.readFileSync(path.join(root, ".vibesafe", "sessions.json"), "utf-8"),
      ) as SessionsFile
    ).sessions;
    const groups = idor.plan({
      findings: scan.findings,
      routes,
      sessions,
      env: {},
      readSource: read,
    });
    expect(groups).toHaveLength(3);

    const client = new SafeHttpClient({ rate: 1000 });
    const send = async (r: ProbeRequest): Promise<ProbeResponse> => {
      const s = sessions.find((x) => x.label === r.session);
      const res = await client.request({
        url: `${base}${r.path}`,
        ...(s ? { headers: s.headers, session: s.label } : {}),
      });
      return {
        label: r.label,
        status: res.status,
        contentType: res.contentType,
        headers: res.headers,
        body: res.body,
        bodyTruncated: res.bodyTruncated,
        ms: res.ms,
        fingerprint: fingerprintResponse(res.status, res.contentType, res.body),
      };
    };
    const controlResponses: ProbeResponse[] = [];
    for (const r of planControlRequests({
      dynamicRoutes: routes.map((x) => x.pattern),
      firstSession: sessions[0]?.label,
    })) {
      controlResponses.push(await send(r));
    }
    const controls = buildControlSet(controlResponses.map((r) => r.fingerprint));

    const outcomes: Record<string, { outcome: string; ownerOk?: boolean; reason: string }> = {};
    for (const g of groups) {
      const responses: ProbeResponse[] = [];
      for (const r of g.requests) responses.push(await send(r));
      const result = idor.evaluate(g, responses, controls);
      outcomes[`${g.method} ${g.route}`] = {
        outcome: result.outcome,
        ...(result.ownerOk === undefined ? {} : { ownerOk: result.ownerOk }),
        reason: result.reasoning,
      };
    }
    expect(outcomes["GET /api/notes/[id]"]).toMatchObject({ outcome: "CONFIRMED", ownerOk: true });
    expect(outcomes["PATCH /api/notes/[id]"]?.outcome).toBe("INCONCLUSIVE");
    expect(outcomes["PATCH /api/notes/[id]"]?.reason).toMatch(/write path, not tested/);
    expect(outcomes["GET /api/invoices/[id]"]).toMatchObject({
      outcome: "NOT_REPRODUCED",
      ownerOk: true,
    });
    expect(client.log.every((e) => e.method === "GET")).toBe(true);
  }, 60000);
});
