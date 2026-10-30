import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { FileDiscovery, ScannerPipeline, createDefaultRegistry } from "@talaljaber/vibesafe-core";
import { unauthRoute } from "../../src/checks/unauth-route.js";
import { buildControlSet, fingerprintResponse, planControlRequests } from "../../src/controls.js";
import { SafeHttpClient } from "../../src/http/safe-client.js";
import { buildRouteMap } from "../../src/target/route-map.js";
import type { ProbeRequest, ProbeResponse, SessionsFile } from "../../src/types.js";

const repoRoot = path.resolve(import.meta.dirname, "../../../..");
const demo = path.join(repoRoot, "fixtures/attack-demo-app");

let child: ChildProcess;
let base = "";

beforeAll(async () => {
  child = spawn(process.execPath, [path.join(demo, "server.mjs"), "--port", "0"], {
    stdio: ["ignore", "pipe", "inherit"],
  });
  base = await new Promise<string>((resolve, reject) => {
    let buf = "";
    child.stdout?.on("data", (d: Buffer) => {
      buf += d.toString();
      const m = /LISTENING (\d+)/.exec(buf);
      if (m) resolve(`http://127.0.0.1:${m[1]}`);
    });
    child.on("error", reject);
    child.on("exit", () => reject(new Error("harness exited")));
  });
});

afterAll(() => {
  child?.kill();
});

describe("unauth-route against the demo harness", () => {
  it("confirms admin/users and leaves other routes alone", async () => {
    const scan = await new ScannerPipeline(createDefaultRegistry()).scan({
      rootPath: demo,
      online: false,
    });
    const files = await new FileDiscovery(demo).discoverFiles([]);
    const read = (f: string): string | undefined => {
      try {
        return fs.readFileSync(path.join(demo, f), "utf8");
      } catch {
        return undefined;
      }
    };
    const routes = buildRouteMap(files, read, scan.findings);
    const sessions = (
      JSON.parse(
        fs.readFileSync(path.join(demo, ".vibesafe/sessions.json"), "utf8"),
      ) as SessionsFile
    ).sessions;
    const groups = unauthRoute.plan({
      findings: scan.findings,
      routes,
      sessions,
      env: {},
      readSource: read,
    });
    const admin = groups.find((g) => g.route === "/api/admin/users");
    expect(admin).toBeDefined();
    expect(admin?.skip).toBeUndefined();
    expect(groups.map((g) => g.route)).toEqual(["/api/admin/users"]);

    const client = new SafeHttpClient({ rate: 1000 });
    const send = async (r: ProbeRequest): Promise<ProbeResponse> => {
      const headers =
        r.session === undefined ? {} : (sessions.find((s) => s.label === r.session)?.headers ?? {});
      const res = await client.request({ url: base + r.path, headers, session: r.session });
      return {
        label: r.label,
        status: res.status,
        contentType: res.contentType,
        headers: res.headers,
        body: res.body,
        bodyTruncated: res.bodyTruncated,
        location: res.location,
        ms: res.ms,
        fingerprint: fingerprintResponse(res.status, res.contentType, res.body),
      };
    };
    const controls = buildControlSet(
      (await Promise.all(planControlRequests({ firstSession: sessions[0]?.label }).map(send))).map(
        (r) => r.fingerprint,
      ),
    );
    const responses = await Promise.all((admin?.requests ?? []).map(send));
    const result = unauthRoute.evaluate(admin!, responses, controls);

    expect(responses.map((r) => r.status)).toEqual([200, 200]);
    expect(result.outcome).toBe("CONFIRMED");
    expect(result.title).toBe("This endpoint returns private data without logging in.");
    expect(result.ownerOk).toBe(true);
  });
});
