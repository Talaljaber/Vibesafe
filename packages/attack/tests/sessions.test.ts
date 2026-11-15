import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  AttackConfigError,
  checkLoopbackTarget,
  loadAttackConfig,
  loadSessions,
} from "../src/sessions.js";

let dir: string;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "vibesafe-sessions-"));
  fs.mkdirSync(path.join(dir, ".vibesafe"));
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

const write = (name: string, body: unknown) =>
  fs.writeFileSync(
    path.join(dir, ".vibesafe", name),
    typeof body === "string" ? body : JSON.stringify(body),
  );
const session = (label: string, extra: Record<string, unknown> = {}) => ({
  label,
  headers: { Cookie: `vs=${label}` },
  resources: { "/api/notes/[id]": `n_${label}` },
  ...extra,
});
const sessionsErr = (): AttackConfigError => {
  try {
    loadSessions(dir);
  } catch (e) {
    return e as AttackConfigError;
  }
  throw new Error("expected loadSessions to throw");
};
const configErr = (): AttackConfigError => {
  try {
    loadAttackConfig(dir);
  } catch (e) {
    return e as AttackConfigError;
  }
  throw new Error("expected loadAttackConfig to throw");
};

describe("checkLoopbackTarget", () => {
  it.each([
    "http://127.0.0.1:3000",
    "http://localhost:3000/",
    "http://[::1]:3000",
    "http://127.0.0.1",
  ])("accepts %s", (u) => expect(checkLoopbackTarget(u).ok).toBe(true));

  it.each([
    "http://10.0.0.1/",
    "http://192.168.1.1/",
    "http://169.254.169.254/latest",
    "http://0.0.0.0/",
    "http://127.1/",
    "http://2130706433/",
    "http://0x7f000001/",
    "http://[::ffff:127.0.0.1]/",
    "http://localhost.evil.com/",
    "http://foo.localhost/",
    "http://127.0.0.1.nip.io/",
    "http://host.docker.internal/",
    "http://a@evil.com@localhost/",
    "http://user:pw@127.0.0.1/",
    "https://127.0.0.1/",
    "ftp://127.0.0.1/",
    "file:///etc/passwd",
    "http://127.0.0.1\\@evil.com/",
    "http://127.0.0.1/\t",
    "not a url",
  ])("rejects %s", (u) => {
    expect(checkLoopbackTarget(u).ok).toBe(false);
  });
});

describe("loadSessions", () => {
  it("returns no sessions when the default file is absent", () => {
    expect(loadSessions(dir)).toEqual({ schemaVersion: 1, sessions: [] });
  });

  it("errors when an explicit path is missing", () => {
    expect(() => loadSessions(dir, "nope.json")).toThrow(AttackConfigError);
  });

  it("loads a valid file", () => {
    write("sessions.json", { schemaVersion: 1, sessions: [session("alice"), session("bob")] });
    const r = loadSessions(dir);
    expect(r.sessions.map((s) => s.label)).toEqual(["alice", "bob"]);
    expect(r.sessions[0]?.resources).toEqual({ "/api/notes/[id]": "n_alice" });
  });

  it("defaults resources to empty and honours an explicit relative path", () => {
    fs.writeFileSync(
      path.join(dir, "s.json"),
      JSON.stringify({
        schemaVersion: 1,
        sessions: [{ label: "a", headers: { Authorization: "Bearer x" } }],
      }),
    );
    expect(loadSessions(dir, "s.json").sessions[0]?.resources).toEqual({});
  });

  it("rejects malformed JSON with exit code 2 and the file name", () => {
    write("sessions.json", "{ nope");
    const e = sessionsErr();
    expect(e.exitCode).toBe(2);
    expect(e.message).toContain("sessions.json");
    expect(e.message).toContain("invalid JSON");
  });

  it("rejects an unknown or missing schemaVersion", () => {
    write("sessions.json", { schemaVersion: 2, sessions: [] });
    expect(sessionsErr().message).toContain("unsupported schemaVersion 2");
    write("sessions.json", { sessions: [] });
    expect(sessionsErr().message).toContain('missing "schemaVersion"');
    write("sessions.json", { schemaVersion: "1", sessions: [] });
    expect(sessionsErr().message).toContain("unsupported schemaVersion");
  });

  it.each([
    [[1], "sessions[0] must be an object"],
    [[session("a", { extra: 1 })], 'unknown key "extra" in sessions[0]'],
    [[session("bad label")], "sessions[0].label"],
    [[session("a", { headers: { "X-Evil": "1" } })], "only Cookie, Authorization and apikey"],
    [[session("a", { headers: { Cookie: "a\r\nX: b" } })], "control characters"],
    [[session("a", { headers: [] })], "headers must be an object"],
    [[session("a", { resources: { "api/x": "1" } })], 'must be a route pattern starting with "/"'],
    [[session("a", { resources: { "/api/x/[id]": "a/b" } })], "must be a string of 1-128"],
    [[session("a", { resources: { "/api/x/[id]": 5 } })], "must be a string of 1-128"],
    [[session("a", { resources: { "/api/x/[id]": ".." } })], "must be a string of 1-128"],
    [[session("a", { resources: { "/api/x/[id]": "." } })], "must be a string of 1-128"],
    [[session("a"), session("a")], 'duplicate session label "a"'],
  ])("rejects invalid sessions %#", (sessions, message) => {
    write("sessions.json", { schemaVersion: 1, sessions });
    const e = sessionsErr();
    expect(e.exitCode).toBe(2);
    expect(e.message).toContain(message);
  });

  it("rejects unknown top-level keys, non-object and non-array sessions", () => {
    write("sessions.json", { schemaVersion: 1, sessions: [], loginUrl: "x" });
    expect(sessionsErr().message).toContain('unknown key "loginUrl"');
    write("sessions.json", []);
    expect(sessionsErr().message).toContain("top level must be an object");
    write("sessions.json", { schemaVersion: 1, sessions: {} });
    expect(sessionsErr().message).toContain('"sessions" must be an array');
  });
});

describe("loadAttackConfig", () => {
  it("returns undefined when absent", () => {
    expect(loadAttackConfig(dir)).toBeUndefined();
  });

  it("loads a valid file", () => {
    write("attack.json", { schemaVersion: 1, target: "http://localhost:3001", rate: 2 });
    expect(loadAttackConfig(dir)).toEqual({
      schemaVersion: 1,
      target: "http://localhost:3001",
      rate: 2,
    });
    write("attack.json", { schemaVersion: 1 });
    expect(loadAttackConfig(dir)).toEqual({ schemaVersion: 1 });
  });

  it("rejects a non-loopback target", () => {
    for (const target of [
      "https://example.com",
      "http://10.0.0.1:3000",
      "http://localhost.evil.com",
    ]) {
      write("attack.json", { schemaVersion: 1, target });
      const e = configErr();
      expect(e.exitCode).toBe(2);
      expect(e.message).toContain('"target"');
    }
  });

  it("rejects an unknown schemaVersion, unknown keys, bad rate and malformed JSON", () => {
    write("attack.json", { schemaVersion: 9 });
    expect(configErr().message).toContain("unsupported schemaVersion 9");
    write("attack.json", { schemaVersion: 1, supabaseProject: "x" });
    expect(configErr().message).toContain('unknown key "supabaseProject"');
    for (const rate of [0, -1, 101, "5", null]) {
      write("attack.json", { schemaVersion: 1, rate });
      expect(configErr().message).toContain('"rate"');
    }
    write("attack.json", "{");
    expect(configErr().message).toContain("invalid JSON");
  });
});
