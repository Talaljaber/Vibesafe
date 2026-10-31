import fs from "node:fs";
import path from "node:path";
import type { AttackConfigFile, SessionSpec, SessionsFile } from "./types.js";

/** Thrown for any invalid or unreadable config file. The CLI maps it to exit code 2. */
export class AttackConfigError extends Error {
  readonly exitCode = 2 as const;
  constructor(message: string) {
    super(message);
    this.name = "AttackConfigError";
  }
}

/** Headers a session may carry. Mirrors the gate's allow-list for credentials (spec 3.1). */
const SESSION_HEADER_NAMES = new Set(["cookie", "authorization", "apikey"]);
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "[::1]", "::1", "localhost"]);
const LABEL_RE = /^[A-Za-z0-9_.-]{1,32}$/;
const RESOURCE_ID_RE = /^[A-Za-z0-9_.~:-]{1,128}$/;
const MAX_SESSIONS = 10;
export const MAX_RATE = 100;
const BAD_CHARS_RE = /[\\\u0000-\u0020\u007f]/;

export const SESSIONS_RELATIVE_PATH = path.join(".vibesafe", "sessions.json");
export const ATTACK_CONFIG_RELATIVE_PATH = path.join(".vibesafe", "attack.json");

/**
 * Pure loopback check with the same set as the gate (spec 3.1): http only, exact host
 * 127.0.0.1, [::1] or localhost, no userinfo, no control characters or backslashes.
 * Local copy until B1's gate is unified with it (note for C4).
 */
export function checkLoopbackTarget(raw: string): { ok: true } | { ok: false; reason: string } {
  if (raw.length > 2048) return { ok: false, reason: "is longer than 2048 characters" };
  if (BAD_CHARS_RE.test(raw)) {
    return { ok: false, reason: "contains whitespace, a backslash or a control character" };
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, reason: "is not a valid URL" };
  }
  if (url.username !== "" || url.password !== "") {
    return { ok: false, reason: "must not contain credentials" };
  }
  if (url.protocol !== "http:") return { ok: false, reason: "must use http:// (loopback only)" };
  // WHATWG normalizes 127.1, 2130706433 and 0x7f000001 to 127.0.0.1, so also pin the raw host text.
  const rawHost = /^http:\/\/([^/?#:]+|\[[^\]]*\])(?::\d*)?(?:[/?#]|$)/.exec(raw)?.[1];
  if (!LOOPBACK_HOSTS.has(url.hostname) || rawHost === undefined || !LOOPBACK_HOSTS.has(rawHost)) {
    return {
      ok: false,
      reason: `host "${rawHost ?? url.hostname}" is not loopback (only 127.0.0.1, [::1] and localhost are allowed)`,
    };
  }
  return { ok: true };
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function readJson(file: string, optional: boolean): unknown {
  let text: string;
  try {
    text = fs.readFileSync(file, "utf8");
  } catch (err) {
    if (optional && (err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw new AttackConfigError(`${file}: cannot read file (${(err as Error).message})`);
  }
  try {
    return JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text);
  } catch (err) {
    throw new AttackConfigError(`${file}: invalid JSON (${(err as Error).message})`);
  }
}

function checkKeys(file: string, where: string, obj: Record<string, unknown>, allowed: string[]) {
  for (const key of Object.keys(obj)) {
    if (!allowed.includes(key)) {
      throw new AttackConfigError(
        `${file}: unknown key "${key}" in ${where} (allowed: ${allowed.join(", ")})`,
      );
    }
  }
}

function checkSchemaVersion(file: string, obj: Record<string, unknown>): void {
  if (!("schemaVersion" in obj)) throw new AttackConfigError(`${file}: missing "schemaVersion"`);
  if (obj["schemaVersion"] !== 1) {
    throw new AttackConfigError(
      `${file}: unsupported schemaVersion ${JSON.stringify(obj["schemaVersion"])} (this version of VibeSafe supports 1)`,
    );
  }
}

function parseSession(file: string, raw: unknown, i: number): SessionSpec {
  const at = `sessions[${i}]`;
  if (!isPlainObject(raw)) throw new AttackConfigError(`${file}: ${at} must be an object`);
  checkKeys(file, at, raw, ["label", "headers", "resources"]);
  const label = raw["label"];
  if (typeof label !== "string" || !LABEL_RE.test(label)) {
    throw new AttackConfigError(
      `${file}: ${at}.label must be a string of 1-32 characters from [A-Za-z0-9_.-]`,
    );
  }
  const rawHeaders = raw["headers"];
  if (!isPlainObject(rawHeaders)) {
    throw new AttackConfigError(`${file}: ${at}.headers must be an object of header name to value`);
  }
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(rawHeaders)) {
    if (!SESSION_HEADER_NAMES.has(name.toLowerCase())) {
      throw new AttackConfigError(
        `${file}: ${at}.headers has "${name}"; only Cookie, Authorization and apikey are allowed`,
      );
    }
    if (typeof value !== "string" || value === "" || /[\u0000-\u001f\u007f]/.test(value)) {
      throw new AttackConfigError(
        `${file}: ${at}.headers.${name} must be a non-empty string without control characters`,
      );
    }
    headers[name] = value;
  }
  const rawRes = raw["resources"] ?? {};
  if (!isPlainObject(rawRes)) {
    throw new AttackConfigError(
      `${file}: ${at}.resources must be an object of route pattern to id`,
    );
  }
  const resources: Record<string, string> = {};
  for (const [pattern, id] of Object.entries(rawRes)) {
    if (!pattern.startsWith("/") || BAD_CHARS_RE.test(pattern)) {
      throw new AttackConfigError(
        `${file}: ${at}.resources key "${pattern}" must be a route pattern starting with "/"`,
      );
    }
    if (typeof id !== "string" || !RESOURCE_ID_RE.test(id) || id === "." || id === "..") {
      throw new AttackConfigError(
        `${file}: ${at}.resources["${pattern}"] must be a string of 1-128 characters from [A-Za-z0-9_.~:-]`,
      );
    }
    resources[pattern] = id;
  }
  return { label, headers, resources };
}

/** Validates already-parsed sessions JSON. `file` is only used in messages. */
export function validateSessionsFile(file: string, data: unknown): SessionsFile {
  if (!isPlainObject(data)) throw new AttackConfigError(`${file}: top level must be an object`);
  checkSchemaVersion(file, data);
  checkKeys(file, "the top level", data, ["schemaVersion", "sessions"]);
  const list = data["sessions"];
  if (!Array.isArray(list)) throw new AttackConfigError(`${file}: "sessions" must be an array`);
  if (list.length > MAX_SESSIONS) {
    throw new AttackConfigError(`${file}: at most ${MAX_SESSIONS} sessions are allowed`);
  }
  const sessions = list.map((s, i) => parseSession(file, s, i));
  const seen = new Set<string>();
  for (const s of sessions) {
    if (seen.has(s.label))
      throw new AttackConfigError(`${file}: duplicate session label "${s.label}"`);
    seen.add(s.label);
  }
  return { schemaVersion: 1, sessions };
}

/** Validates already-parsed attack.json content. */
export function validateAttackConfig(file: string, data: unknown): AttackConfigFile {
  if (!isPlainObject(data)) throw new AttackConfigError(`${file}: top level must be an object`);
  checkSchemaVersion(file, data);
  checkKeys(file, "the top level", data, ["schemaVersion", "target", "rate"]);
  const out: AttackConfigFile = { schemaVersion: 1 };
  const target = data["target"];
  if (target !== undefined) {
    if (typeof target !== "string")
      throw new AttackConfigError(`${file}: "target" must be a string`);
    const check = checkLoopbackTarget(target);
    if (!check.ok) throw new AttackConfigError(`${file}: "target" ${check.reason}`);
    out.target = target;
  }
  const rate = data["rate"];
  if (rate !== undefined) {
    if (typeof rate !== "number" || !Number.isFinite(rate) || rate <= 0 || rate > MAX_RATE) {
      throw new AttackConfigError(
        `${file}: "rate" must be a number greater than 0 and at most ${MAX_RATE}`,
      );
    }
    out.rate = rate;
  }
  return out;
}

/**
 * Loads sessions. With no explicit path the default .vibesafe/sessions.json is optional
 * (a missing file yields no sessions); an explicit path must exist.
 * Throws AttackConfigError (exit code 2) on any problem.
 */
export function loadSessions(projectPath: string, sessionsPath?: string): SessionsFile {
  const explicit = sessionsPath !== undefined;
  const file = explicit
    ? path.resolve(projectPath, sessionsPath)
    : path.join(projectPath, SESSIONS_RELATIVE_PATH);
  const data = readJson(file, !explicit);
  if (data === undefined) return { schemaVersion: 1, sessions: [] };
  return validateSessionsFile(file, data);
}

/** Loads .vibesafe/attack.json, or undefined when absent. Throws AttackConfigError on problems. */
export function loadAttackConfig(projectPath: string): AttackConfigFile | undefined {
  const file = path.join(projectPath, ATTACK_CONFIG_RELATIVE_PATH);
  const data = readJson(file, true);
  if (data === undefined) return undefined;
  return validateAttackConfig(file, data);
}
