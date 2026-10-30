import { isRiskyRoutePattern } from "@talaljaber/vibesafe-core";
import type {
  AttackCheck,
  AttackOutcome,
  AttackResult,
  ControlSet,
  PlanContext,
  ProbeGroup,
  ProbeRequest,
  ProbeResponse,
  ResponseShape,
  StaticRef,
} from "../types.js";
import { stableAttackId } from "../ids.js";
import { formatCurl } from "../report/curl.js";
import { preflightGet } from "../plan/preflight.js";
import { enclosingHandler } from "../target/enclosing-handler.js";
import { concretePath } from "../target/route-map.js";

const RULE_ID = "auth/missing-route-auth";
const CONFIRMED_TITLE = "This endpoint returns private data without logging in.";
const FIX_GUIDANCE =
  "Check the session at the start of the handler and return 401 when there is none. Take any user or organization id from the session, not from the request.";
const SENSITIVE_WORDS = new Set([
  "email",
  "password",
  "token",
  "secret",
  "role",
  "phone",
  "address",
  "ssn",
  "card",
]);
const LOGIN_PATH_RE = /\/(login|log-in|signin|sign-in|sign_in|signup|auth)(\/|\?|#|$)/i;
const MAX_SHAPE_KEYS = 20;

const norm = (p: string): string => p.replace(/\\/g, "/");

function skipGroup(
  attackId: string,
  ref: StaticRef,
  route: string | undefined,
  reason: string,
  method = "GET",
): ProbeGroup {
  return {
    attackId,
    checkId: "unauth-route",
    title: `Unauthenticated ${method} ${route ?? ref.file}`,
    route,
    method,
    requests: [],
    staticRef: ref,
    skip: { outcome: "INCONCLUSIVE", reason },
  };
}

function plan(ctx: PlanContext): ProbeGroup[] {
  const groups: ProbeGroup[] = [];
  const seen = new Set<string>();
  for (const f of ctx.findings) {
    if (f.ruleId !== RULE_ID || f.file === undefined) continue;
    const file = norm(f.file);
    const ref: StaticRef = {
      findingId: f.id,
      ruleId: f.ruleId,
      title: f.title,
      file,
      line: f.line,
      severity: f.severity,
    };
    const entry = ctx.routes.find((r) => norm(r.sourceFile) === file);
    if (entry === undefined) {
      const id = stableAttackId("unauth-route", "GET", file);
      if (seen.has(id)) continue;
      seen.add(id);
      groups.push(skipGroup(id, ref, undefined, "route not resolved (Next.js app router only)"));
      continue;
    }
    const attackId = stableAttackId("unauth-route", "GET", entry.pattern);
    const content = ctx.readSource(entry.sourceFile) ?? "";
    const handler = f.line === undefined ? undefined : enclosingHandler(content, f.line);
    if (handler === undefined || handler.method !== "GET") {
      if (seen.has(attackId)) continue;
      seen.add(attackId);
      const m = handler?.method;
      const reason =
        handler === undefined
          ? "handler not resolved"
          : m === "HEAD"
            ? "not a GET handler, not tested"
            : "write path, not tested";
      groups.push(skipGroup(attackId, ref, entry.pattern, reason, m ?? "GET"));
      continue;
    }
    // A GET finding replaces an earlier write-path skip group for the same route.
    const prior = groups.findIndex((g) => g.attackId === attackId);
    if (prior >= 0) {
      const reason = groups[prior]?.skip?.reason ?? "";
      if (!/^(write path|not a GET|handler not resolved)/.test(reason)) continue;
      groups.splice(prior, 1);
    }
    seen.add(attackId);
    const pre = preflightGet(entry.pattern, content);
    if (pre.skip) {
      groups.push(skipGroup(attackId, ref, entry.pattern, pre.reason ?? "handler may write"));
      continue;
    }
    const first = ctx.sessions[0];
    const concrete = concretePath(entry.pattern, first);
    if ("skip" in concrete) {
      groups.push(skipGroup(attackId, ref, entry.pattern, concrete.skip.reason));
      continue;
    }
    const requests: ProbeRequest[] = [
      { label: "U1", method: "GET", host: "target", path: concrete.path },
    ];
    if (first !== undefined) {
      requests.push({
        label: "U2",
        method: "GET",
        host: "target",
        path: concrete.path,
        session: first.label,
      });
    }
    groups.push({
      attackId,
      checkId: "unauth-route",
      title: `Unauthenticated GET ${entry.pattern}`,
      route: entry.pattern,
      method: "GET",
      requests,
      staticRef: ref,
      ownerLabels: first === undefined ? [] : ["U2"],
    });
  }
  return groups;
}

function isSensitiveKey(key: string): boolean {
  const words = key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
  return words.some((w) => SENSITIVE_WORDS.has(w) || SENSITIVE_WORDS.has(w.replace(/s$/, "")));
}

/** Looks for sensitive key names at depth 0..2 (arrays are looked into without costing depth). */
function sensitiveKeysWithin(value: unknown, depth: number): boolean {
  if (value === null || typeof value !== "object") return false;
  if (Array.isArray(value)) {
    return value.slice(0, 5).some((v) => sensitiveKeysWithin(v, depth));
  }
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (isSensitiveKey(k)) return true;
    if (depth < 2 && sensitiveKeysWithin(v, depth + 1)) return true;
  }
  return false;
}

function parseJson(body: string): { ok: true; value: unknown } | { ok: false } {
  try {
    return { ok: true, value: JSON.parse(body) };
  } catch {
    return { ok: false };
  }
}

function isEmptyJson(v: unknown): boolean {
  if (v === null) return true;
  if (Array.isArray(v)) return v.length === 0;
  return typeof v === "object" && Object.keys(v as object).length === 0;
}

/** Keys that look like ids, tokens or secrets rather than field names. */
function looksLikeValue(k: string): boolean {
  return (
    /^\d+$/.test(k) ||
    /^[0-9a-f]{16,}$/i.test(k) ||
    /^(sk|pk|rk)_/i.test(k) ||
    /^eyJ/.test(k) ||
    k.length > 40
  );
}

const ERROR_ONLY_KEYS = ["error", "errors", "message", "ok", "success", "status"];
const ERROR_COMPANION_KEYS = [
  "code",
  "statusCode",
  "message",
  "msg",
  "details",
  "status",
  "ok",
  "success",
];

function isErrorOnly(v: unknown): boolean {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const o = v as Record<string, unknown>;
  const keys = Object.keys(o);
  if (keys.length === 0) return false;
  if (keys.every((k) => ERROR_ONLY_KEYS.includes(k))) return true;
  return (
    (Boolean(o["error"]) || Boolean(o["errors"])) &&
    keys.every((k) => k === "error" || k === "errors" || ERROR_COMPANION_KEYS.includes(k))
  );
}

function isEmptyValue(x: unknown): boolean {
  if (x === null || x === undefined || x === "") return true;
  if (Array.isArray(x)) return x.length === 0;
  return typeof x === "object" && Object.keys(x as object).length === 0;
}

/** True when the body carries no data: every top-level value is null or empty (array: element 0 too). */
function carriesNoData(v: unknown): boolean {
  if (isEmptyJson(v)) return true;
  if (Array.isArray(v)) return carriesNoData(v[0]) || isEmptyValue(v[0]);
  if (v !== null && typeof v === "object") {
    return Object.values(v as Record<string, unknown>).every(isEmptyValue);
  }
  return false;
}

function isLoginRedirect(r: ProbeResponse): boolean {
  return (
    r.status >= 300 &&
    r.status < 400 &&
    LOGIN_PATH_RE.test(r.location ?? r.headers["location"] ?? "")
  );
}

function shapeOf(r: ProbeResponse): ResponseShape {
  const shape: ResponseShape = { label: r.label, status: r.status, keys: [] };
  if (!r.contentType.toLowerCase().includes("json")) return shape;
  const parsed = parseJson(r.body);
  if (!parsed.ok) return shape;
  let target: unknown = parsed.value;
  if (Array.isArray(parsed.value)) {
    shape.rowCount = parsed.value.length;
    target = parsed.value[0];
  }
  if (target !== null && typeof target === "object" && !Array.isArray(target)) {
    shape.keys = Object.keys(target as Record<string, unknown>)
      .slice(0, MAX_SHAPE_KEYS)
      .map((k) => (/^[\w.-]{1,64}$/.test(k) && !looksLikeValue(k) ? k : "<key>"))
      .sort();
  }
  return shape;
}

function curlLines(group: ProbeGroup): string[] {
  return group.requests.map((r) =>
    formatCurl({ targetUrl: "<target>", path: r.path, session: r.session }),
  );
}

function evaluate(
  group: ProbeGroup,
  responses: readonly ProbeResponse[],
  controls: ControlSet,
): AttackResult {
  const ref = group.staticRef;
  const base = {
    attackId: group.attackId,
    checkId: "unauth-route" as const,
    title: group.title,
    severity: ref?.severity ?? "high",
    route: group.route,
    method: group.method ?? "GET",
    sourceFile: ref?.file,
    line: ref?.line,
    staticRef: ref,
    curl: curlLines(group),
    fixGuidance: FIX_GUIDANCE,
  };
  const done = (
    outcome: AttackOutcome,
    reasoning: string,
    extra: Partial<AttackResult> = {},
  ): AttackResult => ({
    ...base,
    outcome,
    reasoning,
    shapes: responses.map(shapeOf),
    ...extra,
  });

  if (group.skip !== undefined) {
    return { ...base, outcome: group.skip.outcome, reasoning: group.skip.reason, shapes: [] };
  }
  const u1 = responses.find((r) => r.label === "U1");
  const u2 = responses.find((r) => r.label === "U2");
  const ownerOk =
    u2 === undefined ||
    (u2.status !== 0 &&
      u2.status !== 401 &&
      u2.status !== 404 &&
      u2.status < 500 &&
      !isLoginRedirect(u2) &&
      !controls.matches(u2.fingerprint));

  if (u1 === undefined || u1.status === 0 || u1.status >= 500) {
    return done("ERROR", "The logged-out request failed or the server errored; can't judge.", {
      ownerOk,
    });
  }
  const loginRedirect = isLoginRedirect(u1);
  if (u1.status === 401 || u1.status === 403 || loginRedirect || controls.matches(u1.fingerprint)) {
    return done("NOT_REPRODUCED", "Refused without login.", { ownerOk });
  }
  if (u1.status !== 200) {
    return done(
      "INCONCLUSIVE",
      `Unexpected status ${u1.status} for the logged-out request; can't judge.`,
      { ownerOk },
    );
  }
  if (!u1.contentType.toLowerCase().includes("json") || u1.bodyTruncated) {
    return done("INCONCLUSIVE", "Returned 200 but not a complete JSON body; can't judge.", {
      ownerOk,
    });
  }
  const parsed = parseJson(u1.body);
  if (!parsed.ok || carriesNoData(parsed.value)) {
    return done("INCONCLUSIVE", "Returned 200 with an empty or unreadable JSON body.", {
      ownerOk,
    });
  }
  if (isErrorOnly(parsed.value)) {
    return done("INCONCLUSIVE", "Returned 200 with only an error or status body; can't judge.", {
      ownerOk,
    });
  }
  // Limitation: SafeHttpClient follows same-host redirects and reports only the final hop, so a followed
  // redirect to a login page or JSON auth endpoint cannot be seen here (follow-up: expose `redirected`).
  // Deliberate deviation from spec 7.2 step 3: empty JSON and error-only bodies are never CONFIRMED.
  const risky = ref !== undefined && isRiskyRoutePattern(ref.file);
  if (risky || sensitiveKeysWithin(parsed.value, 0)) {
    return done(
      "CONFIRMED",
      "A request with no login returned 200 JSON from a route the static scan flagged as unauthenticated.",
      { title: CONFIRMED_TITLE, ownerOk },
    );
  }
  return done("NOT_REPRODUCED", "Public endpoint, no sensitive fields.", { ownerOk });
}

export const unauthRoute: AttackCheck = {
  id: "unauth-route",
  title: "unauth-route",
  plan,
  evaluate,
};
