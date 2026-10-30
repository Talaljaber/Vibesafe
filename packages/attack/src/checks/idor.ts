import type { Finding } from "@talaljaber/vibesafe-shared";
import { normalizeBody } from "../controls.js";
import { stableAttackId } from "../ids.js";
import { preflightGet } from "../plan/preflight.js";
import { enclosingHandler } from "../target/enclosing-handler.js";
import { formatCurl } from "../report/curl.js";
import { concretePath, dynamicSegmentsOf } from "../target/route-map.js";
import type {
  AttackCheck,
  AttackResult,
  ControlSet,
  PlanContext,
  ProbeGroup,
  ProbeRequest,
  ProbeResponse,
  ResponseShape,
  RouteEntry,
  SessionSpec,
  StaticRef,
} from "../types.js";

const RULE_ID = "authorization/idor-unscoped-lookup";
const READ_PREFIX = "This handler reads";
const REASON_UNRESOLVED = "handler not resolved";
const REASON_WRITE = "write path, not tested (attack mode only sends reads)";
const REASON_ROUTE = "route not resolved (Next.js app router only)";
const REASON_SESSIONS = "needs two test sessions with an id each; see .vibesafe/sessions.json";
const REASON_NO_ID_SEGMENT = "route has no id segment to swap between two users";
const REASON_SAME_ID =
  "the two test sessions use the same id for this route; give each user their own record";
const MAX_KEYS = 32;
const MAY_WRITE = "handler may write";
const FIX_GUIDANCE =
  'Load the record filtered by both its id and the signed-in user\'s id (for example `.eq("user_id", session.userId)`), and return 404 when no row matches.';
const LOGIN_RE = /log-?in|sign-?in|signin|\/auth\b/i;
const SAFE_KEY_RE = /^[\w.-]{1,64}$/;

const norm = (p: string): string => p.replace(/\\/g, "/");

function refOf(f: Finding): StaticRef {
  return {
    findingId: f.id,
    ruleId: f.ruleId,
    title: f.title,
    file: f.file ?? "",
    line: f.line,
    severity: f.severity,
  };
}

/** The table name from the detector's problem text ("a row of notes by an id"). */
function recordOf(problem: string | undefined): string {
  const m = /\brow of "?([\w.-]{1,64})"? by\b/.exec(problem ?? "");
  return m?.[1] ?? "record";
}

function skipGroup(base: Omit<ProbeGroup, "requests" | "skip">, reason: string): ProbeGroup {
  return { ...base, requests: [], skip: { outcome: "INCONCLUSIVE", reason } };
}

function req(label: string, path: string, session?: SessionSpec): ProbeRequest {
  const r: ProbeRequest = { label, method: "GET", host: "target", path };
  if (session) r.session = session.label;
  return r;
}

function planOne(f: Finding, ctx: PlanContext): ProbeGroup {
  const file = norm(f.file ?? "");
  const route: RouteEntry | undefined = ctx.routes.find((r) => r.sourceFile === file);
  const staticRef = refOf(f);
  const record = recordOf(f.plainEnglishProblem);
  const title = `One signed-in user can read another user's ${record}.`;
  if (!route) {
    return skipGroup(
      { attackId: stableAttackId("idor", "GET", file), checkId: "idor", title, staticRef },
      REASON_ROUTE,
    );
  }
  const content = ctx.readSource(f.file ?? "") ?? ctx.readSource(file) ?? "";
  const handler = f.line === undefined ? undefined : enclosingHandler(content, f.line);
  const method = handler?.method ?? "GET";
  const base = {
    attackId: stableAttackId("idor", method, route.pattern),
    checkId: "idor" as const,
    title,
    route: route.pattern,
    method,
    staticRef,
    ownerLabels: ["R1", "R2"],
  };
  if (handler === undefined) return skipGroup(base, REASON_UNRESOLVED);
  if (handler.method !== "GET" || !f.plainEnglishProblem.startsWith(READ_PREFIX)) {
    return skipGroup(
      { ...base, title: `Write to another user's ${record} (not tested).` },
      REASON_WRITE,
    );
  }
  if (preflightGet(route.pattern, content).skip) return skipGroup(base, MAY_WRITE);
  const nDyn = dynamicSegmentsOf(route.pattern).length;
  if (nDyn === 0) return skipGroup(base, REASON_NO_ID_SEGMENT);
  if (nDyn > 1) return skipGroup(base, "route has several id segments; not supported yet");
  const a = ctx.sessions[0];
  const b = ctx.sessions[1];
  const pa = a && concretePath(route.pattern, a);
  const pb = b && concretePath(route.pattern, b);
  if (!a || !b || !pa || !pb || !("path" in pa) || !("path" in pb)) {
    return skipGroup(base, REASON_SESSIONS);
  }
  const dot = (p: string): boolean =>
    p
      .split("?")[0]!
      .split("/")
      .some((x) => x === "." || x === ".." || /^%2e(%2e)?$/i.test(x));
  if (dot(pa.path) || dot(pb.path)) return skipGroup(base, REASON_SESSIONS);
  if (pa.path === pb.path) return skipGroup(base, REASON_SAME_ID);
  return {
    ...base,
    requests: [
      req("R0", pb.path),
      req("R1", pa.path, a),
      req("R2", pb.path, b),
      req("R3", pb.path, a),
    ],
  };
}

// ---------------------------------------------------------------- evaluation helpers

function parse(body: string): unknown {
  try {
    return JSON.parse(body);
  } catch {
    return undefined;
  }
}

interface Shape {
  keys: string[];
  rows?: number;
  id?: string;
}

const ID_KEYS = ["id", "_id", "uuid"];

function shapeOf(r: ProbeResponse, targetId?: string): Shape | undefined {
  const parsed = parse(r.body);
  if (parsed === null || typeof parsed !== "object") return undefined;
  let obj: unknown = parsed;
  const out: Shape = { keys: [] };
  if (Array.isArray(parsed)) {
    out.rows = parsed.length;
    obj = parsed[0];
  }
  if (obj !== null && typeof obj === "object" && !Array.isArray(obj)) {
    const rec = obj as Record<string, unknown>;
    out.keys = Object.keys(rec).sort();
    let key = ID_KEYS.find((k) => k in rec);
    if (key === undefined) {
      const cands = out.keys.filter((k) => /[a-z]Id$/.test(k) || k === "Id");
      const idVal = (k: string): string | undefined => {
        const x = rec[k];
        return typeof x === "string" || typeof x === "number" ? String(x) : undefined;
      };
      key = cands.find((k) => targetId !== undefined && idVal(k) === targetId);
    }
    const v = key === undefined ? undefined : rec[key];
    if (typeof v === "string" || typeof v === "number") out.id = String(v);
  }
  return out;
}

const is2xx = (r: ProbeResponse): boolean => r.status >= 200 && r.status < 300;
const isBad = (r: ProbeResponse): boolean => r.status === 0 || r.status >= 500;

function decode(seg: string): string {
  try {
    return decodeURIComponent(seg);
  } catch {
    return seg;
  }
}

/** The id filled into the route pattern's dynamic segment (catch-alls join the rest). */
function targetIdOf(pattern: string | undefined, path: string): string {
  const pat = (pattern ?? "").split("/");
  const segs = path.split("?")[0]!.split("/");
  const i = pat.findIndex((s) => /^\[.+\]$/.test(s));
  if (i < 0) return decode(segs.pop() ?? "");
  const catchAll = pat[i]!.startsWith("[...") || pat[i]!.startsWith("[[...");
  return (catchAll ? segs.slice(i) : segs.slice(i, i + 1)).map(decode).join("/");
}

/** The "shape match" of spec 7: 200s, same key set (and row count), ids equal the target id. */
function similar(a: ProbeResponse, b: ProbeResponse, targetId: string, useId: boolean): boolean {
  if (a.status !== 200 || b.status !== 200) return false;
  const sa = shapeOf(a, targetId);
  const sb = shapeOf(b, targetId);
  if (!sa || !sb) return false;
  if (sa.keys.length === 0 || sa.keys.join("\0") !== sb.keys.join("\0")) return false;
  if (sa.rows !== sb.rows) return false;
  if (useId && sa.id !== undefined && sb.id !== undefined)
    return sa.id === targetId && sb.id === targetId;
  return true;
}

function hasId(r: ProbeResponse, targetId: string, useId: boolean): boolean {
  return useId && shapeOf(r, targetId)?.id !== undefined;
}

function toShape(r: ProbeResponse): ResponseShape {
  const s = shapeOf(r);
  const out: ResponseShape = {
    label: r.label,
    status: r.status,
    keys: (s?.keys ?? []).slice(0, MAX_KEYS).map((k) => (SAFE_KEY_RE.test(k) ? k : "<key>")),
  };
  if (s?.rows !== undefined) out.rowCount = s.rows;
  return out;
}

function curlLines(group: ProbeGroup): string[] {
  return group.requests.map((r) => formatCurl({ targetUrl: "", path: r.path, session: r.session }));
}

function evaluateIdor(
  group: ProbeGroup,
  responses: readonly ProbeResponse[],
  controls: ControlSet,
): AttackResult {
  const sev = group.staticRef?.severity ?? "high";
  const result = (
    outcome: AttackResult["outcome"],
    reasoning: string,
    extra: Partial<AttackResult> = {},
  ): AttackResult => {
    const out: AttackResult = {
      attackId: group.attackId,
      checkId: "idor",
      title: group.title,
      outcome,
      severity: sev,
      reasoning,
      shapes: responses.map(toShape),
      curl: curlLines(group),
      fixGuidance: FIX_GUIDANCE,
      ...extra,
    };
    if (group.route !== undefined) out.route = group.route;
    if (group.method !== undefined) out.method = group.method;
    if (group.staticRef) {
      out.staticRef = group.staticRef;
      out.sourceFile = group.staticRef.file;
      if (group.staticRef.line !== undefined) out.line = group.staticRef.line;
    }
    return out;
  };

  if (group.skip) {
    return result(group.skip.outcome, group.skip.reason, { shapes: [], curl: [] });
  }
  const by = (label: string): ProbeResponse | undefined => responses.find((r) => r.label === label);
  const r0 = by("R0");
  const r1 = by("R1");
  const r2 = by("R2");
  const r3 = by("R3");
  if (!r0 || !r1 || !r2 || !r3) return result("ERROR", "a deciding request did not complete");
  const ownerOk = r1.status === 200 && r2.status === 200;
  if (isBad(r2) || isBad(r3)) {
    return result("ERROR", "a deciding request failed or returned a server error", { ownerOk });
  }
  if (r2.status !== 200 || controls.matches(r2.fingerprint)) {
    return result("INCONCLUSIVE", "owner request failed; can't judge", { ownerOk });
  }
  const noun = /user's (.+)\.$/.exec(group.title)?.[1] ?? "record";
  const targetId = targetIdOf(
    group.route,
    group.requests.find((q) => q.label === "R2")?.path ?? "",
  );

  const useId = shapeOf(r2, targetId)?.id === targetId;
  const n = (r: ProbeResponse): string => normalizeBody(r.body);
  const anonOk =
    is2xx(r0) &&
    !controls.matches(r0.fingerprint) &&
    similar(r0, r2, targetId, useId) &&
    (hasId(r0, targetId, useId) && hasId(r2, targetId, useId) ? true : n(r0) === n(r2));
  if (anonOk) {
    return result(
      "CONFIRMED",
      "A logged-out request received the same kind of record the owner receives.",
      {
        severity: "critical",
        title: `Anyone, even logged out, can read another user's ${noun}.`,
        ownerOk,
      },
    );
  }
  const loginRedirect = r3.status >= 300 && r3.status < 400 && LOGIN_RE.test(r3.location ?? "");
  if (r3.status === 401 || r3.status === 403 || r3.status === 404 || loginRedirect) {
    return result(
      "NOT_REPRODUCED",
      `The other user's record was refused to the first user (${r3.status}) while its owner still got it.`,
      { ownerOk },
    );
  }
  if (controls.matches(r3.fingerprint)) {
    return result(
      "NOT_REPRODUCED",
      "The answer to the first user matches a not-found/auth-wall control.",
      { ownerOk },
    );
  }
  if (r2.bodyTruncated || r3.bodyTruncated || (shapeOf(r2)?.keys.length ?? 0) === 0) {
    return result("INCONCLUSIVE", "owner response is empty or not comparable JSON; can't judge", {
      ownerOk,
    });
  }
  if (similar(r3, r2, targetId, useId)) {
    // Without an id in the body, only an exact copy of the owner's response that differs
    // from the first user's own record shows that this is the other user's record.
    if (!hasId(r3, targetId, useId) || !hasId(r2, targetId, useId)) {
      if (n(r1) === n(r2)) {
        return result("INCONCLUSIVE", "the owners' records are indistinguishable; can't judge", {
          ownerOk,
        });
      }
      if (n(r3) === n(r1)) {
        return result("NOT_REPRODUCED", "response is not Bob's record", { ownerOk });
      }
      if (n(r3) !== n(r2)) {
        return result(
          "INCONCLUSIVE",
          "response differs from the owner's and has no id; can't judge",
          {
            ownerOk,
          },
        );
      }
    }
    return result(
      "CONFIRMED",
      "A signed-in user received the same kind of record another user owns.",
      { severity: "high", title: `One signed-in user can read another user's ${noun}.`, ownerOk },
    );
  }
  if (r3.status !== 200) {
    return result("INCONCLUSIVE", `attack request got ${r3.status}; can't judge`, { ownerOk });
  }
  return result("NOT_REPRODUCED", "response is not Bob's record", { ownerOk });
}

export const idor: AttackCheck = {
  id: "idor",
  title: "Insecure direct object reference",
  plan(ctx) {
    const groups: ProbeGroup[] = [];
    for (const f of ctx.findings) {
      if (f.ruleId !== RULE_ID) continue;
      const g = planOne(f, ctx);
      const at = groups.findIndex((x) => x.attackId === g.attackId);
      if (at >= 0) {
        if (groups[at]!.skip && !g.skip) groups[at] = g;
        continue;
      }
      groups.push(g);
    }
    return groups;
  },
  evaluate: evaluateIdor,
};
