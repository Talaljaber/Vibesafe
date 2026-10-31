/**
 * Attack runner (spec 6, 9, 15 C4): static pass -> route map -> plan (with pre-flight) ->
 * pre-warm and target check -> controls -> probes -> evaluate -> ledger -> persist + reports.
 * All network I/O goes through SafeHttpClient; this file never opens a socket itself.
 */
import fs from "node:fs";
import path from "node:path";
import { FileDiscovery, ScannerPipeline, createDefaultRegistry } from "@talaljaber/vibesafe-core";
import { VIBESAFE_VERSION, type Finding } from "@talaljaber/vibesafe-shared";
import { ATTACK_CHECKS } from "./checks/index.js";
import { buildControlSet, fingerprintResponse, planControlRequests } from "./controls.js";
import { computeRetestDiff, type ReplayedResult } from "./diff.js";
import { SafeHttpClient, type SafeResponse } from "./http/safe-client.js";
import { DEFAULT_RATE } from "./http/rate-limiter.js";
import {
  AttackPersistError,
  NO_BASELINE_MESSAGE,
  assertCanRun,
  loadSavedRun,
  saveReport,
  saveRun,
} from "./persist.js";
import { formatCurl } from "./report/curl.js";
import { renderHtmlReport } from "./report/html.js";
import { renderAgentReport } from "./report/markdown.js";
import { safeId } from "./report/text.js";
import { AttackConfigError, loadAttackConfig, loadSessions } from "./sessions.js";
import {
  DEFAULT_TARGETS,
  detectTarget,
  normalizeTarget,
  type OwnerControl,
} from "./target/detect-target.js";
import { buildRouteMap } from "./target/route-map.js";
import type {
  AttackCheck,
  AttackCheckId,
  AttackResult,
  AttackRun,
  ControlSet,
  Fingerprint,
  Ledger,
  PlanContext,
  ProbeGroup,
  ProbeRequest,
  ProbeResponse,
  RouteEntry,
  RunOptions,
  SessionSpec,
} from "./types.js";

/** Static ruleIds each floor check consumes (the ledger counts findings with these rules). */
export const CHECK_RULES: Readonly<Record<string, AttackCheckId>> = {
  "authorization/idor-unscoped-lookup": "idor",
  "auth/missing-route-auth": "unauth-route",
};

const MAX_SOURCE_BYTES = 2 * 1024 * 1024;

// ---------------------------------------------------------------- static pass

interface StaticPass {
  findings: Finding[];
  routes: RouteEntry[];
  readSource(relativeFile: string): string | undefined;
}

function sourceReader(root: string): (relativeFile: string) => string | undefined {
  return (rel) => {
    const abs = path.resolve(root, rel);
    const inside = path.relative(root, abs);
    if (inside === "" || inside.startsWith("..") || path.isAbsolute(inside)) return undefined;
    try {
      const stat = fs.statSync(abs);
      if (!stat.isFile() || stat.size > MAX_SOURCE_BYTES) return undefined;
      return fs.readFileSync(abs, "utf8");
    } catch {
      return undefined;
    }
  };
}

/**
 * Runs the core scan with network egress explicitly off (explicit options win over a project
 * config file, so a config can never turn the advisory or registry lookups on) and builds the
 * App Router route map from the discovered files.
 */
async function staticPass(root: string): Promise<StaticPass> {
  let findings: Finding[];
  let files: string[];
  try {
    const scan = await new ScannerPipeline(createDefaultRegistry()).scan({
      rootPath: root,
      online: false,
      deep: false,
    });
    findings = scan.findings;
    files = await new FileDiscovery(root).discoverFiles([], { includeTests: false });
  } catch (err) {
    throw new AttackConfigError(`static scan failed: ${(err as Error).message}`);
  }
  const readSource = sourceReader(root);
  return { findings, routes: buildRouteMap(files, readSource, findings), readSource };
}

function planGroups(ctx: PlanContext, log: RunOptions["log"]): ProbeGroup[] {
  const groups: ProbeGroup[] = [];
  for (const check of ATTACK_CHECKS) {
    try {
      groups.push(...check.plan(ctx));
    } catch (err) {
      log?.(`check ${check.id} could not plan: ${(err as Error).message}`);
    }
  }
  return groups;
}

// ---------------------------------------------------------------- ledger

/** Spec 9: over findings whose ruleId a check in this run consumes. */
export function computeLedger(findings: readonly Finding[], results: readonly AttackResult[]) {
  const consumed = new Set(ATTACK_CHECKS.map((c) => c.id));
  const ledger: Ledger = {
    staticFlagged: findings.filter((f) => {
      const check = CHECK_RULES[f.ruleId];
      return check !== undefined && consumed.has(check);
    }).length,
    confirmed: 0,
    refuted: 0,
    untested: 0,
    errors: 0,
  };
  for (const r of results) {
    if (r.outcome === "CONFIRMED") ledger.confirmed += 1;
    else if (r.outcome === "NOT_REPRODUCED") ledger.refuted += 1;
    else if (r.outcome === "INCONCLUSIVE") ledger.untested += 1;
    else ledger.errors += 1;
  }
  return ledger;
}

// ---------------------------------------------------------------- sending

interface SendContext {
  client: SafeHttpClient;
  base: string;
  sessions: readonly SessionSpec[];
}

function toProbeResponse(label: string, res: SafeResponse): ProbeResponse {
  const out: ProbeResponse = {
    label,
    status: res.status,
    contentType: res.contentType,
    headers: res.headers,
    body: res.body,
    bodyTruncated: res.bodyTruncated,
    ms: res.ms,
    fingerprint: fingerprintResponse(res.status, res.contentType, res.body),
  };
  if (res.location !== undefined) out.location = res.location;
  if (res.redirectBlocked !== undefined) out.redirectBlocked = res.redirectBlocked;
  if (res.error !== undefined) out.error = res.error;
  return out;
}

function failed(label: string, error: string): ProbeResponse {
  return {
    label,
    status: 0,
    contentType: "",
    headers: {},
    body: "",
    bodyTruncated: false,
    ms: 0,
    error,
    fingerprint: fingerprintResponse(0, "", ""),
  };
}

const validPath = (p: string): boolean => /^\/(?!\/)/.test(p);

async function send(ctx: SendContext, r: ProbeRequest, prewarm = false): Promise<ProbeResponse> {
  // Floor: only the local target. A remote host needs S1 and is reported as a failed request.
  if (r.host !== "target") return failed(r.label, "remote host not enabled");
  if (!validPath(r.path)) return failed(r.label, "invalid request path");
  const session = r.session === undefined ? undefined : findSession(ctx.sessions, r.session);
  if (r.session !== undefined && session === undefined) {
    return failed(r.label, "session not found");
  }
  const res = await ctx.client.request({
    url: `${ctx.base}${r.path}`,
    ...(session ? { headers: session.headers, session: session.label } : {}),
    ...(prewarm ? { prewarm: true } : {}),
  });
  return toProbeResponse(r.label, res);
}

function findSession(sessions: readonly SessionSpec[], label: string): SessionSpec | undefined {
  return sessions.find((s) => s.label === label);
}

function credentialHeader(session: SessionSpec | undefined): "Cookie" | "Authorization" {
  const names = Object.keys(session?.headers ?? {}).map((h) => h.toLowerCase());
  return !names.includes("cookie") && names.includes("authorization") ? "Authorization" : "Cookie";
}

/** Checks emit curl lines with a <target> placeholder; rebuild them with the real loopback base. */
function curlFor(group: ProbeGroup, ctx: SendContext): string[] {
  return group.requests
    .filter((r) => r.host === "target")
    .map((r) => {
      const session = r.session === undefined ? undefined : findSession(ctx.sessions, r.session);
      return formatCurl({
        targetUrl: ctx.base,
        path: r.path,
        session: r.session,
        headerName: credentialHeader(session),
      });
    });
}

function checkFor(id: AttackCheckId): AttackCheck | undefined {
  return ATTACK_CHECKS.find((c) => c.id === id);
}

/** A result the runner produces itself, when a check cannot judge the group. */
function plainResult(
  group: ProbeGroup,
  outcome: "INCONCLUSIVE" | "ERROR",
  reasoning: string,
): AttackResult {
  const out: AttackResult = {
    attackId: group.attackId,
    checkId: group.checkId,
    title: group.title,
    outcome,
    severity: group.staticRef?.severity ?? "medium",
    reasoning,
    shapes: [],
    curl: [],
    fixGuidance: "",
  };
  if (group.route !== undefined) out.route = group.route;
  if (group.method !== undefined) out.method = group.method;
  if (group.staticRef) {
    out.staticRef = group.staticRef;
    out.sourceFile = group.staticRef.file;
    if (group.staticRef.line !== undefined) out.line = group.staticRef.line;
  }
  return out;
}

/** Sends one group's requests in order and evaluates them with its check. */
async function runGroup(
  ctx: SendContext,
  group: ProbeGroup,
  controls: ControlSet,
  warmed: Set<string>,
): Promise<ReplayedResult> {
  const check = checkFor(group.checkId);
  if (!check) return { result: plainResult(group, "INCONCLUSIVE", "check not available") };
  if (group.skip || group.requests.length === 0) {
    try {
      return { result: check.evaluate(group, [], controls) };
    } catch {
      return {
        result: plainResult(group, "INCONCLUSIVE", group.skip?.reason ?? "nothing to send"),
      };
    }
  }
  const missing = group.requests.find(
    (r) => r.session !== undefined && findSession(ctx.sessions, r.session) === undefined,
  );
  if (missing) {
    // Never send a request without the session it was planned with: a missing session would
    // turn a signed-in attack into an anonymous one and look like a refusal.
    return {
      result: plainResult(
        group,
        "INCONCLUSIVE",
        `session "${missing.session ?? ""}" is not in sessions.json; can't replay`,
      ),
    };
  }
  const responses: ProbeResponse[] = [];
  for (const r of group.requests) {
    // The first request to a route may compile it on a dev server: give it the pre-warm timeout.
    const key = group.route ?? r.path;
    const prewarm = !warmed.has(key);
    warmed.add(key);
    responses.push(await send(ctx, r, prewarm));
  }
  let result: AttackResult;
  try {
    result = check.evaluate(group, responses, controls);
  } catch (err) {
    result = plainResult(group, "ERROR", `evaluation failed: ${(err as Error).message}`);
  }
  result.curl = curlFor(group, ctx);
  const ownerLabel = group.ownerLabels?.[group.ownerLabels.length - 1];
  const owner =
    ownerLabel === undefined ? undefined : responses.find((x) => x.label === ownerLabel);
  return owner === undefined ? { result } : { result, ownerStatus: owner.status };
}

/** Controls once per run (spec 8): C1, C2 and one Cr per probed dynamic route. */
async function runControls(
  ctx: SendContext,
  groups: readonly ProbeGroup[],
  warmed: Set<string>,
): Promise<ControlSet> {
  const dynamicRoutes = [
    ...new Set(
      groups
        .filter((g) => !g.skip && g.requests.length > 0 && g.route?.includes("["))
        .map((g) => g.route as string),
    ),
  ];
  const fingerprints: Fingerprint[] = [];
  for (const r of planControlRequests({
    dynamicRoutes,
    firstSession: ctx.sessions[0]?.label,
  })) {
    const res = await send(ctx, r, true);
    if (res.status !== 0) fingerprints.push(res.fingerprint);
  }
  for (const route of dynamicRoutes) warmed.add(route);
  return buildControlSet(fingerprints);
}

function ownerControls(groups: readonly ProbeGroup[], sessions: readonly SessionSpec[]) {
  const out: OwnerControl[] = [];
  for (const g of groups) {
    if (g.skip) continue;
    for (const r of g.requests) {
      if (!g.ownerLabels?.includes(r.label) || r.session === undefined || r.host !== "target") {
        continue;
      }
      const s = findSession(sessions, r.session);
      if (s && validPath(r.path)) out.push({ path: r.path, session: s.label, headers: s.headers });
    }
  }
  return out;
}

// ---------------------------------------------------------------- setup

interface Setup {
  root: string;
  sessions: SessionSpec[];
  rate: number;
  configuredTarget?: string | undefined;
}

function setup(options: RunOptions): Setup {
  const root = path.resolve(options.projectPath);
  const config = loadAttackConfig(root);
  const sessions = loadSessions(root, options.sessionsPath).sessions;
  const rate = options.rate ?? config?.rate ?? DEFAULT_RATE;
  if (typeof rate !== "number" || !Number.isFinite(rate) || rate <= 0) {
    throw new AttackConfigError(`invalid rate: ${String(rate)} (must be a number above 0)`);
  }
  return { root, sessions, rate, configuredTarget: config?.target };
}

function newClient(s: Setup, options: RunOptions, dryRun = false): SafeHttpClient {
  return new SafeHttpClient({
    rate: s.rate,
    supabaseProject: options.supabaseProject,
    ...(dryRun ? { dryRun: true } : {}),
  });
}

/** One result per attackId, in first-seen order; a later entry replaces an earlier one. */
function byAttackId<T extends { attackId: string }>(items: readonly T[]): T[] {
  const map = new Map<string, T>();
  for (const it of items) map.set(it.attackId, it);
  return [...map.values()];
}

function finishRun(
  options: RunOptions,
  s: Setup,
  run: Omit<AttackRun, "finishedAt" | "ledger" | "vibesafeVersion" | "schemaVersion">,
  findings: readonly Finding[],
): AttackRun {
  const full: AttackRun = {
    schemaVersion: 1,
    vibesafeVersion: VIBESAFE_VERSION,
    ...run,
    finishedAt: new Date().toISOString(),
    ledger: computeLedger(findings, run.results),
  };
  if (full.mode === "dry-run") return full;
  saveRun(s.root, full, { newBaseline: options.newBaseline });
  saveReport(s.root, "md", renderAgentReport(full));
  saveReport(s.root, "html", renderHtmlReport(full));
  return full;
}

// ---------------------------------------------------------------- public API

/**
 * Plans and executes an attack run against the local dev server. A plain baseline run refuses
 * when a baseline exists (AttackPersistError, exit code 2) unless `newBaseline`; a retest replays
 * every baseline group and diffs it. Dry runs gate and log the plan and send nothing.
 */
export async function runAttack(options: RunOptions): Promise<AttackRun> {
  const startedAt = new Date().toISOString();
  const log = options.log;
  // Refuse before scanning or sending anything.
  assertCanRun(path.resolve(options.projectPath), options.mode, options.newBaseline);
  const s = setup(options);
  const baseline = options.mode === "retest" ? loadSavedRun(s.root, "baseline") : undefined;
  if (options.mode === "retest" && baseline === undefined) {
    throw new AttackPersistError(NO_BASELINE_MESSAGE);
  }

  const pass = await staticPass(s.root);
  log?.(`Static scan: ${pass.findings.length} findings, ${pass.routes.length} routes`);
  const planned = planGroups(
    {
      findings: pass.findings,
      routes: pass.routes,
      sessions: s.sessions,
      env: {},
      readSource: pass.readSource,
    },
    log,
  );

  if (options.mode === "dry-run") {
    return dryRun(options, s, planned, pass.findings, startedAt);
  }

  // Groups to send: in a retest, every baseline group is replayed (spec 9); a baseline group with
  // nothing to send is re-planned when a fresh group exists for it. Fresh groups add NEW.
  const freshById = new Map(planned.map((g) => [g.attackId, g] as const));
  const replayGroups = (baseline?.groups ?? []).map((g) => {
    const fresh = freshById.get(g.attackId);
    return (g.skip || g.requests.length === 0) && fresh ? fresh : g;
  });
  const baselineIds = new Set(replayGroups.map((g) => g.attackId));
  const freshGroups =
    baseline === undefined ? planned : planned.filter((g) => !baselineIds.has(g.attackId));
  const allGroups = [...replayGroups, ...freshGroups];
  log?.(`Planned ${allGroups.length} attack groups`);

  const client = newClient(s, options);
  const target = await detectTarget({
    client,
    explicit: options.target,
    configured: s.configuredTarget,
    ownerControls: ownerControls(allGroups, s.sessions),
    log,
  });
  const ctx: SendContext = { client, base: target.targetUrl, sessions: s.sessions };
  const warmed = new Set<string>();
  const controls = await runControls(ctx, allGroups, warmed);

  const replayed: ReplayedResult[] = [];
  for (const g of replayGroups) replayed.push(await runGroup(ctx, g, controls, warmed));
  const fresh: ReplayedResult[] = [];
  for (const g of freshGroups) fresh.push(await runGroup(ctx, g, controls, warmed));

  const results = byAttackId([...replayed, ...fresh].map((r) => r.result));
  const run: Omit<AttackRun, "finishedAt" | "ledger" | "vibesafeVersion" | "schemaVersion"> = {
    mode: options.mode,
    startedAt,
    projectPath: s.root,
    targetUrl: target.targetUrl,
    groups: byAttackId(allGroups),
    results,
    requestLog: [...client.log],
  };
  if (baseline !== undefined) {
    run.diff = computeRetestDiff({
      baseline,
      replayed,
      fresh: fresh.map((r) => r.result),
      freshRoutes: pass.routes.map((r) => r.pattern),
    });
  }
  return finishRun(options, s, run, pass.findings);
}

async function dryRun(
  options: RunOptions,
  s: Setup,
  groups: ProbeGroup[],
  findings: readonly Finding[],
  startedAt: string,
): Promise<AttackRun> {
  const explicit = options.target ?? s.configuredTarget;
  const base =
    explicit === undefined ? (DEFAULT_TARGETS[0] as string) : normalizeTarget(explicit, "target");
  const client = newClient(s, options, true);
  const ctx: SendContext = { client, base, sessions: s.sessions };
  const warmed = new Set<string>();
  // Gate and log every planned request (controls first, then probes); nothing is sent.
  await runControls(ctx, groups, warmed);
  for (const g of groups) {
    if (g.skip) continue;
    for (const r of g.requests) await send(ctx, r);
  }
  return finishRun(
    options,
    s,
    {
      mode: "dry-run",
      startedAt,
      projectPath: s.root,
      targetUrl: base,
      groups,
      results: [],
      requestLog: [...client.log],
    },
    findings,
  );
}

/**
 * Re-sends the requests of one saved result (from attack-last.json, else the baseline) and
 * returns its new result. Writes nothing. Throws AttackPersistError (exit 2) for an unknown id.
 */
export async function replayAttack(options: RunOptions, attackId: string): Promise<AttackResult> {
  const s = setup(options);
  const saved = loadSavedRun(s.root, "last") ?? loadSavedRun(s.root, "baseline");
  if (saved === undefined) throw new AttackPersistError(NO_BASELINE_MESSAGE);
  const wanted = attackId.startsWith("ATK-") ? attackId : `ATK-${attackId}`;
  const group = saved.groups.find((g) => g.attackId === wanted);
  if (group === undefined) {
    throw new AttackPersistError(`No attack ${safeId(wanted)} in the last run.`);
  }
  const client = newClient(s, options);
  const target = await detectTarget({
    client,
    explicit: options.target,
    configured: s.configuredTarget,
    remembered: saved.targetUrl,
    ownerControls: ownerControls([group], s.sessions),
    log: options.log,
  });
  const ctx: SendContext = { client, base: target.targetUrl, sessions: s.sessions };
  const warmed = new Set<string>();
  const controls = await runControls(ctx, [group], warmed);
  return (await runGroup(ctx, group, controls, warmed)).result;
}
