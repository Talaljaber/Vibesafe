import type { Finding, Severity } from "@talaljaber/vibesafe-shared";

export type AttackCheckId =
  "idor" | "unauth-route" | "exposed-file" | "supabase-anon-read" | "open-redirect";
export type AttackOutcome = "CONFIRMED" | "NOT_REPRODUCED" | "INCONCLUSIVE" | "ERROR";
export type RetestState =
  "BLOCKED" | "STILL_VULNERABLE" | "BROKEN" | "GONE" | "NEW" | "UNCHANGED" | "ERROR";
export type ProbeHost = "target" | "supabase";

export interface StaticRef {
  findingId: string;
  ruleId: string;
  title: string;
  file: string;
  line?: number | undefined;
  severity: Severity;
}
export interface RouteEntry {
  /** "/api/notes/[id]" as nextRoutePath returns it */
  pattern: string;
  sourceFile: string;
  methods: string[];
  dynamicSegments: string[];
  findingRefs: StaticRef[];
}
export interface SessionSpec {
  label: string;
  headers: Record<string, string>;
  /** pattern -> concrete id */
  resources: Record<string, string>;
}
export interface SessionsFile {
  schemaVersion: 1;
  sessions: SessionSpec[];
}
export interface AttackConfigFile {
  schemaVersion: 1;
  target?: string | undefined;
  rate?: number | undefined;
}
export interface ProjectEnv {
  supabaseUrl?: string | undefined;
  supabaseRef?: string | undefined;
  supabaseKey?: { value: string; kind: "anon-jwt" | "publishable" | "refused" } | undefined;
}

export interface ProbeRequest {
  /** "R0".."R3", "U1", "U2", "C1".. */
  label: string;
  method: "GET";
  host: ProbeHost;
  /** concrete path */
  path: string;
  session?: string | undefined;
  headers?: Record<string, string> | undefined;
}
export interface ProbeGroup {
  attackId: string;
  checkId: AttackCheckId;
  title: string;
  route?: string | undefined;
  method?: string | undefined;
  requests: ProbeRequest[];
  staticRef?: StaticRef | undefined;
  ownerLabels?: string[] | undefined;
  skip?: { outcome: "INCONCLUSIVE"; reason: string } | undefined;
}
export interface Fingerprint {
  status: number;
  contentClass: "json" | "html" | "text" | "other";
  keys?: string[] | undefined;
  lengthBucket?: number | undefined;
  hash?: string | undefined;
}
export interface ProbeResponse {
  label: string;
  /** 0 = connection error */
  status: number;
  contentType: string;
  headers: Record<string, string>;
  body: string;
  bodyTruncated: boolean;
  location?: string | undefined;
  redirectBlocked?: boolean | undefined;
  ms: number;
  error?: string | undefined;
  fingerprint: Fingerprint;
}
export interface ControlSet {
  fingerprints: Fingerprint[];
  matches(fp: Fingerprint): boolean;
}
export interface ResponseShape {
  label: string;
  status: number;
  rowCount?: number | undefined;
  /** sanitized [\w.-]{1,64}, else "<key>" */
  keys: string[];
}
export interface AttackResult {
  attackId: string;
  checkId: AttackCheckId;
  title: string;
  outcome: AttackOutcome;
  severity: Severity;
  route?: string | undefined;
  method?: string | undefined;
  sourceFile?: string | undefined;
  line?: number | undefined;
  staticRef?: StaticRef | undefined;
  reasoning: string;
  shapes: ResponseShape[];
  /** HTML only, loopback only, redacted, at most 200 chars */
  excerpts?: Record<string, string> | undefined;
  curl: string[];
  fixGuidance: string;
  ownerOk?: boolean | undefined;
}
export interface RequestLogEntry {
  method: string;
  url: string;
  status: number;
  ms: number;
  session?: string | undefined;
  blocked?: string | undefined;
}
export interface Ledger {
  staticFlagged: number;
  confirmed: number;
  refuted: number;
  untested: number;
  errors: number;
}
export interface RetestDiff {
  attackId: string;
  was?: AttackOutcome | undefined;
  now: AttackOutcome;
  state: RetestState;
  ownerOk?: boolean | undefined;
}
export interface AttackRun {
  schemaVersion: 1;
  vibesafeVersion: string;
  mode: "baseline" | "retest" | "dry-run";
  startedAt: string;
  finishedAt: string;
  projectPath: string;
  targetUrl: string;
  groups: ProbeGroup[];
  results: AttackResult[];
  requestLog: RequestLogEntry[];
  ledger: Ledger;
  diff?: RetestDiff[] | undefined;
}

export interface PlanContext {
  findings: readonly Finding[];
  routes: readonly RouteEntry[];
  sessions: readonly SessionSpec[];
  env: ProjectEnv;
  readSource(relativeFile: string): string | undefined;
}
export interface AttackCheck {
  id: AttackCheckId;
  title: string;
  plan(ctx: PlanContext): ProbeGroup[];
  evaluate(
    group: ProbeGroup,
    responses: readonly ProbeResponse[],
    controls: ControlSet,
  ): AttackResult;
}
export interface RunOptions {
  projectPath: string;
  target?: string | undefined;
  sessionsPath?: string | undefined;
  mode: "baseline" | "retest" | "dry-run";
  newBaseline?: boolean | undefined;
  rate?: number | undefined;
  supabaseProject?: string | undefined;
  log?: ((line: string) => void) | undefined;
}
