// ─────────────────────────────────────────────────────────────────────────────
// @talaljaber/vibesafe-core — Public API
// ─────────────────────────────────────────────────────────────────────────────

export { DEFAULT_CONFIG, mergeConfig } from "./config/defaults.js";
export { validateConfig, validateUserConfig } from "./config/schema.js";
export { defineConfig } from "./config/user-config.js";
export type { VibeSafeConfig } from "./config/user-config.js";
export { loadUserConfig, CONFIG_FILE_NAMES, ConfigLoadError } from "./config/load-config.js";
export type { LoadedUserConfig, LoadUserConfigOptions } from "./config/load-config.js";
export { applyRuleOverrides } from "./scanner/rule-overrides.js";

export { DetectorRegistry, createDefaultRegistry } from "./scanner/detector-registry.js";
export { FileDiscovery } from "./scanner/file-discovery.js";
export { ScannerPipeline } from "./scanner/pipeline.js";
export { ProjectContextBuilder } from "./scanner/project-context.js";

export { SecretDetector } from "./detectors/secret-detector.js";
export { FrontendExposureDetector } from "./detectors/frontend-exposure-detector.js";
export { MissingAuthDetector } from "./detectors/missing-auth-detector.js";
export { MissingValidationDetector } from "./detectors/missing-validation-detector.js";

export { MissingAuthorizationDetector } from "./detectors/missing-authorization-detector.js";
export { DependencyDetector } from "./detectors/dependency-detector.js";
export { CodebaseMessDetector } from "./detectors/codebase-mess-detector.js";
export { ProjectStructureDetector } from "./detectors/project-structure-detector.js";
export { ErrorBoundaryDetector } from "./detectors/error-boundary-detector.js";
export { GitHistoryDetector } from "./detectors/git-history-detector.js";
export { HardcodedLocalhostDetector } from "./detectors/hardcoded-localhost-detector.js";
export { DangerousHtmlDetector } from "./detectors/dangerous-html-detector.js";
export { DjangoSettingsDetector } from "./detectors/django-settings-detector.js";
export { DjangoViewsDetector } from "./detectors/django-views-detector.js";
export { PythonDependencyDetector } from "./detectors/python-dependency-detector.js";
export { SupabaseRlsDetector } from "./detectors/supabase-rls-detector.js";
export { SecurityHeadersDetector } from "./detectors/security-headers-detector.js";
export { CorsDetector } from "./detectors/cors-detector.js";
export { StripeWebhookDetector } from "./detectors/stripe-webhook-detector.js";
export { RateLimitDetector } from "./detectors/rate-limit-detector.js";

// Detector groups (each exports only its *Detector classes, <group>Detectors,
// <group>Precedence and <group>NonJsExempt).
export * from "./detectors/groups/infra.js";
export * from "./detectors/groups/injection.js";
export * from "./detectors/groups/client.js";
export * from "./detectors/groups/authz.js";
export * from "./detectors/groups/crypto.js";
export * from "./detectors/groups/supabase.js";
export * from "./detectors/groups/deps.js";
export * from "./detectors/groups/tooling.js";

// Shared detector primitives
export {
  applyPrecedence,
  matchesRulePattern,
  patternsOverlap,
  validatePrecedenceRules,
} from "./scanner/precedence.js";
export type { PrecedenceRule } from "./scanner/precedence.js";
export { makeFinding, assertFindingRubric } from "./detectors/utils/finding.js";
export type { FindingInput } from "./detectors/utils/finding.js";
export {
  classifyPath,
  classifyFile,
  runtimeOfKind,
  isJsLike,
  isTestOrFixturePath,
  isGenerated,
  isServerScope,
  isClientScope,
} from "./detectors/utils/file-kind.js";
export type { FileKind, FileRuntime, FileClassification } from "./detectors/utils/file-kind.js";
export {
  createJsSource,
  getJsSource,
  createLineIndex,
  findMatchingBrace,
  isJsxPath,
  lineAt,
  lineText,
  maskCode,
  matchOf,
} from "./detectors/utils/js-source.js";
export type { JsSource, JsSourceOptions, LineIndex } from "./detectors/utils/js-source.js";
export {
  calleeBefore,
  enclosingFunction,
  enclosingOpen,
  expressionEnd,
  extractFunctions,
  handlerSpans,
  moduleSpan,
  patternBindings,
  skipTypeForward,
} from "./detectors/utils/js-functions.js";
export type {
  FunctionKind,
  FunctionParam,
  FunctionRole,
  FunctionSpan,
} from "./detectors/utils/js-functions.js";
export { analyzeTaint, capSeverityForTrust, taintConfidence } from "./detectors/utils/taint.js";
export type {
  TaintBinding,
  TaintGuard,
  TaintHit,
  TaintOptions,
  TaintPath,
  TaintState,
} from "./detectors/utils/taint.js";
export {
  CLIENT_SOURCES,
  PAGE_PROPS_SOURCE,
  PARAMETER_SOURCE,
  PASS_THROUGH_CALLS,
  ROUTE_PARAMS_SOURCE,
  SCRIPT_SOURCES,
  SERVER_ACTION_SOURCE,
  SERVER_SOURCES,
  TAINT_CLEANERS,
  requestMemberSource,
  sourcesForRuntime,
} from "./detectors/patterns/taint-sources.js";
export type {
  CleanerKind,
  TaintCleaner,
  TaintRuntime,
  TaintSource,
  TaintTrust,
} from "./detectors/patterns/taint-sources.js";

// Fixers
export * from "./fixers/index.js";

export { sanitizeEvidence, MAX_EVIDENCE_LENGTH } from "./detectors/utils/sanitize-evidence.js";
