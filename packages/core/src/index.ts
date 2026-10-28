// ─────────────────────────────────────────────────────────────────────────────
// @vibesafe/core — Public API
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
export { SupabaseRlsDetector } from "./detectors/supabase-rls-detector.js";
export { SecurityHeadersDetector } from "./detectors/security-headers-detector.js";
export { CorsDetector } from "./detectors/cors-detector.js";
export { StripeWebhookDetector } from "./detectors/stripe-webhook-detector.js";
export { RateLimitDetector } from "./detectors/rate-limit-detector.js";

// Fixers
export * from "./fixers/index.js";

export { sanitizeEvidence, MAX_EVIDENCE_LENGTH } from "./detectors/utils/sanitize-evidence.js";
