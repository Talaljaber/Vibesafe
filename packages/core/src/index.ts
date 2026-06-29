// ─────────────────────────────────────────────────────────────────────────────
// @vibesafe/core — Public API
// ─────────────────────────────────────────────────────────────────────────────

export { DEFAULT_CONFIG, mergeConfig } from "./config/defaults.js";
export { validateConfig } from "./config/schema.js";

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

// Fixers
export * from "./fixers/index.js";
