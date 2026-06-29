// ─────────────────────────────────────────────────────────────────────────────
// @vibeguard/core — Public API
// ─────────────────────────────────────────────────────────────────────────────

export { DEFAULT_CONFIG, mergeConfig } from "./config/defaults.js";
export { validateConfig } from "./config/schema.js";

export { DetectorRegistry } from "./scanner/detector-registry.js";
export { FileDiscovery } from "./scanner/file-discovery.js";
export { ScannerPipeline } from "./scanner/pipeline.js";
export { ProjectContextBuilder } from "./scanner/project-context.js";
