// ─────────────────────────────────────────────────────────────────────────────
// VibeGuard — Core Type Definitions
//
// These are the source of truth for all types used across packages.
// Do NOT create parallel type definitions in other packages.
// ─────────────────────────────────────────────────────────────────────────────

// ─── Primitive Types ─────────────────────────────────────────────────────────

/** How severe is this finding? */
export type Severity = "critical" | "high" | "medium" | "low";

/** What category of issue is this? */
export type FindingCategory =
  | "secret"
  | "auth"
  | "authorization"
  | "frontend_exposure"
  | "validation"
  | "dependency"
  | "code_quality"
  | "structure";

/** How confident is the detector in this finding? */
export type Confidence = "high" | "medium" | "low";

/** Overall deploy safety status derived from the score and findings. */
export type DeployStatus = "safe" | "warning" | "danger" | "blocker";

// ─── Finding ─────────────────────────────────────────────────────────────────

/**
 * A single security, quality, or structural issue found in the project.
 *
 * The "translation layer" fields (plainEnglishProblem, whyItMatters, fixSteps,
 * aiFixPrompt) are what make VibeGuard different from a raw scanner.
 */
export interface Finding {
  /** Unique ID for this finding instance (e.g., "SEC-001-a1b2c3"). */
  id: string;

  /** Rule that produced this finding (e.g., "secret/hardcoded-api-key"). */
  ruleId: string;

  /** Short title (e.g., "Hardcoded OpenAI API key found"). */
  title: string;

  severity: Severity;
  category: FindingCategory;

  /** Does this block deployment? Only critical findings should set this to true. */
  deployBlocking: boolean;

  /** How confident is the detector? Affects display but not severity. */
  confidence: Confidence;

  // ─── Location ────────────────────────────────────────────────────────────
  /** Relative file path from project root. */
  file?: string | undefined;
  line?: number | undefined;
  endLine?: number | undefined;
  column?: number | undefined;
  endColumn?: number | undefined;

  /** The code snippet or matched text that triggered this finding. */
  evidence?: string | undefined;

  // ─── Translation Layer (the real product) ────────────────────────────────

  /**
   * Plain English explanation of the problem.
   * Must be understandable by someone who doesn't know security terminology.
   * Example: "Your OpenAI API key is written directly in your code."
   */
  plainEnglishProblem: string;

  /**
   * Why this matters — real-world consequences.
   * Example: "Anyone who sees your code on GitHub can use this key to rack up
   * thousands of dollars in OpenAI charges on your account."
   */
  whyItMatters: string;

  /** Ordered list of fix steps the user should follow. */
  fixSteps: string[];

  /** Can VibeGuard safely auto-fix this mechanically? */
  autoFixAvailable: boolean;

  /**
   * Copy-paste prompt for Cursor / Claude Code / ChatGPT.
   * Only present when a prewritten template exists for this rule.
   */
  aiFixPrompt?: string | undefined;

  // ─── Metadata ────────────────────────────────────────────────────────────
  /** URL to documentation or explanation for this issue. */
  learnMoreUrl?: string | undefined;

  /** IDs of related findings (e.g., a leaked key and its exposure location). */
  relatedFindings?: string[] | undefined;

  /** Tags for filtering and grouping (e.g., ["nextjs", "supabase"]). */
  tags?: string[] | undefined;
}

// ─── Scan Summary ─────────────────────────────────────────────────────────────

export interface ScanSummary {
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  /** Count of findings per category. */
  categoryCounts: Record<FindingCategory, number>;
  filesScanned: number;
  linesScanned: number;
}

// ─── Scan Result ─────────────────────────────────────────────────────────────

/** The complete result of a VibeGuard scan. */
export interface ScanResult {
  /** ISO timestamp when the scan completed. */
  timestamp: string;

  /** Absolute path to the project root that was scanned. */
  projectPath: string;

  /** Detected information about the project (framework, deps, structure). */
  projectContext: ProjectContext;

  /** Every finding from all detectors. */
  findings: Finding[];

  /** Deploy readiness score from 0 (worst) to 100 (best). */
  score: number;

  /** Human-readable deploy status derived from score and critical findings. */
  deployStatus: DeployStatus;

  /** Summary statistics for quick display. */
  summary: ScanSummary;

  /** Ordered repair plan with prioritized fix steps. */
  repairPlan: RepairPlan;

  /** How long the scan took in milliseconds. */
  durationMs: number;
}

// ─── Project Context ──────────────────────────────────────────────────────────

/**
 * Information about the scanned project, detected from package.json,
 * tsconfig.json, and file structure analysis.
 */
export interface ProjectContext {
  framework: "nextjs" | "vite" | "express" | "unknown";
  language: "typescript" | "javascript" | "mixed";
  hasTypeScript: boolean;
  packageManager: "npm" | "pnpm" | "yarn" | "unknown";
  /** Direct dependencies from package.json. */
  dependencies: Record<string, string>;
  /** Dev dependencies from package.json. */
  devDependencies: Record<string, string>;
  /** Scripts from package.json. */
  scripts: Record<string, string>;
  hasGitignore: boolean;
  hasEnvFile: boolean;
  hasEnvExample: boolean;
  hasReadme: boolean;
  hasTests: boolean;
  nextjsVersion?: string | undefined;
  nodeVersion?: string | undefined;
}

// ─── Scan Config ─────────────────────────────────────────────────────────────

/** Configuration passed to the scanner. All fields except rootPath are optional. */
export interface ScanConfig {
  /** Absolute path to the project root to scan. */
  rootPath: string;

  /** Which categories to run. Defaults to all categories if omitted. */
  enabledCategories?: FindingCategory[] | undefined;

  /** Minimum severity level to include in results. Defaults to "low". */
  minSeverity?: Severity | undefined;

  /** Additional glob patterns to exclude beyond the defaults. */
  excludePatterns?: string[] | undefined;

  /** Maximum number of files to scan. Safety limit for huge projects. */
  maxFiles?: number | undefined;

  /** Scan timeout in milliseconds. Defaults to 30000 (30s). */
  timeoutMs?: number | undefined;
}

// ─── Repair Plan ─────────────────────────────────────────────────────────────

/** A prioritized, ordered list of fix steps generated from the findings. */
export interface RepairPlan {
  /** Ordered repair steps — most critical first. */
  steps: RepairStep[];

  /** Total estimated minutes to complete all fixes. */
  estimatedMinutes: number;

  /** Short summary text for display at top of report. */
  summary: string;
}

/** A single step in the repair plan, linked to a specific finding. */
export interface RepairStep {
  /** 1-based order of this step. */
  order: number;

  /** ID of the finding this step addresses. */
  findingId: string;

  /** Short title for the step. */
  title: string;

  severity: Severity;
  category: FindingCategory;

  /** Longer description of what to do. */
  description: string;

  /** Ordered list of specific actions to take. */
  fixSteps: string[];

  /** Copy-paste AI prompt if available. */
  aiFixPrompt?: string | undefined;

  /** Whether VibeGuard can auto-fix this. */
  autoFixAvailable: boolean;

  /** Estimated minutes for this specific step. */
  estimatedMinutes: number;
}

// ─── Detector Interface ───────────────────────────────────────────────────────

/**
 * Contract that every detector must implement.
 *
 * Detectors are independent — they must not depend on each other.
 * Each detector receives the full ScanContext and returns an array of findings.
 */
export interface Detector {
  /** Unique detector ID (e.g., "secret-detector"). */
  id: string;

  /** Human-readable name (e.g., "Secret Detection"). */
  name: string;

  /** Which category of findings this detector produces. */
  category: FindingCategory;

  /** Short description of what this detector checks. */
  description: string;

  /**
   * Run the detector against the scan context.
   * Must return an empty array (never throw) if nothing is found.
   */
  detect(context: ScanContext): Promise<Finding[]>;
}

/**
 * The context passed to every detector.
 *
 * File content is accessed through readFile() which caches reads —
 * detectors must use readFile() instead of fs.readFile() directly.
 */
export interface ScanContext {
  /** Absolute path to the project root. */
  rootPath: string;

  /** Detected project information. */
  projectContext: ProjectContext;

  /**
   * All discovered files as relative paths from rootPath.
   * Already filtered — does not include node_modules, .git, dist, etc.
   */
  files: string[];

  /**
   * Read a file's content by relative path.
   * Results are cached — the file is read from disk only once per scan.
   */
  readFile(relativePath: string): Promise<string>;

  /** The configuration this scan is running with. */
  config: ScanConfig;
}

// ─── Auto-Fixer Interface ────────────────────────────────────────────────────

/**
 * Contract for safe auto-fixers.
 *
 * Auto-fixers must only perform mechanical, safe changes (e.g., appending a
 * line to .gitignore). They must never modify complex business logic.
 * Always show a preview before applying.
 */
export interface AutoFixer {
  /** The rule ID this fixer handles. */
  ruleId: string;

  /** Human-readable description of what this fixer does. */
  description: string;

  /** Return true if this fixer can handle the given finding. */
  canFix(finding: Finding): boolean;

  /**
   * Preview what the fix would do without modifying any files.
   * Must be called before apply() in CLI confirmation flows.
   */
  preview(finding: Finding, rootPath: string): Promise<FixPreview>;

  /**
   * Apply the fix. Should only be called after user confirmation.
   * Respects Workspace Trust in the VS Code extension context.
   */
  apply(finding: Finding, rootPath: string): Promise<FixResult>;
}

/** What the fix will do — shown to user before confirmation. */
export interface FixPreview {
  /** Human-readable description of the change. */
  description: string;
  /** Files that will be modified. */
  filesToModify: string[];
  /** Files that will be created. */
  filesToCreate: string[];
  /** Optional unified diff string for display. */
  diff?: string | undefined;
}

/** Result returned after a fix is applied. */
export interface FixResult {
  success: boolean;
  filesModified: string[];
  filesCreated: string[];
  /** Human-readable outcome message. */
  message: string;
  /** Error message if success is false. */
  error?: string | undefined;
}
