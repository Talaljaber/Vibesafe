import type { Finding, ScanResult, Severity } from "@vibesafe/shared";

/**
 * Pure SARIF 2.1.0 formatter. No I/O, no console output: it only turns a
 * ScanResult into a plain object that can be JSON.stringify'd.
 *
 * Evidence snippets are intentionally NOT emitted (they can contain secrets).
 */

export const SARIF_VERSION = "2.1.0";
export const SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json";
export const VIBESAFE_INFORMATION_URI = "https://github.com/Talaljaber/Vibesafe";
export const FINGERPRINT_KEY = "vibesafeFindingId/v1";

export type SarifLevel = "error" | "warning" | "note";

export interface SarifRegion {
  startLine: number;
  endLine?: number;
  startColumn?: number;
  endColumn?: number;
}

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help: { text: string; markdown: string };
  helpUri?: string;
  defaultConfiguration: { level: SarifLevel };
  properties: {
    tags: string[];
    category: string;
    "security-severity": string;
  };
}

export interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: SarifLevel;
  message: { text: string };
  locations?: {
    physicalLocation: {
      artifactLocation: { uri: string; uriBaseId: string };
      region?: SarifRegion;
    };
  }[];
  partialFingerprints: Record<string, string>;
  properties: { severity: Severity; confidence: string; deployBlocking: boolean };
}

export interface SarifLog {
  $schema: string;
  version: typeof SARIF_VERSION;
  runs: {
    tool: {
      driver: {
        name: "VibeSafe";
        version: string;
        informationUri: string;
        rules: SarifRule[];
      };
    };
    results: SarifResult[];
  }[];
}

const LEVEL: Record<Severity, SarifLevel> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
};

/** GitHub code scanning "security-severity" (CVSS-like) scores. */
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: "9.0",
  high: "7.5",
  medium: "5.0",
  low: "3.0",
};

const SEVERITY_RANK: Record<Severity, number> = { critical: 3, high: 2, medium: 1, low: 0 };

/** Relative path with forward slashes, no leading "./", percent-encoded as a URI reference. */
export function toSarifUri(file: string): string {
  const normalized = file.replace(/\\/g, "/").replace(/^(\.\/)+/, "");
  return encodeURI(normalized).replace(/#/g, "%23").replace(/\?/g, "%3F");
}

function positiveInt(n: number | undefined): n is number {
  return typeof n === "number" && Number.isInteger(n) && n >= 1;
}

function buildRegion(f: Finding): SarifRegion | undefined {
  if (!positiveInt(f.line)) return undefined;
  const region: SarifRegion = { startLine: f.line };
  if (positiveInt(f.endLine) && f.endLine >= f.line) region.endLine = f.endLine;
  if (positiveInt(f.column)) {
    region.startColumn = f.column;
    const sameLine = region.endLine === undefined || region.endLine === f.line;
    if (positiveInt(f.endColumn) && sameLine && f.endColumn >= f.column) region.endColumn = f.endColumn;
  }
  return region;
}

function buildRule(f: Finding, severity: Severity, tags: string[]): SarifRule {
  const steps = f.fixSteps ?? [];
  const help =
    steps.length > 0 ? steps.map((s, i) => `${i + 1}. ${s}`).join("\n") : f.plainEnglishProblem;
  const rule: SarifRule = {
    id: f.ruleId,
    name: f.ruleId,
    shortDescription: { text: f.title },
    fullDescription: { text: f.whyItMatters || f.plainEnglishProblem },
    help: { text: help, markdown: help },
    defaultConfiguration: { level: LEVEL[severity] },
    properties: {
      tags,
      category: f.category,
      "security-severity": SECURITY_SEVERITY[severity],
    },
  };
  if (f.learnMoreUrl) rule.helpUri = f.learnMoreUrl;
  return rule;
}

export function formatSarif(result: ScanResult, toolVersion: string): SarifLog {
  const rules: SarifRule[] = [];
  const ruleIndex = new Map<string, number>();
  const ruleSeverity = new Map<string, Severity>();
  const ruleTags = new Map<string, Set<string>>();

  // One rule per ruleId, with the max severity and union of tags across that
  // rule's findings so rule metadata is consistent with the results.
  for (const f of result.findings) {
    const prev = ruleSeverity.get(f.ruleId);
    if (prev === undefined || SEVERITY_RANK[f.severity] > SEVERITY_RANK[prev]) {
      ruleSeverity.set(f.ruleId, f.severity);
    }
    const tags = ruleTags.get(f.ruleId) ?? new Set<string>();
    for (const t of f.tags ?? []) tags.add(t);
    ruleTags.set(f.ruleId, tags);
  }

  const results: SarifResult[] = [];
  for (const f of result.findings) {
    let idx = ruleIndex.get(f.ruleId);
    if (idx === undefined) {
      idx = rules.length;
      ruleIndex.set(f.ruleId, idx);
      rules.push(
        buildRule(f, ruleSeverity.get(f.ruleId) ?? f.severity, [...(ruleTags.get(f.ruleId) ?? [])].sort()),
      );
    }

    const sarifResult: SarifResult = {
      ruleId: f.ruleId,
      ruleIndex: idx,
      level: LEVEL[f.severity],
      message: { text: f.plainEnglishProblem || f.title },
      partialFingerprints: { [FINGERPRINT_KEY]: f.id },
      properties: { severity: f.severity, confidence: f.confidence, deployBlocking: f.deployBlocking },
    };
    if (f.file) {
      const region = buildRegion(f);
      sarifResult.locations = [
        {
          physicalLocation: {
            artifactLocation: { uri: toSarifUri(f.file), uriBaseId: "%SRCROOT%" },
            ...(region ? { region } : {}),
          },
        },
      ];
    }
    results.push(sarifResult);
  }

  return {
    $schema: SARIF_SCHEMA_URI,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: "VibeSafe",
            version: toolVersion,
            informationUri: VIBESAFE_INFORMATION_URI,
            rules,
          },
        },
        results,
      },
    ],
  };
}
