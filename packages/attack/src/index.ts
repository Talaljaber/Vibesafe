import { loadSavedRun } from "./persist.js";
import type { AttackRun } from "./types.js";

export type * from "./types.js";
export { ATTACK_CHECKS } from "./checks/index.js";

/** Plans and executes an attack run against a local dev server. */
export { runAttack } from "./runner.js";
/** Re-sends the requests of one saved result (identified by attackId) and returns its new result. */
export { replayAttack } from "./runner.js";

/**
 * Loads a saved run for a project, or undefined when there is none.
 * "baseline" is attack-baseline.json (used by retest), "last" is attack-last.json.
 */
export function loadRun(
  projectPath: string,
  which: "baseline" | "last" = "last",
): AttackRun | undefined {
  return loadSavedRun(projectPath, which);
}

/** Errors the CLI maps to exit code 2 (each carries `exitCode: 2`). */
export { AttackPersistError, REPORT_HTML_FILE, REPORT_MD_FILE, VIBESAFE_DIR } from "./persist.js";
export { AttackConfigError } from "./sessions.js";
export { AttackTargetError } from "./target/detect-target.js";
export { exitCodeForRun } from "./diff.js";

export { renderAgentReport } from "./report/markdown.js";
export { renderHtmlReport } from "./report/html.js";
export { renderTerminalSummary, type TerminalOptions } from "./report/terminal.js";
export { formatCurl, replayLine, placeholderName, type CurlOptions } from "./report/curl.js";
