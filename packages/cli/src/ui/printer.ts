import chalk from "chalk";
import type { ScanResult, Finding, DeployStatus, Severity } from "@vibeguard/shared";
import { DEPLOY_STATUS_LABEL, DEPLOY_STATUS_MESSAGE, SEVERITY_LEVELS } from "@vibeguard/shared";

function getColorForDeployStatus(status: DeployStatus) {
  switch (status) {
    case "blocker": return chalk.red.bold;
    case "danger": return chalk.red;
    case "warning": return chalk.yellow;
    case "safe": return chalk.green;
  }
}

function getColorForSeverity(severity: Severity) {
  switch (severity) {
    case "critical": return chalk.red.bold;
    case "high": return chalk.red;
    case "medium": return chalk.yellow;
    case "low": return chalk.blue;
  }
}

export function printScanResult(result: ScanResult) {
  console.log("\n" + chalk.bold.underline("📊 SCAN RESULTS") + "\n");
  
  // 1. Overview & Score
  const statusColor = getColorForDeployStatus(result.deployStatus);
  console.log(`Score:         ${statusColor(result.score + " / 100")}`);
  console.log(`Deploy Status: ${statusColor(DEPLOY_STATUS_LABEL[result.deployStatus])}`);
  console.log(`Message:       ${statusColor(DEPLOY_STATUS_MESSAGE[result.deployStatus])}`);
  console.log(`Time taken:    ${chalk.gray(result.durationMs + "ms")}`);
  console.log(`Files scanned: ${chalk.gray(result.summary.filesScanned)}`);
  console.log("");

  // 2. Findings List
  if (result.findings.length === 0) {
    console.log(chalk.green("✨ No issues found! Your code is pristine. ✨\n"));
    return;
  }

  // Group findings by severity
  for (const severity of SEVERITY_LEVELS) {
    const severityFindings = result.findings.filter(f => f.severity === severity);
    if (severityFindings.length === 0) continue;

    const sevColor = getColorForSeverity(severity);
    console.log(sevColor(`=== ${severity.toUpperCase()} ISSUES (${severityFindings.length}) ===`));

    for (const finding of severityFindings) {
      console.log(`\n  ${sevColor("●")} ${chalk.bold(finding.title)} [${chalk.gray(finding.ruleId)}]`);
      if (finding.file) {
        console.log(`    File: ${chalk.cyan(finding.file)}${finding.line ? chalk.cyan(":" + finding.line) : ""}`);
      }
      if (finding.evidence) {
        console.log(`    Code: ${chalk.dim(finding.evidence.trim().substring(0, 100))}`);
      }
      console.log(`    Problem: ${finding.plainEnglishProblem}`);
      console.log(`    Why it matters: ${chalk.dim(finding.whyItMatters)}`);
    }
    console.log("");
  }

  // 3. Repair Plan
  console.log(chalk.bold.underline("\n🛠️  REPAIR PLAN") + "\n");
  console.log(chalk.yellow(result.repairPlan.summary));
  console.log("");

  for (const step of result.repairPlan.steps) {
    const sevColor = getColorForSeverity(step.severity);
    const locationStr = (step.file && step.line) ? ` (@ ${step.file}:${step.line})` : (step.file ? ` (@ ${step.file})` : '');
    console.log(`${chalk.bold(`Step ${step.order}`)}: Fix ${sevColor(step.title)}${chalk.dim(locationStr)} (~${step.estimatedMinutes} mins)`);
    for (const fix of step.fixSteps) {
      console.log(`  - ${fix}`);
    }
    console.log("");
  }
}
