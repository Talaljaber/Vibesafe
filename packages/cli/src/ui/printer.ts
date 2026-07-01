import chalk from "chalk";
import type { ScanResult, Finding, DeployStatus, Severity } from "@vibesafe/shared";
import { DEPLOY_STATUS_LABEL, DEPLOY_STATUS_MESSAGE, SEVERITY_LEVELS } from "@vibesafe/shared";
import { setTimeout as sleep } from "timers/promises";

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

export async function printScanResult(result: ScanResult) {
  await sleep(400);
  console.log("\n" + chalk.bold.underline("📊 SCAN RESULTS") + "\n");
  await sleep(300);
  
  // 1. Overview & Score
  const statusColor = getColorForDeployStatus(result.deployStatus);
  console.log(`Score:         ${statusColor(result.score + " / 100")}`);
  await sleep(100);
  console.log(`Deploy Status: ${statusColor(DEPLOY_STATUS_LABEL[result.deployStatus])}`);
  await sleep(100);
  console.log(`Message:       ${statusColor(DEPLOY_STATUS_MESSAGE[result.deployStatus])}`);
  await sleep(100);
  console.log(`Time taken:    ${chalk.gray(result.durationMs + "ms")}`);
  await sleep(100);
  console.log(`Files scanned: ${chalk.gray(result.summary.filesScanned)}`);
  console.log("");
  await sleep(400);

  // 2. Issues & Repair Plan
  console.log(chalk.bold.underline("\n🛠️  ISSUES & REPAIR PLAN") + "\n");
  await sleep(300);
  console.log(chalk.yellow(result.repairPlan.summary));
  console.log("");
  await sleep(200);

  if (result.findings.length === 0) {
    console.log(chalk.green("✨ No issues found! Your code is pristine. ✨\n"));
    return;
  }

  for (const severity of SEVERITY_LEVELS) {
    const steps = result.repairPlan.steps.filter(s => s.severity === severity);
    if (steps.length === 0) continue;

    const sevColor = getColorForSeverity(severity);
    console.log(sevColor(`=== ${severity.toUpperCase()} ISSUES (${steps.length}) ===`));
    await sleep(200);

    for (const step of steps) {
      const finding = result.findings.find(f => f.id === step.findingId)!;

      console.log(`\n  ${sevColor("●")} ${chalk.bold(`Step ${step.order}: ${step.title}`)} [${chalk.gray(finding.ruleId)}]`);
      if (step.file) {
        console.log(`    File: ${chalk.cyan(step.file)}${step.line ? chalk.cyan(":" + step.line) : ""}`);
      }
      if (finding.evidence) {
        console.log(`    Code: ${chalk.dim(finding.evidence.trim().substring(0, 100))}`);
      }
      console.log(`    Problem: ${finding.plainEnglishProblem}`);
      console.log(`    Why it matters: ${chalk.dim(finding.whyItMatters)}`);
      
      console.log(`    ${chalk.bold("Fix")} (~${step.estimatedMinutes} mins):`);
      for (const fix of step.fixSteps) {
        console.log(`      - ${fix}`);
      }
      await sleep(100);
    }
    console.log("");
    await sleep(300);
  }
}
