import path from "path";
import chalk from "chalk";
import { ScannerPipeline, createDefaultRegistry, createDefaultFixRegistry } from "@vibeguard/core";
import { confirm } from "@inquirer/prompts";

export async function runFix(findingId: string, targetDir: string) {
  const rootPath = path.resolve(process.cwd(), targetDir);

  console.log(chalk.gray(`Scanning ${rootPath} to locate finding ${findingId}...`));

  const registry = createDefaultRegistry();
  const pipeline = new ScannerPipeline(registry);
  const result = await pipeline.scan({ rootPath });

  const finding = result.findings.find(f => f.id === findingId || f.ruleId === findingId);

  if (!finding) {
    console.log(chalk.red(`\n❌ Could not find an issue with ID or Rule: ${findingId}`));
    process.exit(1);
  }

  if (!finding.autoFixAvailable) {
    console.log(chalk.yellow(`\n⚠️  The finding '${finding.title}' does not have an auto-fix available.`));
    process.exit(1);
  }

  const fixRegistry = createDefaultFixRegistry();
  const fixer = fixRegistry.getFixer(finding.ruleId);

  if (!fixer) {
    console.log(chalk.red(`\n❌ No AutoFixer is registered for rule '${finding.ruleId}'.`));
    process.exit(1);
  }

  console.log(chalk.cyan(`\n🔧 Fix Preview for: ${finding.title}`));
  
  const preview = await fixer.preview(finding, rootPath);
  
  console.log(chalk.white(`\n${preview.description}`));
  if (preview.filesToCreate.length > 0) {
    console.log(chalk.green(`\nFiles to be created:`));
    preview.filesToCreate.forEach(f => console.log(`  + ${f}`));
  }
  if (preview.filesToModify.length > 0) {
    console.log(chalk.yellow(`\nFiles to be modified:`));
    preview.filesToModify.forEach(f => console.log(`  ~ ${f}`));
  }
  if (preview.diff) {
    console.log(chalk.gray(`\nChanges:`));
    console.log(preview.diff.split('\n').map(line => {
      if (line.startsWith('+')) return chalk.green(line);
      if (line.startsWith('-')) return chalk.red(line);
      return chalk.gray(line);
    }).join('\n'));
  }

  const proceed = await confirm({
    message: chalk.magenta.bold("\nAre you sure you want to apply this fix?"),
    default: true
  });

  if (!proceed) {
    console.log(chalk.gray("Fix cancelled."));
    process.exit(0);
  }

  console.log(chalk.gray("\nApplying fix..."));
  
  const fixResult = await fixer.apply(finding, rootPath);

  if (fixResult.success) {
    console.log(chalk.green(`\n✅ Success: ${fixResult.message}`));
    
    // Fix verification (rescan)
    console.log(chalk.gray("\nVerifying fix..."));
    const verifyResult = await pipeline.scan({ rootPath });
    const stillExists = verifyResult.findings.some(f => 
      f.ruleId === finding.ruleId && f.file === finding.file && f.line === finding.line
    );

    if (stillExists) {
      console.log(chalk.yellow("⚠️  The fix was applied, but the issue still appears in the scan."));
    } else {
      console.log(chalk.green("✅ Fix verified! The issue is resolved."));
    }
  } else {
    console.log(chalk.red(`\n❌ Failed to apply fix: ${fixResult.message}`));
    if (fixResult.error) console.log(chalk.red(fixResult.error));
  }
}
