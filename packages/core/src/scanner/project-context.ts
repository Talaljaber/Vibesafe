import fs from "node:fs/promises";
import path from "node:path";
import type { ProjectContext } from "@vibesafe/shared";

export class ProjectContextBuilder {
  private rootPath: string;

  constructor(rootPath: string) {
    this.rootPath = rootPath;
  }

  async build(): Promise<ProjectContext> {
    const packageJsonPath = path.join(this.rootPath, "package.json");
    const tsconfigPath = path.join(this.rootPath, "tsconfig.json");
    const gitignorePath = path.join(this.rootPath, "gitignore");
    const envPath = path.join(this.rootPath, ".env");
    const envExamplePath = path.join(this.rootPath, ".env.example");
    const readmePath = path.join(this.rootPath, "README.md");

    const packageJson = await this.readJson(packageJsonPath);
    
    const dependencies = packageJson?.dependencies ?? {};
    const devDependencies = packageJson?.devDependencies ?? {};
    const scripts = packageJson?.scripts ?? {};

    const hasTypeScript = await this.fileExists(tsconfigPath);
    const hasGitignore = await this.fileExists(gitignorePath) || await this.fileExists(path.join(this.rootPath, ".gitignore"));
    const hasEnvFile = await this.fileExists(envPath) || await this.fileExists(path.join(this.rootPath, ".env.local"));
    const hasEnvExample = await this.fileExists(envExamplePath);
    const hasReadme = await this.fileExists(readmePath);
    
    const hasTests = Object.keys(devDependencies).some(dep => 
      ['jest', 'vitest', 'mocha', 'cypress', 'playwright'].includes(dep)
    ) || Object.keys(scripts).some(script => script.includes('test'));

    // Framework detection
    let framework: ProjectContext["framework"] = "unknown";
    if (dependencies["next"]) framework = "nextjs";
    else if (devDependencies["vite"] || dependencies["vite"]) framework = "vite";
    else if (dependencies["express"]) framework = "express";

    // Language detection
    let language: ProjectContext["language"] = "mixed";
    if (hasTypeScript) {
      language = "typescript";
    } else {
      language = "javascript"; // Simplified: assume JS if no TS config
    }

    // Package manager detection (simple)
    let packageManager: ProjectContext["packageManager"] = "npm";
    if (await this.fileExists(path.join(this.rootPath, "pnpm-lock.yaml"))) packageManager = "pnpm";
    else if (await this.fileExists(path.join(this.rootPath, "yarn.lock"))) packageManager = "yarn";

    return {
      framework,
      language,
      hasTypeScript,
      packageManager,
      dependencies,
      devDependencies,
      scripts,
      hasGitignore,
      hasEnvFile,
      hasEnvExample,
      hasReadme,
      hasTests,
      nextjsVersion: dependencies["next"]?.replace(/[\^~]/g, ""),
      nodeVersion: packageJson?.engines?.node,
    };
  }

  private async readJson(filePath: string): Promise<any | null> {
    try {
      const content = await fs.readFile(filePath, "utf-8");
      return JSON.parse(content);
    } catch {
      return null;
    }
  }

  private async fileExists(filePath: string): Promise<boolean> {
    try {
      await fs.stat(filePath);
      return true;
    } catch {
      return false;
    }
  }
}
