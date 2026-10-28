import fs from "node:fs/promises";
import path from "node:path";
import type { Dirent } from "node:fs";
import { ALWAYS_EXCLUDED_DIRS, type ProjectContext } from "@vibesafe/shared";

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
    
    let hasTests = Object.keys(devDependencies).some(dep => 
      ['jest', 'vitest', 'mocha', 'cypress', 'playwright'].includes(dep)
    ) || Object.keys(scripts).some(script => script.includes('test'));

    const hasViteConfig = await this.hasViteConfig();

    // Framework detection
    let framework: ProjectContext["framework"] = "unknown";
    if (dependencies["next"]) framework = "nextjs";
    else if (devDependencies["vite"] || dependencies["vite"] || hasViteConfig) framework = "vite";
    else if (dependencies["express"]) framework = "express";
    else if (await this.isDjangoProject()) framework = "django";

    if (framework === "django" && !hasTests) hasTests = await this.hasPythonTests();

    // Language detection
    let language: ProjectContext["language"] = "mixed";
    if (hasTypeScript) {
      language = "typescript";
    } else if (framework === "django") {
      language = "python";
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

  /** A Django project has manage.py, or a Python manifest that lists django. */
  private async isDjangoProject(): Promise<boolean> {
    if (await this.fileExists(path.join(this.rootPath, "manage.py"))) return true;

    let entries: string[] = [];
    try {
      entries = await fs.readdir(this.rootPath);
    } catch {
      return false;
    }
    const manifests = entries.filter(
      (name) =>
        /^requirements[\w.-]*\.txt$/i.test(name) || name === "pyproject.toml" || name === "Pipfile",
    );
    for (const name of manifests) {
      try {
        const content = await fs.readFile(path.join(this.rootPath, name), "utf-8");
        const withoutComments = content.replace(/#.*$/gm, "");
        if (/(^|[\s"'[,])django(?![\w-])/im.test(withoutComments)) return true;
      } catch {
        // unreadable manifest: ignore
      }
    }
    return false;
  }

  /**
   * Evidence of Python tests: pytest config, conftest.py, tests.py, test_*.py,
   * *_test.py or a tests/ directory at the root or in a top-level app folder.
   */
  private async hasPythonTests(): Promise<boolean> {
    const isTestEntry = (name: string, isDir: boolean): boolean =>
      isDir
        ? name === "tests"
        : name === "tests.py" ||
          name === "conftest.py" ||
          name === "pytest.ini" ||
          /^test_.*\.py$/.test(name) ||
          /_test\.py$/.test(name);

    let entries: Dirent[];
    try {
      entries = await fs.readdir(this.rootPath, { withFileTypes: true });
    } catch {
      return false;
    }
    if (entries.some((e) => isTestEntry(e.name, e.isDirectory()))) return true;

    const excluded = new Set<string>(ALWAYS_EXCLUDED_DIRS);
    for (const entry of entries) {
      if (!entry.isDirectory() || entry.name.startsWith(".") || excluded.has(entry.name)) continue;
      try {
        const children = await fs.readdir(path.join(this.rootPath, entry.name), { withFileTypes: true });
        if (children.some((e) => isTestEntry(e.name, e.isDirectory()))) return true;
      } catch {
        // unreadable directory: ignore
      }
    }
    return false;
  }

  /** True when a `vite.config.{ts,mts,js,mjs,cjs}` exists at the project root. */
  private async hasViteConfig(): Promise<boolean> {
    for (const ext of ["ts", "mts", "js", "mjs", "cjs"]) {
      if (await this.fileExists(path.join(this.rootPath, `vite.config.${ext}`))) return true;
    }
    return false;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
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
