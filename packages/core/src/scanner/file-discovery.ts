import fs from "node:fs/promises";
import path from "node:path";
import fg from "fast-glob";
import ignore from "ignore";
import { ALWAYS_EXCLUDED_DIRS, SCANNABLE_EXTENSIONS, SCANNABLE_FILENAMES } from "@vibeguard/shared";

export class FileDiscovery {
  private rootPath: string;
  private ig: ReturnType<typeof ignore>;

  constructor(rootPath: string) {
    this.rootPath = rootPath;
    // The ignore package's default export might need to be called directly
    // @ts-ignore - ignore package typings can be weird with esm
    this.ig = typeof ignore === "function" ? ignore() : ignore.default();
  }

  /**
   * Discovers all scannable files in the rootPath, respecting .gitignore and
   * additional exclude patterns.
   */
  async discoverFiles(additionalExcludes: string[] = []): Promise<string[]> {
    // 1. Parse .gitignore if it exists
    await this.loadGitignore();

    // 2. Add custom ignores and always-excluded dirs
    this.ig.add(additionalExcludes);
    
    // Add always excluded dirs to the ignore instance
    this.ig.add(ALWAYS_EXCLUDED_DIRS.map(dir => `${dir}/**`));
    this.ig.add(ALWAYS_EXCLUDED_DIRS.map(dir => `**/${dir}/**`));

    // 3. Glob all files
    // We use a broad glob and let fast-glob do some initial filtering for speed,
    // then apply our stricter `ignore` rules and extension matching.
    const globPattern = "**/*";

    const allFiles = await fg([globPattern], {
      cwd: this.rootPath,
      dot: true,
      onlyFiles: true,
      // Pass the top-level excluded dirs to fast-glob to save traversing them
      ignore: ALWAYS_EXCLUDED_DIRS.map((dir) => `**/${dir}/**`),
    });

    // 4. Filter through `ignore` and extension checks
    const filteredFiles = allFiles.filter((file) => {
      // Check against gitignore rules
      if (this.ig.ignores(file)) {
        return false;
      }

      const basename = path.basename(file);
      const ext = path.extname(file);

      // Check if it's a specific scannable filename (e.g. .env)
      if (SCANNABLE_FILENAMES.includes(basename as any)) {
        return true;
      }

      // Check if it has a scannable extension (e.g. .ts, .tsx)
      if (SCANNABLE_EXTENSIONS.includes(ext as any)) {
        return true;
      }

      return false;
    });

    return filteredFiles;
  }

  private async loadGitignore(): Promise<void> {
    const gitignorePath = path.join(this.rootPath, ".gitignore");
    try {
      const content = await fs.readFile(gitignorePath, "utf-8");
      this.ig.add(content);
    } catch (error) {
      // It's okay if .gitignore doesn't exist
    }
  }
}
