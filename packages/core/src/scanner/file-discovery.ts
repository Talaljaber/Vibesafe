import fs from "node:fs/promises";
import path from "node:path";
import fg from "fast-glob";
import ignore from "ignore";
import {
  SCANNABLE_EXTENSIONS,
  SCANNABLE_FILENAMES,
  TEST_PATH_GLOBS,
  buildExcludedDirGlobs,
} from "@vibesafe/shared";

type Ignore = ReturnType<typeof ignore>;

function createIgnore(): Ignore {
  // The ignore package's default export might need to be called directly
  // @ts-ignore - ignore package typings can be weird with esm
  return typeof ignore === "function" ? ignore() : ignore.default();
}

export class FileDiscovery {
  private rootPath: string;

  constructor(rootPath: string) {
    this.rootPath = rootPath;
  }

  /**
   * Discovers all scannable files in the rootPath, respecting .gitignore files
   * (root and nested, each scoped to its own directory) and additional exclude
   * patterns. Symbolic links are never followed or returned.
   */
  async discoverFiles(
    additionalExcludes: string[] = [],
    options: { includeTests?: boolean | undefined } = {},
  ): Promise<string[]> {
    const defaultExcludes = buildExcludedDirGlobs();
    // Test/fixture paths are excluded unless the caller opts in. Patterns are
    // relative to rootPath, so scanning a fixtures directory directly still works.
    const testExcludes = options.includeTests ? [] : [...TEST_PATH_GLOBS];

    // 1. Load every .gitignore, scoped to the directory that contains it.
    const scopedIgnores = await this.loadGitignores(defaultExcludes);

    // 2. Custom excludes + default directory exclusions (relative to root)
    const rootIg = createIgnore();
    rootIg.add(additionalExcludes);
    rootIg.add(defaultExcludes);
    rootIg.add(testExcludes);

    // 3. Glob all files. Symlinks are not followed; symlink entries themselves
    // are dropped below.
    const entries = await fg(["**/*"], {
      cwd: this.rootPath,
      dot: true,
      onlyFiles: true,
      followSymbolicLinks: false,
      objectMode: true,
      ignore: [...defaultExcludes, ...testExcludes],
    });

    // 4. Filter through `ignore` and extension checks
    const files: string[] = [];
    for (const entry of entries) {
      const file = entry.path;
      if (entry.dirent.isSymbolicLink()) continue;
      if (rootIg.ignores(file)) continue;
      if (this.isIgnoredByGitignore(file, scopedIgnores)) continue;

      const basename = path.basename(file);
      const ext = path.extname(file);

      if (
        (SCANNABLE_FILENAMES as readonly string[]).includes(basename) ||
        (SCANNABLE_EXTENSIONS as readonly string[]).includes(ext)
      ) {
        files.push(file);
      }
    }
    return files;
  }

  /** Finds all .gitignore files (outside excluded dirs) and builds one `ignore` per directory. */
  private async loadGitignores(defaultExcludes: string[]): Promise<Map<string, Ignore>> {
    const result = new Map<string, Ignore>();
    const gitignores = await fg(["**/.gitignore"], {
      cwd: this.rootPath,
      dot: true,
      onlyFiles: true,
      followSymbolicLinks: false,
      ignore: defaultExcludes,
    });

    for (const rel of gitignores) {
      try {
        const content = await fs.readFile(path.join(this.rootPath, rel), "utf-8");
        const dir = path.posix.dirname(rel); // "." for the root
        result.set(dir === "." ? "" : dir, createIgnore().add(content));
      } catch {
        // Unreadable .gitignore: ignore it
      }
    }
    return result;
  }

  /** A file is ignored if any ancestor directory's .gitignore ignores its path relative to that directory. */
  private isIgnoredByGitignore(file: string, scoped: Map<string, Ignore>): boolean {
    const parts = file.split("/");
    for (let i = 0; i < parts.length; i++) {
      const dir = parts.slice(0, i).join("/");
      const ig = scoped.get(dir);
      if (!ig) continue;
      const rel = parts.slice(i).join("/");
      if (ig.ignores(rel)) return true;
    }
    return false;
  }
}
