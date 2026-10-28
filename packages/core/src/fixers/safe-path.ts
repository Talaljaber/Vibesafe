import fs from "node:fs/promises";
import path from "node:path";

/**
 * Resolves `relPath` against `rootPath` and guarantees the result is a path
 * inside the project root that is not (and does not traverse) a symlink.
 *
 * Throws when the path is absolute, escapes the root (lexically or through a
 * symlinked directory), or when the target itself is a symlink. A missing
 * target is allowed (so fixers can create files); its parent must exist and
 * resolve inside the root.
 */
export async function resolveInsideRoot(rootPath: string, relPath: string): Promise<string> {
  if (!relPath || path.isAbsolute(relPath) || path.win32.isAbsolute(relPath)) {
    throw new Error(`Refusing path outside project root: ${relPath}`);
  }

  const root = path.resolve(rootPath);
  const target = path.resolve(root, relPath);
  const realRoot = await fs.realpath(root);

  const lexical = path.relative(root, target);
  if (!lexical || lexical.startsWith("..") || path.isAbsolute(lexical)) {
    throw new Error(`Refusing path outside project root: ${relPath}`);
  }

  let exists = true;
  try {
    const st = await fs.lstat(target);
    if (st.isSymbolicLink()) {
      throw new Error(`Refusing to follow symlink: ${relPath}`);
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code !== "ENOENT") throw error;
    exists = false;
  }

  const realParent = await fs.realpath(exists ? target : path.dirname(target));
  const base = exists ? realParent : path.join(realParent, path.basename(target));
  if (base !== realRoot && !base.startsWith(realRoot + path.sep)) {
    throw new Error(`Refusing path outside project root: ${relPath}`);
  }
  return target;
}
