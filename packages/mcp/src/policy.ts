import fs from "node:fs";
import path from "node:path";

/** Runtime restrictions for the MCP server. */
export interface ServerPolicy {
  /** Absolute directories that scans may target (the directory itself and its subtree). */
  roots: string[];
  /** Whether vibesafe_fix may write files (dryRun: false). */
  allowFix: boolean;
}

function realpathOrResolve(p: string): string {
  const resolved = path.resolve(p);
  try {
    return fs.realpathSync(resolved);
  } catch {
    return resolved;
  }
}

function isInside(root: string, target: string): boolean {
  const rel = path.relative(root, target);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

/** True when `target` (after resolving symlinks) is inside one of the allowed roots. */
export function isPathAllowed(policy: ServerPolicy, target: string): boolean {
  const real = realpathOrResolve(target);
  return policy.roots.some((root) => isInside(realpathOrResolve(root), real));
}

/**
 * Builds the policy from CLI arguments and environment.
 *  - roots: `--root <dir>` (repeatable) and/or VIBESAFE_MCP_ROOTS (path-delimiter separated);
 *    defaults to the server's working directory.
 *  - writes: `--allow-fix` or VIBESAFE_MCP_ALLOW_FIX=1.
 */
export function resolvePolicy(
  argv: string[] = process.argv.slice(2),
  env: NodeJS.ProcessEnv = process.env,
  cwd: string = process.cwd(),
): ServerPolicy {
  const roots: string[] = [];
  let allowFix = env["VIBESAFE_MCP_ALLOW_FIX"] === "1";

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === "--allow-fix") {
      allowFix = true;
    } else if (arg === "--root") {
      const value = argv[++i];
      if (value) roots.push(value);
    } else if (arg.startsWith("--root=")) {
      roots.push(arg.slice("--root=".length));
    }
  }

  const envRoots = env["VIBESAFE_MCP_ROOTS"];
  if (envRoots) {
    roots.push(...envRoots.split(path.delimiter).filter((r) => r.length > 0));
  }

  const resolved = (roots.length > 0 ? roots : [cwd]).map((r) => path.resolve(cwd, r));
  return { roots: resolved, allowFix };
}

export function defaultPolicy(): ServerPolicy {
  return { roots: [path.resolve(process.cwd())], allowFix: false };
}
