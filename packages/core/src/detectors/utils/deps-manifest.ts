// ─────────────────────────────────────────────────────────────────────────────
// package.json / lockfile helpers for the dependency detectors (deps stream).
//
// Reads manifests and lockfiles through context.readFile only, never throws, and
// keeps the 1-based line of every dependency so findings can point at it.
// ─────────────────────────────────────────────────────────────────────────────

import type { ScanContext } from "@talaljaber/vibesafe-shared";
import { LOCKFILE_NAMES } from "@talaljaber/vibesafe-shared";
import { resolvedVersions, type ResolvedVersions } from "./semver.js";

export type DependencySection = "dependencies" | "devDependencies" | "optionalDependencies";

const SECTIONS: readonly DependencySection[] = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
];

export interface ManifestDependency {
  name: string;
  spec: string;
  section: DependencySection;
  /** 1-based line of the `"name": "spec"` entry, when it can be located. */
  line?: number | undefined;
  /** The raw source line of the entry (for evidence). */
  text?: string | undefined;
}

export interface Manifest {
  /** Relative path of the package.json. */
  file: string;
  /** Directory of the manifest relative to the root ("" for the root). */
  dir: string;
  json: Record<string, unknown>;
  deps: ManifestDependency[];
  /** Line of each `scripts` entry by script name. */
  scriptLines: Map<string, { line: number; text: string }>;
}

const norm = (p: string): string => p.replace(/\\/g, "/");

/** package.json files the scan sees (never inside node_modules). */
export function manifestFiles(context: ScanContext): string[] {
  return context.files.filter((f) => {
    const p = norm(f);
    return (p === "package.json" || p.endsWith("/package.json")) && !p.includes("node_modules/");
  });
}

/** Directory part of a relative path ("" for a root file). */
export function dirOf(file: string): string {
  const p = norm(file);
  const i = p.lastIndexOf("/");
  return i < 0 ? "" : p.slice(0, i);
}

/** Parses a package.json; null when it is not a JSON object. Never throws. */
export function parseManifest(file: string, text: string): Manifest | null {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof json !== "object" || json === null || Array.isArray(json)) return null;
  const obj = json as Record<string, unknown>;

  // Locate entries line by line: `"section": {` opens a block, a line starting with `}` closes it.
  const located = new Map<string, { line: number; text: string }>();
  const scriptLines = new Map<string, { line: number; text: string }>();
  const lines = text.split(/\r?\n/);
  let block: string | undefined;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const open = /^\s*"([^"]+)"\s*:\s*\{\s*$/.exec(line);
    if (open && block === undefined) {
      block = open[1];
      continue;
    }
    if (block === undefined) continue;
    if (/^\s*\}/.test(line)) {
      block = undefined;
      continue;
    }
    const entry = /^\s*"((?:[^"\\]|\\.)+)"\s*:/.exec(line);
    if (!entry) continue;
    if (block === "scripts") scriptLines.set(entry[1]!, { line: i + 1, text: line.trim() });
    else if ((SECTIONS as readonly string[]).includes(block))
      located.set(`${block}\u0000${entry[1]}`, { line: i + 1, text: line.trim() });
  }

  const deps: ManifestDependency[] = [];
  for (const section of SECTIONS) {
    const value = obj[section];
    if (typeof value !== "object" || value === null || Array.isArray(value)) continue;
    for (const [name, spec] of Object.entries(value as Record<string, unknown>)) {
      if (typeof spec !== "string") continue;
      const at = located.get(`${section}\u0000${name}`);
      deps.push({ name, spec, section, line: at?.line, text: at?.text });
    }
  }
  return { file, dir: dirOf(file), json: obj, deps, scriptLines };
}

export type LockfileState = "none" | "empty" | "ok";

export interface LockfileInfo {
  /** Relative path of the lockfile that applies, when one exists. */
  file?: string | undefined;
  /** none: no lockfile; empty: it exists but could not be read (too large); ok: parsed. */
  state: LockfileState;
  versions: ResolvedVersions;
}

/**
 * Finds the lockfile governing a manifest: the first of package-lock.json,
 * pnpm-lock.yaml or yarn.lock in the manifest's directory or any parent (workspace
 * roots). A lockfile counts as existing when it reads non-empty or is listed in
 * context.files; a listed one that reads empty (over the size limit) is `empty`.
 */
export async function findLockfile(
  context: ScanContext,
  manifestFile: string,
  cache: Map<string, LockfileInfo>,
): Promise<LockfileInfo> {
  const listed = new Set(context.files.map(norm));
  let dir = dirOf(manifestFile);
  for (;;) {
    for (const name of LOCKFILE_NAMES) {
      const rel = dir ? `${dir}/${name}` : name;
      const cached = cache.get(rel);
      if (cached) return cached;
      let content = "";
      try {
        content = await context.readFile(rel);
      } catch {
        content = "";
      }
      if (typeof content === "string" && content.length > 0) {
        const info: LockfileInfo = {
          file: rel,
          state: "ok",
          versions: resolvedVersions(name, content),
        };
        cache.set(rel, info);
        return info;
      }
      if (listed.has(rel)) {
        const info: LockfileInfo = { file: rel, state: "empty", versions: new Map() };
        cache.set(rel, info);
        return info;
      }
    }
    if (dir === "") break;
    dir = dirOf(dir);
  }
  return { state: "none", versions: new Map() };
}

/** Valid npm package name (lowercase, optional scope). */
export function isValidPackageName(name: string): boolean {
  return (
    name.length > 0 &&
    name.length <= 214 &&
    /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/.test(name)
  );
}
