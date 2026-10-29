import type { Detector, Finding, ScanContext } from "@talaljaber/vibesafe-shared";

/** In-memory scan context for the injection detector tests. */
export function createContext(
  files: Record<string, string>,
  options: { includeTests?: boolean; targetFiles?: string[] } = {},
): ScanContext {
  return {
    rootPath: "/fake/path",
    projectContext: { framework: "nextjs" } as ScanContext["projectContext"],
    files: options.targetFiles ?? Object.keys(files),
    config: { includeTests: options.includeTests === true } as ScanContext["config"],
    readFile: async (file) => files[file] ?? "",
  };
}

/** Runs `detector` over `files` and returns its findings. */
export async function run(
  detector: Detector,
  files: Record<string, string>,
  options: { includeTests?: boolean; targetFiles?: string[] } = {},
): Promise<Finding[]> {
  return detector.detect(createContext(files, options));
}
